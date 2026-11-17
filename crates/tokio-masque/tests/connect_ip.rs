//! tobi-quic と HTTP/3 の上で CONNECT-IP のアドレス代入と IP パケット往復を確認する。
//!
//! モックは使わない。ループバックの UDP ソケットで QUIC を張る。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::PrivatePkcs8KeyDer;
use shiguredo_masque::connect_ip::{ConnectIp, Event, Role};
use shiguredo_masque::ip::{self, AssignedAddress, IpPrefix, RequestedAddress, RouteRange};
use tobi_quic::{
    Client, ClientTlsConfig, Connect, Connection, DatagramConfig, IoConfig, Server, ServerTlsConfig,
};
use tokio_masque::h3::{H3Event, H3Handle};

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_ip_over_http3_carries_an_ip_packet() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (server_conn, client_conn) = connect_pair().await;
    let proxy = tokio::spawn(async move { run_proxy(server_conn).await });
    let payload = run_client(client_conn).await;
    let proxied = proxy.await.expect("プロキシタスクが終われる");
    assert_eq!(proxied, b"ping");
    assert_eq!(payload, b"pong");
}

async fn run_client(connection: Connection) -> Vec<u8> {
    let mut http = H3Handle::spawn_client(connection)
        .await
        .expect("クライアントの HTTP/3 を起動できる");
    wait_for_settings(&mut http).await;
    let stream_id = http
        .request(vec![
            (b":method".to_vec(), b"CONNECT".to_vec()),
            (b":protocol".to_vec(), b"connect-ip".to_vec()),
            (b":scheme".to_vec(), b"https".to_vec()),
            (b":path".to_vec(), b"/.well-known/masque/ip/*/*/".to_vec()),
            (b":authority".to_vec(), b"localhost".to_vec()),
            (b"capsule-protocol".to_vec(), b"?1".to_vec()),
        ])
        .await
        .expect("CONNECT を送れる");

    let mut session = ConnectIp::new(Role::Client);
    session
        .queue_address_request(vec![RequestedAddress {
            request_id: 1,
            prefix: IpPrefix::new(core::net::Ipv4Addr::UNSPECIFIED.into(), 32)
                .expect("0.0.0.0/32 は要求として有効"),
        }])
        .expect("アドレス要求を積める");
    let capsule = session.poll_capsule().expect("要求カプセルがある");
    http.send_body(stream_id, capsule)
        .await
        .expect("カプセルをストリームへ書ける");

    let deadline = tokio::time::Instant::now() + TIMEOUT;
    let mut saw_assign = false;
    let mut saw_route = false;
    let mut reply = None;
    while tokio::time::Instant::now() < deadline && reply.is_none() {
        let event = tokio::time::timeout(TIMEOUT, http.recv())
            .await
            .expect("クライアントのイベントがタイムアウトしない")
            .expect("駆動が先に終わらない");
        match event {
            H3Event::Data { data, .. } => {
                session
                    .recv_stream(&data, false)
                    .expect("プロキシのカプセルを解釈できる");
                while let Some(event) = session.poll_event() {
                    match event {
                        Event::AddressAssign(_) => saw_assign = true,
                        Event::RouteAdvertisement(_) => saw_route = true,
                        _ => {}
                    }
                }
                if saw_assign && saw_route {
                    let packet = ip::encode_ipv4(
                        core::net::Ipv4Addr::new(192, 0, 2, 11),
                        core::net::Ipv4Addr::new(198, 51, 100, 1),
                        17,
                        64,
                        b"ping",
                    )
                    .expect("IPv4 パケットを作れる");
                    let datagram = session
                        .send_ip_packet(&packet, false)
                        .expect("代入と経路のあとパケットを送れる");
                    http.send_datagram(stream_id, datagram)
                        .await
                        .expect("HTTP Datagram を送れる");
                    // 一度だけ送る。
                    saw_assign = false;
                    saw_route = false;
                }
            }
            H3Event::Datagram { payload, .. } => {
                session
                    .recv_http_datagram(&payload)
                    .expect("戻りデータグラムを解釈できる");
                if let Some(Event::IpPacket(packet)) = session.poll_event() {
                    reply = Some(packet);
                }
            }
            H3Event::Failed(message) => panic!("HTTP/3 駆動が失敗した: {message}"),
            _ => {}
        }
    }
    let packet = reply.expect("プロキシからの IP パケットが届く");
    let parsed = ip::parse_ip(&packet).expect("戻りは IP パケット");
    assert_eq!(
        parsed.dst,
        core::net::IpAddr::V4(core::net::Ipv4Addr::new(192, 0, 2, 11))
    );
    packet[packet.len() - 4..].to_vec()
}

async fn run_proxy(connection: Connection) -> Vec<u8> {
    let mut http = H3Handle::spawn_server(connection)
        .await
        .expect("サーバーの HTTP/3 を起動できる");
    let mut session = ConnectIp::new(Role::Proxy);
    let mut stream_id = None;
    let mut payload = None;
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while tokio::time::Instant::now() < deadline && payload.is_none() {
        let event = tokio::time::timeout(TIMEOUT, http.recv())
            .await
            .expect("サーバーのイベントがタイムアウトしない")
            .expect("駆動が先に終わらない");
        match event {
            H3Event::Headers {
                stream_id: id,
                fields,
            } => {
                let connect = fields.iter().any(|(name, value)| {
                    name.as_slice() == b":protocol" && value.as_slice() == b"connect-ip"
                });
                if connect {
                    http.respond(
                        id,
                        vec![
                            (b":status".to_vec(), b"200".to_vec()),
                            (b"capsule-protocol".to_vec(), b"?1".to_vec()),
                        ],
                    )
                    .await
                    .expect("200 を返せる");
                    stream_id = Some(id);
                }
            }
            H3Event::Data {
                stream_id: id,
                data,
            } => {
                session
                    .recv_stream(&data, false)
                    .expect("クライアントのカプセルを解釈できる");
                let mut requested = false;
                while let Some(event) = session.poll_event() {
                    if matches!(event, Event::AddressRequest(_)) {
                        requested = true;
                    }
                }
                if requested {
                    session
                        .queue_address_assign(vec![AssignedAddress {
                            request_id: 1,
                            prefix: IpPrefix::new(
                                core::net::Ipv4Addr::new(192, 0, 2, 11).into(),
                                32,
                            )
                            .expect("代入プレフィックスは有効"),
                        }])
                        .expect("代入を積める");
                    session
                        .queue_route_advertisement(vec![
                            RouteRange::new(
                                core::net::Ipv4Addr::UNSPECIFIED.into(),
                                core::net::Ipv4Addr::BROADCAST.into(),
                                0,
                            )
                            .expect("デフォルト経路を作れる"),
                        ])
                        .expect("経路を積める");
                    while let Some(capsule) = session.poll_capsule() {
                        http.send_body(id, capsule).await.expect("カプセルを返せる");
                    }
                }
            }
            H3Event::Datagram {
                stream_id: id,
                payload: bytes,
            } => {
                session
                    .recv_http_datagram(&bytes)
                    .expect("IP データグラムを解釈できる");
                if let Some(Event::IpPacket(packet)) = session.poll_event() {
                    payload = Some(packet[packet.len() - 4..].to_vec());
                    let reply = ip::encode_ipv4(
                        core::net::Ipv4Addr::new(198, 51, 100, 1),
                        core::net::Ipv4Addr::new(192, 0, 2, 11),
                        17,
                        64,
                        b"pong",
                    )
                    .expect("戻りパケットを作れる");
                    let datagram = session
                        .send_ip_packet(&reply, true)
                        .expect("代入アドレス宛の戻りをカプセル化できる");
                    let id = stream_id.unwrap_or(id);
                    http.send_datagram(id, datagram)
                        .await
                        .expect("戻りデータグラムを送れる");
                }
            }
            H3Event::Failed(message) => panic!("HTTP/3 駆動が失敗した: {message}"),
            _ => {}
        }
    }
    payload.expect("クライアントの IP ペイロードが届く")
}

async fn wait_for_settings(http: &mut H3Handle) {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout(TIMEOUT, http.recv())
            .await
            .expect("SETTINGS の待機がタイムアウトしない")
            .expect("駆動が先に終わらない");
        if let H3Event::PeerSettings {
            enable_connect_protocol: Some(true),
            h3_datagram: Some(true),
        } = event
        {
            return;
        }
    }
    panic!("ピアが CONNECT と HTTP Datagram を有効にしない");
}

async fn connect_pair() -> (Connection, Connection) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("テスト証明書を作れる");
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(cert.cert.der().clone())
        .expect("ルートに証明書を入れられる");
    let mut client_tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .expect("サーバー TLS を作れる");
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let bind: SocketAddr = "127.0.0.1:0"
        .parse()
        .expect("ループバックアドレスを解釈できる");
    let mut server = Server::builder()
        .with_tls(ServerTlsConfig::new(Arc::new(server_tls)))
        .with_io(IoConfig::new(bind))
        .with_datagram(DatagramConfig::default())
        .start()
        .expect("QUIC サーバーを起動できる");
    let client = Client::builder()
        .with_tls(ClientTlsConfig::new(Arc::new(client_tls)))
        .with_io(IoConfig::new(bind))
        .with_datagram(DatagramConfig::default())
        .start()
        .expect("QUIC クライアントを起動できる");
    let addr = server.local_addr();
    let (client_conn, server_conn) = tokio::join!(
        client.connect(Connect::new(addr, "localhost")),
        server.accept(),
    );
    (
        server_conn.expect("サーバーが QUIC 接続を受け取れる"),
        client_conn.expect("QUIC 接続を張れる"),
    )
}
