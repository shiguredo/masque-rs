//! プロキシへ CONNECT-IP し、代入アドレスと試験パケットを扱う。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use shiguredo_masque::connect_ip::{ConnectIp, Event, Role};
use shiguredo_masque::ip::{self, IpPrefix, RequestedAddress};
use tokio_masque::endpoint;
use tokio_masque::h3::{H3Event, H3Handle};

use crate::tun::Tun;

/// 代入と経路を待つ上限
const TIMEOUT: Duration = Duration::from_secs(10);

/// RFC 3692 の実験用プロトコル番号。UDP ヘッダは付けない。
const TEST_PROTOCOL: u8 = 253;

/// 1 本の CONNECT-IP
pub struct Tunnel {
    http: H3Handle,
    session: ConnectIp,
    stream_id: u64,
    address: Ipv4Addr,
}

impl Tunnel {
    /// プロキシへ接続し、IPv4 アドレスが代入されるまで待つ
    ///
    /// 証明書は localhost 向けに作ってある。`insecure` が真のときだけ検証を省略する。
    /// 10 秒以内に SETTINGS、200、ADDRESS_ASSIGN、ROUTE_ADVERTISEMENT が揃わなければエラー。
    pub async fn connect(proxy: SocketAddr, insecure: bool) -> Result<Self, String> {
        // 証明書の名前は localhost 固定。接続先の IP とは別に渡す。
        let mut http = endpoint::connect(proxy, "localhost", insecure).await?;
        let deadline = Instant::now() + TIMEOUT;
        wait_for_settings(&mut http, deadline).await?;
        let stream_id = http.request(connect_headers()).await?;
        let mut session = ConnectIp::new(Role::Client);
        session
            .queue_address_request(vec![RequestedAddress {
                request_id: 1,
                prefix: IpPrefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 32)
                    .map_err(|err| err.to_string())?,
            }])
            .map_err(|err| err.to_string())?;
        let capsule = session
            .poll_capsule()
            .ok_or_else(|| "address request was not queued".to_string())?;
        http.send_body(stream_id, capsule).await?;
        let address = wait_assignment(&mut http, &mut session, deadline).await?;
        tracing::info!(%address, "assigned address");
        Ok(Self {
            http,
            session,
            stream_id,
            address,
        })
    }

    /// プロキシが代入した IPv4 アドレス
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// `destination` 宛の試験 IP パケットを 1 つ送る
    ///
    /// この端点が作ったパケットなので、Hop Limit は減らさない。
    pub async fn send_to(&mut self, destination: Ipv4Addr, payload: &[u8]) -> Result<(), String> {
        let packet = ip::encode_ipv4(self.address, destination, TEST_PROTOCOL, 64, payload)
            .map_err(|err| err.to_string())?;
        let datagram = self
            .session
            .send_ip_packet(&packet, true)
            .map_err(|err| format!("send ip packet: {err:?}"))?;
        self.http.send_datagram(self.stream_id, datagram).await
    }

    /// 次の IP パケットを 1 つ受け取る
    pub async fn recv_packet(&mut self) -> Result<Vec<u8>, String> {
        loop {
            let event = self
                .http
                .recv()
                .await
                .ok_or_else(|| "h3 driver stopped".to_string())?;
            match event {
                H3Event::Data { data, .. } => {
                    self.session
                        .recv_stream(&data, false)
                        .map_err(|err| err.to_string())?;
                    while self.session.poll_event().is_some() {}
                }
                H3Event::Datagram { payload, .. } => {
                    self.session
                        .recv_http_datagram(&payload)
                        .map_err(|err| err.to_string())?;
                    while let Some(event) = self.session.poll_event() {
                        if let Event::IpPacket(packet) = event {
                            return Ok(packet);
                        }
                    }
                }
                H3Event::Failed(message) => return Err(message),
                _ => {}
            }
        }
    }
}

/// 代入アドレスを表示し、パケットを受け取る
///
/// `tun` が真のときは TUN を開いて OS とトンネルの間で IP パケットを渡す。
/// `to` があるときは 1 つ送って返事を表示して戻る。どちらも無いときは受け取ったパケットを送り主へ返し続ける。
pub async fn run(
    proxy: SocketAddr,
    insecure: bool,
    to: Option<Ipv4Addr>,
    payload: &[u8],
    tun: bool,
) -> Result<(), String> {
    let mut tunnel = Tunnel::connect(proxy, insecure).await?;
    println!("assigned {}", tunnel.address());
    if tun {
        let mut device = Tun::open()?;
        device.assign_ipv4(tunnel.address(), crate::POOL_PREFIX, crate::POOL_PREFIX_LEN)?;
        println!("tun {} address {}", device.name(), tunnel.address());
        return bridge(&mut tunnel, &mut device).await;
    }
    if let Some(destination) = to {
        tunnel.send_to(destination, payload).await?;
        println!("sent {} bytes to {destination}", payload.len());
        let packet = tunnel.recv_packet().await?;
        let (_, _, line) = describe(&packet)?;
        println!("{line}");
        return Ok(());
    }
    loop {
        let packet = tunnel.recv_packet().await?;
        let (source, payload, line) = describe(&packet)?;
        println!("{line}");
        if let Err(err) = tunnel.send_to(source, &payload).await {
            tracing::info!(%err, "did not echo packet");
        }
    }
}

async fn bridge(tunnel: &mut Tunnel, device: &mut Tun) -> Result<(), String> {
    loop {
        let incoming = {
            tokio::select! {
                result = device.read_packet() => Incoming::Device(result),
                result = tunnel.recv_packet() => Incoming::Tunnel(result),
            }
        };
        match incoming {
            Incoming::Device(Ok(packet)) => forward_from_tun(tunnel, &packet).await?,
            Incoming::Device(Err(err)) => return Err(err),
            Incoming::Tunnel(Ok(packet)) => device.write_packet(&packet).await?,
            Incoming::Tunnel(Err(err)) => return Err(err),
        }
    }
}

async fn forward_from_tun(tunnel: &mut Tunnel, packet: &[u8]) -> Result<(), String> {
    // カーネルが TUN に書いた時点で Hop Limit は確定している。
    // カプセル化でさらに減らさない (RFC 9484 Section 7.2)。
    let datagram = match tunnel.session.send_ip_packet(packet, true) {
        Ok(datagram) => datagram,
        Err(err) => {
            tracing::info!(error = ?err, "dropped tun packet");
            return Ok(());
        }
    };
    tunnel.http.send_datagram(tunnel.stream_id, datagram).await
}

enum Incoming {
    Device(Result<Vec<u8>, String>),
    Tunnel(Result<Vec<u8>, String>),
}

fn describe(packet: &[u8]) -> Result<(Ipv4Addr, Vec<u8>, String), String> {
    let parsed = ip::parse_ip(packet).map_err(|err| err.to_string())?;
    let IpAddr::V4(source) = parsed.src else {
        return Err("received packet is not IPv4".to_string());
    };
    let payload = ipv4_payload(packet)?.to_vec();
    let text = String::from_utf8_lossy(&payload);
    let line = format!("received {} bytes from {source}: {text}", payload.len());
    Ok((source, payload, line))
}

fn ipv4_payload(packet: &[u8]) -> Result<&[u8], String> {
    let first = packet.first().copied().ok_or("empty packet")?;
    if first >> 4 != 4 {
        return Err("received packet is not IPv4".to_string());
    }
    let header_len = usize::from(first & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len {
        return Err("short IPv4 packet".to_string());
    }
    Ok(&packet[header_len..])
}

fn connect_headers() -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (b":method".to_vec(), b"CONNECT".to_vec()),
        (b":protocol".to_vec(), b"connect-ip".to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":path".to_vec(), crate::CONNECT_PATH.to_vec()),
        (b":authority".to_vec(), b"localhost".to_vec()),
        (b"capsule-protocol".to_vec(), b"?1".to_vec()),
    ]
}

async fn wait_for_settings(http: &mut H3Handle, deadline: Instant) -> Result<(), String> {
    while Instant::now() < deadline {
        match next_event(http, deadline, "timed out waiting for settings").await? {
            H3Event::PeerSettings {
                enable_connect_protocol: Some(true),
                h3_datagram: Some(true),
            } => return Ok(()),
            H3Event::Failed(message) => return Err(message),
            _ => {}
        }
    }
    Err("timed out waiting for settings".to_string())
}

async fn wait_assignment(
    http: &mut H3Handle,
    session: &mut ConnectIp,
    deadline: Instant,
) -> Result<Ipv4Addr, String> {
    while Instant::now() < deadline {
        match next_event(http, deadline, "timed out waiting for address assignment").await? {
            H3Event::Headers { fields, .. } => {
                if let Some(status) = field(&fields, b":status")
                    && status != b"200"
                {
                    return Err(format!(
                        "connect-ip response status {}",
                        String::from_utf8_lossy(status)
                    ));
                }
            }
            H3Event::Data { data, .. } => {
                session
                    .recv_stream(&data, false)
                    .map_err(|err| err.to_string())?;
                while session.poll_event().is_some() {}
                if session.assigned_to_us().is_some() && !session.routes_from_peer().is_empty() {
                    return assigned_ipv4(session);
                }
            }
            H3Event::Failed(message) => return Err(message),
            _ => {}
        }
    }
    Err("timed out waiting for address assignment".to_string())
}

async fn next_event(
    http: &mut H3Handle,
    deadline: Instant,
    timed_out: &str,
) -> Result<H3Event, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    match tokio::time::timeout(remaining, http.recv()).await {
        Ok(Some(event)) => Ok(event),
        Ok(None) => Err("h3 driver stopped".to_string()),
        Err(_) => Err(timed_out.to_string()),
    }
}

fn assigned_ipv4(session: &ConnectIp) -> Result<Ipv4Addr, String> {
    let prefixes = session
        .assigned_to_us()
        .ok_or_else(|| "no address assignment".to_string())?;
    for prefix in prefixes {
        if let IpAddr::V4(address) = prefix.address {
            return Ok(address);
        }
    }
    Err("assignment is not IPv4".to_string())
}

fn field<'a>(fields: &'a [(Vec<u8>, Vec<u8>)], name: &[u8]) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|(field_name, _)| field_name.as_slice() == name)
        .map(|(_, value)| value.as_slice())
}
