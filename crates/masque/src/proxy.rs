//! CONNECT-IP を受け、代入アドレス宛の IP パケットを相手のクライアントへ渡す。
//!
//! アドレス表はルータタスクが 1 つだけ持つ。接続タスクはチャネルで依頼する。

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use shiguredo_masque::connect_ip::{ConnectIp, Event, Role};
use shiguredo_masque::ip::{self, AssignedAddress, IpPrefix, RouteRange};
use tokio::sync::{mpsc, oneshot};
use tokio_masque::endpoint::Listener;
use tokio_masque::h3::{H3Event, H3Handle};

/// ルータが溜められる依頼の数
const ROUTER_COMMANDS: usize = 64;

/// 1 接続が溜められる転送待ちパケットの数
const INBOUND_PACKETS: usize = 16;

/// 待受中のプロキシ
pub struct Proxy {
    listener: Listener,
}

impl Proxy {
    /// `addr` で UDP を待ち受ける
    ///
    /// 証明書は localhost 向けの自己署名で、プロセスの中だけに置く。
    pub fn bind(addr: SocketAddr) -> Result<Self, String> {
        Ok(Self {
            listener: Listener::bind(addr)?,
        })
    }

    /// 実際に bind したアドレス
    pub fn local_addr(&self) -> SocketAddr {
        self.listener.local_addr()
    }
}

/// 接続を受け続け、クライアント同士の IP パケットを中継する
///
/// accept に失敗したときだけ戻る。つながっていない宛先のパケットは捨てる。NAT も TUN も使わない。
pub async fn serve(mut proxy: Proxy) -> Result<(), String> {
    tracing::info!(addr = %proxy.local_addr(), "listening");
    let (router_tx, router_rx) = mpsc::channel(ROUTER_COMMANDS);
    tokio::spawn(route_packets(router_rx));
    loop {
        let http = proxy.listener.accept().await?;
        let router_tx = router_tx.clone();
        tokio::spawn(async move {
            match handle_connection(http, router_tx).await {
                Ok(()) => tracing::info!("connection closed"),
                Err(err) => tracing::info!(%err, "connection closed"),
            }
        });
    }
}

enum RouterMsg {
    Allocate {
        inbound: mpsc::Sender<Vec<u8>>,
        reply: oneshot::Sender<Result<Ipv4Addr, String>>,
    },
    Release {
        address: Ipv4Addr,
    },
    Forward {
        destination: Ipv4Addr,
        packet: Vec<u8>,
    },
}

/// 接続が終わるとき、代入アドレスをプールへ戻す
struct Lease {
    address: Option<Ipv4Addr>,
    router: mpsc::Sender<RouterMsg>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(address) = self.address.take() {
            // Drop では待てない。チャネルが満杯なら、そのアドレスはプールに戻らない。
            let _ = self.router.try_send(RouterMsg::Release { address });
        }
    }
}

async fn route_packets(mut commands: mpsc::Receiver<RouterMsg>) {
    // RFC 5737 の TEST-NET-1。ネットワークアドレスとブロードキャストは配らない。
    let mut free: VecDeque<u8> = (1..=254).collect();
    let mut routes: HashMap<Ipv4Addr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    while let Some(command) = commands.recv().await {
        match command {
            RouterMsg::Allocate { inbound, reply } => {
                let result = match free.pop_front() {
                    Some(host) => {
                        let mut octets = crate::POOL_PREFIX.octets();
                        octets[3] = host;
                        let address = Ipv4Addr::from(octets);
                        routes.insert(address, inbound);
                        Ok(address)
                    }
                    None => Err("TEST-NET-1 address pool is exhausted".to_string()),
                };
                let _ = reply.send(result);
            }
            RouterMsg::Release { address } => {
                routes.remove(&address);
                let host = address.octets()[3];
                if !free.contains(&host) {
                    free.push_back(host);
                }
            }
            RouterMsg::Forward {
                destination,
                packet,
            } => {
                let sent = routes
                    .get(&destination)
                    .map(|inbound| inbound.try_send(packet));
                match sent {
                    Some(Ok(())) => tracing::info!(%destination, "forwarded packet"),
                    Some(Err(mpsc::error::TrySendError::Full(_))) => {
                        tracing::info!(%destination, "dropped packet");
                    }
                    Some(Err(mpsc::error::TrySendError::Closed(_))) => {
                        tracing::info!(%destination, "dropped packet");
                        routes.remove(&destination);
                    }
                    None => tracing::info!(%destination, "no client for destination"),
                }
            }
        }
    }
}

async fn allocate(
    router: &mpsc::Sender<RouterMsg>,
    inbound: mpsc::Sender<Vec<u8>>,
) -> Result<Ipv4Addr, String> {
    let (reply_tx, reply_rx) = oneshot::channel();
    router
        .send(RouterMsg::Allocate {
            inbound,
            reply: reply_tx,
        })
        .await
        .map_err(|_| "router stopped".to_string())?;
    reply_rx.await.map_err(|_| "router stopped".to_string())?
}

struct Conn {
    http: H3Handle,
    session: ConnectIp,
    lease: Lease,
    router: mpsc::Sender<RouterMsg>,
    inbound_tx: Option<mpsc::Sender<Vec<u8>>>,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    stream_id: Option<u64>,
    request_id: Option<u64>,
}

enum Incoming {
    Event(Option<H3Event>),
    Packet(Option<Vec<u8>>),
}

async fn handle_connection(http: H3Handle, router: mpsc::Sender<RouterMsg>) -> Result<(), String> {
    let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_PACKETS);
    let mut conn = Conn {
        http,
        session: ConnectIp::new(Role::Proxy),
        lease: Lease {
            address: None,
            router: router.clone(),
        },
        router,
        inbound_tx: Some(inbound_tx),
        inbound_rx,
        stream_id: None,
        request_id: None,
    };
    loop {
        // select の間だけフィールドを借り、処理に入る前に借りを終わらせる。
        let incoming = {
            let http = &mut conn.http;
            let inbound_rx = &mut conn.inbound_rx;
            tokio::select! {
                event = http.recv() => Incoming::Event(event),
                packet = inbound_rx.recv() => Incoming::Packet(packet),
            }
        };
        match incoming {
            Incoming::Event(Some(event)) => conn.on_event(event).await?,
            Incoming::Event(None) | Incoming::Packet(None) => break,
            Incoming::Packet(Some(packet)) => conn.deliver(packet).await?,
        }
    }
    Ok(())
}

impl Conn {
    async fn on_event(&mut self, event: H3Event) -> Result<(), String> {
        match event {
            H3Event::Headers { stream_id, fields } => self.on_headers(stream_id, &fields).await,
            H3Event::Data { data, .. } => self.on_data(&data).await,
            H3Event::Datagram { payload, .. } => self.on_datagram(&payload).await,
            H3Event::Failed(message) => Err(message),
            H3Event::PeerSettings { .. } => Ok(()),
        }
    }

    async fn on_headers(
        &mut self,
        stream_id: u64,
        fields: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), String> {
        if self.stream_id.is_some() {
            return Ok(());
        }
        if !is_connect_ip(fields) {
            tracing::info!(stream_id, "ignored non-connect-ip request");
            return Ok(());
        }
        self.http
            .respond(
                stream_id,
                vec![
                    (b":status".to_vec(), b"200".to_vec()),
                    (b"capsule-protocol".to_vec(), b"?1".to_vec()),
                ],
            )
            .await?;
        self.stream_id = Some(stream_id);
        tracing::info!(stream_id, "accepted connect-ip");
        self.assign_if_ready().await
    }

    async fn on_data(&mut self, data: &[u8]) -> Result<(), String> {
        self.session
            .recv_stream(data, false)
            .map_err(|err| err.to_string())?;
        while let Some(event) = self.session.poll_event() {
            if self.request_id.is_none()
                && let Event::AddressRequest(list) = event
            {
                self.request_id = list.first().map(|item| item.request_id);
            }
        }
        self.assign_if_ready().await
    }

    async fn on_datagram(&mut self, payload: &[u8]) -> Result<(), String> {
        self.session
            .recv_http_datagram(payload)
            .map_err(|err| err.to_string())?;
        while let Some(event) = self.session.poll_event() {
            if let Event::IpPacket(packet) = event {
                self.forward(packet).await?;
            }
        }
        Ok(())
    }

    async fn assign_if_ready(&mut self) -> Result<(), String> {
        if self.lease.address.is_some() {
            return Ok(());
        }
        let Some(request_id) = self.request_id else {
            return Ok(());
        };
        let Some(stream_id) = self.stream_id else {
            return Ok(());
        };
        let Some(inbound) = self.inbound_tx.take() else {
            return Ok(());
        };
        let address = allocate(&self.router, inbound).await?;
        self.lease.address = Some(address);
        queue_assignment(&mut self.session, request_id, address)?;
        send_capsules(&self.http, stream_id, &mut self.session).await?;
        tracing::info!(%address, "assigned address");
        Ok(())
    }

    async fn forward(&self, packet: Vec<u8>) -> Result<(), String> {
        let Some((source, destination)) = packet_endpoints(&packet) else {
            tracing::info!("dropped non-ipv4 packet");
            return Ok(());
        };
        tracing::info!(%source, %destination, "forwarding packet");
        self.router
            .send(RouterMsg::Forward {
                destination,
                packet,
            })
            .await
            .map_err(|_| "router stopped".to_string())
    }

    async fn deliver(&mut self, packet: Vec<u8>) -> Result<(), String> {
        let Some(stream_id) = self.stream_id else {
            tracing::info!("dropped packet before connect-ip was established");
            return Ok(());
        };
        // トンネルから出して別のトンネルへ入れる転送なので、Hop Limit を 1 減らす
        // (RFC 9484 Section 7.2)。
        let datagram = match self.session.send_ip_packet(&packet, false) {
            Ok(datagram) => datagram,
            Err(err) => {
                tracing::info!(error = ?err, "did not forward packet");
                return Ok(());
            }
        };
        self.http.send_datagram(stream_id, datagram).await
    }
}

fn queue_assignment(
    session: &mut ConnectIp,
    request_id: u64,
    address: Ipv4Addr,
) -> Result<(), String> {
    session
        .queue_address_assign(vec![AssignedAddress {
            request_id,
            prefix: IpPrefix::new(IpAddr::V4(address), 32).map_err(|err| err.to_string())?,
        }])
        .map_err(|err| err.to_string())?;
    session
        .queue_route_advertisement(vec![
            RouteRange::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(Ipv4Addr::BROADCAST),
                0,
            )
            .map_err(|err| err.to_string())?,
        ])
        .map_err(|err| err.to_string())
}

async fn send_capsules(
    http: &H3Handle,
    stream_id: u64,
    session: &mut ConnectIp,
) -> Result<(), String> {
    let mut capsules = Vec::new();
    while let Some(capsule) = session.poll_capsule() {
        capsules.push(capsule);
    }
    for capsule in capsules {
        http.send_body(stream_id, capsule).await?;
    }
    Ok(())
}

fn is_connect_ip(fields: &[(Vec<u8>, Vec<u8>)]) -> bool {
    let mut protocol = false;
    let mut path = false;
    for (name, value) in fields {
        if name.as_slice() == b":protocol" && value.as_slice() == b"connect-ip" {
            protocol = true;
        }
        if name.as_slice() == b":path" && value.as_slice() == crate::CONNECT_PATH {
            path = true;
        }
    }
    protocol && path
}

fn packet_endpoints(packet: &[u8]) -> Option<(IpAddr, Ipv4Addr)> {
    let parsed = ip::parse_ip(packet).ok()?;
    let IpAddr::V4(destination) = parsed.dst else {
        return None;
    };
    Some((parsed.src, destination))
}
