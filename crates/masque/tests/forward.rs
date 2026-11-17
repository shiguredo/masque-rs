//! ループバックでプロキシと 2 台のクライアントを動かし、IP パケットが往復することを確認する。
//!
//! モックは使わない。`masque proxy` と同じ待受と、`masque client` と同じ CONNECT-IP を使う。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use masque::client::Tunnel;
use masque::proxy::{Proxy, serve};
use shiguredo_masque::ip;

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_clients_exchange_an_ip_packet() {
    let bind: SocketAddr = "127.0.0.1:0"
        .parse()
        .expect("ループバックアドレスを解釈できる");
    let proxy = Proxy::bind(bind).expect("プロキシを bind できる");
    let addr = proxy.local_addr();
    tokio::spawn(async move {
        match serve(proxy).await {
            Ok(()) => panic!("プロキシの待受が終わった"),
            Err(err) => panic!("プロキシが止まった: {err}"),
        }
    });

    let exchanged = tokio::time::timeout(TIMEOUT, exchange(addr))
        .await
        .expect("10 秒以内に 2 台のクライアントが IP パケットを往復できる");
    exchanged.expect("IP パケットの往復が成功する");
}

async fn exchange(addr: SocketAddr) -> Result<(), String> {
    let mut first = Tunnel::connect(addr, true).await?;
    let mut second = Tunnel::connect(addr, true).await?;
    if first.address() != Ipv4Addr::new(192, 0, 2, 1)
        || second.address() != Ipv4Addr::new(192, 0, 2, 2)
    {
        return Err(format!(
            "代入アドレスが 192.0.2.1 と 192.0.2.2 ではない: {} {}",
            first.address(),
            second.address()
        ));
    }

    first.send_to(second.address(), b"ping").await?;
    let forward = second.recv_packet().await?;
    expect_payload(&forward, first.address(), second.address(), b"ping")?;

    second.send_to(first.address(), b"pong").await?;
    let back = first.recv_packet().await?;
    expect_payload(&back, second.address(), first.address(), b"pong")
}

fn expect_payload(
    packet: &[u8],
    source: Ipv4Addr,
    destination: Ipv4Addr,
    payload: &[u8],
) -> Result<(), String> {
    let parsed = ip::parse_ip(packet).map_err(|err| err.to_string())?;
    if parsed.src != IpAddr::V4(source) || parsed.dst != IpAddr::V4(destination) {
        return Err(format!("IP の宛先が違う: {} -> {}", parsed.src, parsed.dst));
    }
    if !packet.ends_with(payload) {
        return Err("ペイロードが届いていない".to_string());
    }
    Ok(())
}
