//! CONNECT-IP の状態機械。RFC 9484 Section 8.1 のリモートアクセス VPN をバイト列で往復する。

use core::net::{Ipv4Addr, Ipv6Addr};

use shiguredo_masque::connect_ip::{ConnectIp, Event, InboundReject, Role, SendError};
use shiguredo_masque::error::Error;
use shiguredo_masque::ip::{self, AssignedAddress, IpPrefix, RequestedAddress, RouteRange};

fn feed(dst: &mut ConnectIp, src: &mut ConnectIp) {
    while let Some(bytes) = src.poll_capsule() {
        dst.recv_stream(&bytes, false)
            .expect("相手のカプセルを受け取れる");
    }
}

fn prefix(octets: [u8; 4], len: u8) -> IpPrefix {
    IpPrefix::new(Ipv4Addr::from(octets).into(), len).expect("プレフィックスは有効")
}

fn vpn_pair() -> (ConnectIp, ConnectIp) {
    let mut client = ConnectIp::new(Role::Client);
    let mut proxy = ConnectIp::new(Role::Proxy);
    client
        .queue_address_request(vec![RequestedAddress {
            request_id: 1,
            prefix: prefix([0, 0, 0, 0], 32),
        }])
        .expect("アドレス要求を積める");
    feed(&mut proxy, &mut client);
    assert!(matches!(proxy.poll_event(), Some(Event::AddressRequest(_))));
    proxy
        .queue_address_assign(vec![AssignedAddress {
            request_id: 1,
            prefix: prefix([192, 0, 2, 11], 32),
        }])
        .expect("アドレス代入を積める");
    proxy
        .queue_route_advertisement(vec![
            RouteRange::new(
                Ipv4Addr::UNSPECIFIED.into(),
                Ipv4Addr::new(255, 255, 255, 255).into(),
                0,
            )
            .expect("デフォルト経路を作れる"),
        ])
        .expect("経路広告を積める");
    feed(&mut client, &mut proxy);
    assert!(matches!(client.poll_event(), Some(Event::AddressAssign(_))));
    assert!(matches!(
        client.poll_event(),
        Some(Event::RouteAdvertisement(_))
    ));
    (client, proxy)
}

#[test]
fn remote_access_vpn_carries_an_ip_packet_both_ways() {
    // RFC 9484 Section 8.1。クライアントは代入アドレスを送信元にし、
    // プロキシは同じアドレス宛の戻りパケットをトンネルへ戻す。
    let (mut client, mut proxy) = vpn_pair();
    let outbound = ip::encode_ipv4(
        Ipv4Addr::new(192, 0, 2, 11),
        Ipv4Addr::new(198, 51, 100, 1),
        17,
        64,
        b"ping",
    )
    .expect("IPv4 パケットを作れる");
    let datagram = client
        .send_ip_packet(&outbound, false)
        .expect("クライアントはパケットをカプセル化できる");
    proxy
        .recv_http_datagram(&datagram)
        .expect("プロキシはデータグラムを受け取れる");
    let Event::IpPacket(got) = proxy.poll_event().expect("IP パケットが届く") else {
        panic!("転送判定を通過した IP パケットが届く");
    };
    let parsed = ip::parse_ip(&got).expect("転送後も IP パケットである");
    // プロキシが転送するので TTL が 1 減る。
    assert_eq!(parsed.hop_limit, 63);

    let reply = ip::encode_ipv4(
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(192, 0, 2, 11),
        17,
        64,
        b"pong",
    )
    .expect("戻りパケットを作れる");
    let back = proxy
        .send_ip_packet(&reply, true)
        .expect("代入アドレス宛なら経路広告が無くても返せる");
    client
        .recv_http_datagram(&back)
        .expect("クライアントは戻りを受け取れる");
    assert!(matches!(client.poll_event(), Some(Event::IpPacket(_))));
}

#[test]
fn source_outside_the_assignment_is_rejected() {
    let (mut client, _) = vpn_pair();
    let packet = ip::encode_ipv4(
        Ipv4Addr::new(203, 0, 113, 1),
        Ipv4Addr::new(198, 51, 100, 1),
        17,
        64,
        b"x",
    )
    .expect("パケットを作れる");
    assert_eq!(
        client.send_ip_packet(&packet, true),
        Err(SendError::BadSource)
    );
}

#[test]
fn hop_limit_one_is_not_forwarded() {
    let (mut client, _) = vpn_pair();
    let packet = ip::encode_ipv4(
        Ipv4Addr::new(192, 0, 2, 11),
        Ipv4Addr::new(198, 51, 100, 1),
        17,
        1,
        b"x",
    )
    .expect("パケットを作れる");
    let Err(SendError::HopLimitExceeded { icmp }) = client.send_ip_packet(&packet, false) else {
        panic!("TTL 1 の転送パケットは Time Exceeded になる");
    };
    let parsed = ip::parse_ip(&icmp).expect("ICMP は IP パケットである");
    assert_eq!(parsed.protocol, ip::IPV4_ICMP);
}

#[test]
fn packet_larger_than_the_tunnel_mtu_returns_packet_too_big() {
    let (mut client, _) = vpn_pair();
    client.set_max_ip_packet_len(20);
    let packet = ip::encode_ipv4(
        Ipv4Addr::new(192, 0, 2, 11),
        Ipv4Addr::new(198, 51, 100, 1),
        17,
        64,
        b"too-big",
    )
    .expect("パケットを作れる");
    let Err(SendError::PacketTooBig { mtu, icmp }) = client.send_ip_packet(&packet, true) else {
        panic!("MTU を超えたパケットは Packet Too Big になる");
    };
    assert_eq!(mtu, 20);
    assert_eq!(
        ip::parse_ip(&icmp).expect("ICMP を読める").protocol,
        ip::IPV4_ICMP
    );
}

#[test]
fn link_local_is_not_encapsulated() {
    let (mut client, _) = vpn_pair();
    let packet = ip::encode_ipv4(
        Ipv4Addr::new(192, 0, 2, 11),
        Ipv4Addr::new(169, 254, 1, 1),
        17,
        64,
        b"x",
    )
    .expect("パケットを作れる");
    assert_eq!(
        client.send_ip_packet(&packet, true),
        Err(SendError::LinkLocal)
    );
}

#[test]
fn unknown_context_is_dropped() {
    let (_, mut proxy) = vpn_pair();
    // Context ID 2 のうしろに空ペイロード。
    proxy
        .recv_http_datagram(&[0x02])
        .expect("未知 Context ID ではストリームを止めない");
    assert!(matches!(
        proxy.poll_event(),
        Some(Event::UnknownContext { context_id: 2 })
    ));
}

#[test]
fn request_id_cannot_be_reused() {
    let mut client = ConnectIp::new(Role::Client);
    let request = RequestedAddress {
        request_id: 7,
        prefix: prefix([0, 0, 0, 0], 32),
    };
    client
        .queue_address_request(vec![request])
        .expect("最初の要求は積める");
    assert_eq!(
        client.queue_address_request(vec![request]),
        Err(Error::RequestIdReuse)
    );
    assert!(!client.is_aborted());
}

#[test]
fn inbound_spoofed_source_is_rejected_after_assignment() {
    // プロキシが代入したあとは、そのプレフィックス以外の送信元を落とす (Section 11)。
    let (_, mut proxy) = vpn_pair();
    let packet = ip::encode_ipv4(
        Ipv4Addr::new(203, 0, 113, 9),
        Ipv4Addr::new(198, 51, 100, 1),
        17,
        64,
        b"spoof",
    )
    .expect("パケットを作れる");
    let mut datagram = Vec::new();
    shiguredo_masque::datagram::HttpDatagram {
        context_id: 0,
        payload: packet,
    }
    .encode(&mut datagram)
    .expect("データグラムを書ける");
    proxy
        .recv_http_datagram(&datagram)
        .expect("受信自体はストリームを止めない");
    assert!(matches!(
        proxy.poll_event(),
        Some(Event::InboundRejected {
            reason: InboundReject::BadSource,
            ..
        })
    ));
}

#[test]
fn ipv6_extension_header_is_walked_for_the_route_protocol() {
    // 経路は UDP (17) だけ。Hop-by-Hop の次が UDP なら一致する (Section 4.8)。
    let mut client = ConnectIp::new(Role::Client);
    let mut proxy = ConnectIp::new(Role::Proxy);
    let assigned = IpPrefix::new(Ipv6Addr::LOCALHOST.into(), 128).expect("プレフィックスは有効");
    proxy
        .queue_address_assign(vec![AssignedAddress {
            request_id: 0,
            prefix: assigned,
        }])
        .expect("代入を積める");
    proxy
        .queue_route_advertisement(vec![
            RouteRange::new(Ipv6Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into(), 17)
                .expect("経路を作れる"),
        ])
        .expect("経路を積める");
    feed(&mut client, &mut proxy);
    let _ = client.poll_event();
    let _ = client.poll_event();

    // Hop-by-Hop の次ヘッダが UDP なら、経路のプロトコル 17 に一致する。
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x60, 0, 0, 0]);
    packet.extend_from_slice(&8u16.to_be_bytes());
    packet.push(0); // Hop-by-Hop
    packet.push(64);
    packet.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
    packet.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
    // next = UDP, hdr ext len = 0 なのでヘッダ長は 8。
    packet.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
    client
        .send_ip_packet(&packet, true)
        .expect("拡張ヘッダの先が UDP なら経路に合う");
}
