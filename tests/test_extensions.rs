//! 後から足した仕様の正常系と、ストリームを止める誤り。

use core::net::{Ipv4Addr, Ipv6Addr};

use shiguredo_masque::capsule::{Capsule, CapsuleDecoder};
use shiguredo_masque::compress::{self, StaticSegment, TemplateAssign};
use shiguredo_masque::connect_ethernet::{ConnectEthernet, RecvFrame};
use shiguredo_masque::connect_ip::{ConnectIp, RequestScope, Role, SendError, TargetScope};
use shiguredo_masque::connect_udp::{ConnectUdp, Event, UdpSendError};
use shiguredo_masque::ecn::{self, EcnDscpAssignment};
use shiguredo_masque::error::Error;
use shiguredo_masque::ip::{self, IpPrefix};
use shiguredo_masque::quic_proxy::{self, Forwarding, RegisterClientCid};
use shiguredo_masque::udp_bind::{CompressionAssign, CompressionTarget};

fn roundtrip(capsule: Capsule) {
    let bytes = capsule.encode().expect("カプセルを書ける");
    let mut decoder = CapsuleDecoder::new();
    decoder.push(&bytes).expect("追加できる");
    assert_eq!(decoder.poll().expect("読める"), Some(capsule));
}

#[test]
fn connect_ip_scope_rejects_a_destination_outside_the_prefix() {
    // RFC 9484 Section 4.6。target がプレフィックスなら、その外へは送らない。
    let mut client = ConnectIp::new(Role::Client);
    client.set_scope(RequestScope {
        target: TargetScope::Prefix(
            IpPrefix::new(Ipv4Addr::new(192, 0, 2, 0).into(), 24).expect("プレフィックスは有効"),
        ),
        ipproto: Some(17),
    });
    let packet = ip::encode_ipv4(
        Ipv4Addr::new(192, 0, 2, 11),
        Ipv4Addr::new(198, 51, 100, 1),
        17,
        64,
        b"x",
    )
    .expect("パケットを作れる");
    assert_eq!(
        client.send_ip_packet(&packet, true),
        Err(SendError::OutOfScope)
    );
    let icmp = ip::encode_ipv4(
        Ipv4Addr::new(192, 0, 2, 11),
        Ipv4Addr::new(192, 0, 2, 1),
        ip::IPV4_ICMP,
        64,
        &[8, 0, 0, 0, 0, 0, 0, 0],
    )
    .expect("ICMP を作れる");
    // スコープが UDP でも ICMP は通す。経路が無いので NoRoute になる。
    assert_eq!(client.send_ip_packet(&icmp, true), Err(SendError::NoRoute));
}

#[test]
fn ipv6_below_minimum_link_mtu_aborts_the_session() {
    // RFC 9484 Section 7.2。1280 バイトを送れない IPv6 トンネルは止める。
    let mut client = ConnectIp::new(Role::Client);
    client.set_max_ip_packet_len(1200);
    let packet = ip::encode_ipv6(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 59, 64, &[0; 8])
        .expect("IPv6 パケットを作れる");
    assert_eq!(
        client.send_ip_packet(&packet, true),
        Err(SendError::Ipv6LinkMtu)
    );
    assert!(client.is_aborted());
}

#[test]
fn udp_payload_that_does_not_fit_is_dropped_without_abort() {
    let mut client = ConnectUdp::new(shiguredo_masque::connect_udp::Role::Client);
    client.set_max_udp_payload(4);
    assert_eq!(
        client.send_udp_payload(b"12345"),
        Err(UdpSendError::DoesNotFit { max_payload: 4 })
    );
    assert!(!client.is_aborted());
}

#[test]
fn udp_bind_registers_a_compressed_context_and_carries_payload() {
    let mut client = ConnectUdp::new(shiguredo_masque::connect_udp::Role::Client);
    let mut proxy = ConnectUdp::new(shiguredo_masque::connect_udp::Role::Proxy);
    client.enable_bind(false);
    proxy.enable_bind(false);
    client
        .register_context(CompressionAssign {
            context_id: 2,
            target: CompressionTarget::Compressed {
                address: Ipv4Addr::new(192, 0, 2, 1).into(),
                port: 53,
            },
        })
        .expect("偶数の Context ID を登録できる");
    let request = client.poll_capsule().expect("ASSIGN がある");
    proxy
        .recv_stream(&request, false)
        .expect("プロキシが受理できる");
    let ack = proxy.poll_capsule().expect("ACK を返す");
    client
        .recv_stream(&ack, false)
        .expect("クライアントが ACK を受け取れる");
    let datagram = client
        .send_compressed(2, b"dns")
        .expect("登録済みコンテキストで送れる");
    proxy
        .recv_http_datagram(&datagram)
        .expect("プロキシが受け取れる");
    assert!(matches!(
        proxy.poll_event(),
        Some(Event::Bound {
            port: 53,
            payload,
            ..
        }) if payload == b"dns"
    ));
}

#[test]
fn wildcard_bind_rejects_context_zero() {
    let mut proxy = ConnectUdp::new(shiguredo_masque::connect_udp::Role::Proxy);
    proxy.enable_bind(true);
    assert_eq!(proxy.recv_http_datagram(&[0x00]), Err(Error::ContextIdZero));
    assert!(proxy.is_aborted());
}

#[test]
fn ecn_header_and_capsule_roundtrip() {
    let parsed =
        ecn::parse_ecn_dscp_header("(0,0,2,4,6), (46,8,10,12,14)").expect("例のヘッダを読める");
    assert_eq!(parsed[1].dscp, 46);
    assert_eq!(parsed[1].context_id(1), Some(10));
    roundtrip(Capsule::EcnDscpAssign(parsed));
}

#[test]
fn ethernet_frame_omits_context_zero_and_fcs() {
    let session = ConnectEthernet::new();
    let mut frame = vec![0xff; 6];
    frame.extend_from_slice(&[0x02; 6]);
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.extend_from_slice(b"payload");
    let datagram = session.send_frame(&frame).expect("フレームを包める");
    assert!(matches!(
        session.recv_http_datagram(&datagram).expect("戻せる"),
        RecvFrame::Frame(decoded) if decoded == frame
    ));
}

#[test]
fn template_removes_and_restores_static_bytes() {
    let segments = vec![StaticSegment {
        offset: 0,
        payload: b"ab".to_vec(),
    }];
    let packet = b"abxyz";
    let payload = compress::compress_template(packet, &segments).expect("可変部を取り出せる");
    assert_eq!(payload, b"xyz");
    assert_eq!(
        compress::expand_template(&payload, &segments).expect("戻せる"),
        packet
    );
    roundtrip(Capsule::TemplateAssign(TemplateAssign {
        context_id: 4,
        next_context_id: 0,
        segments,
    }));
}

#[test]
fn ipv4_total_length_can_be_stripped_and_recomputed() {
    let packet = ip::encode_ipv4(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 17, 64, b"hi")
        .expect("IPv4 を作れる");
    let stripped = compress::strip_derived_fields(&packet, &[compress::IPV4_TOTAL_LENGTH])
        .expect("Total Length を除ける");
    assert_eq!(stripped.len(), packet.len() - 2);
    let restored = compress::insert_derived_fields(&stripped, &[compress::IPV4_TOTAL_LENGTH])
        .expect("Total Length を計算して戻せる");
    assert_eq!(restored.len(), packet.len());
    assert_eq!(&restored[2..4], &packet[2..4]);
}

#[test]
fn quic_long_header_is_tunnelled_and_matching_short_header_is_forwarded() {
    let long_header = [0x80, 1, 2, 3, 4];
    assert_eq!(
        quic_proxy::classify_packet(&long_header, 4, &[vec![1, 2, 3, 4]]),
        Forwarding::Tunnelled
    );
    let short_header = [0x40, 9, 8, 7, 6];
    assert_eq!(
        quic_proxy::classify_packet(&short_header, 4, &[vec![9, 8, 7, 6]]),
        Forwarding::Forwarded {
            virtual_connection_id: vec![9, 8, 7, 6],
        }
    );
    roundtrip(Capsule::RegisterClientCid(RegisterClientCid {
        sequence: 0,
        connection_id: vec![9, 8, 7, 6],
    }));
}

#[test]
fn ecn_assignment_rejects_a_reused_context_id() {
    assert_eq!(
        EcnDscpAssignment::new(0, 0, 2, 2, 6),
        Err(Error::DuplicateContext)
    );
}
