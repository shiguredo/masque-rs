//! CONNECT-UDP の Context ID 0 と長さ制限。

use shiguredo_masque::connect_udp::{ConnectUdp, Event, MAX_UDP_PAYLOAD, Role};
use shiguredo_masque::error::Error;

#[test]
fn udp_payload_roundtrips_on_context_zero() {
    let mut client = ConnectUdp::new(Role::Client);
    let mut proxy = ConnectUdp::new(Role::Proxy);
    let datagram = client
        .send_udp_payload(b"dns")
        .expect("UDP ペイロードをデータグラムにできる");
    proxy
        .recv_http_datagram(&datagram)
        .expect("プロキシが受け取れる");
    assert_eq!(proxy.poll_event(), Some(Event::UdpPayload(b"dns".to_vec())));
}

#[test]
fn sending_an_overlong_udp_payload_does_not_abort() {
    // 送ってはいけないが、ローカルの拒否でストリームは破棄しない。
    let mut client = ConnectUdp::new(Role::Client);
    let payload = vec![0u8; MAX_UDP_PAYLOAD + 1];
    assert_eq!(
        client.send_udp_payload(&payload),
        Err(shiguredo_masque::connect_udp::UdpSendError::PayloadTooLong)
    );
    assert!(!client.is_aborted());
}

#[test]
fn receiving_an_overlong_udp_payload_aborts_the_stream() {
    // RFC 9298 Section 5。
    let mut proxy = ConnectUdp::new(Role::Proxy);
    let mut payload = vec![0u8];
    payload.extend(std::iter::repeat_n(0u8, MAX_UDP_PAYLOAD + 1));
    assert_eq!(
        proxy.recv_http_datagram(&payload),
        Err(Error::UdpPayloadTooLong)
    );
    assert!(proxy.is_aborted());
    assert_eq!(proxy.recv_http_datagram(&[0]), Err(Error::Aborted));
}

#[test]
fn unknown_context_is_not_a_udp_payload() {
    let mut proxy = ConnectUdp::new(Role::Proxy);
    proxy
        .recv_http_datagram(&[0x04, b'x'])
        .expect("未知 Context ID は破棄しない");
    assert_eq!(
        proxy.poll_event(),
        Some(Event::UnknownContext { context_id: 4 })
    );
}
