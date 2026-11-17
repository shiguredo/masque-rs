//! カプセルのエラーパス。ラウンドトリップは pbt に置く。

use core::net::{Ipv4Addr, Ipv6Addr};

use shiguredo_masque::capsule::{
    ADDRESS_ASSIGN, Capsule, CapsuleDecoder, capsule_protocol_header_is_true,
};
use shiguredo_masque::error::Error;
use shiguredo_masque::ip::{AssignedAddress, IpPrefix, RequestedAddress, RouteRange};
use shiguredo_masque::varint;

fn prefix_v4(octets: [u8; 4], len: u8) -> IpPrefix {
    IpPrefix::new(Ipv4Addr::from(octets).into(), len).expect("テストのプレフィックスは有効")
}

#[test]
fn unknown_capsule_is_skipped_and_the_next_one_is_kept() {
    // RFC 9297 Section 3.2: 未知タイプは黙って捨てて次を読む。
    let assign = Capsule::AddressAssign(vec![AssignedAddress {
        request_id: 0,
        prefix: prefix_v4([192, 0, 2, 11], 32),
    }]);
    let mut bytes = Vec::new();
    varint::encode(0x2a, &mut bytes).expect("未知タイプを書ける");
    varint::encode(3, &mut bytes).expect("長さを書ける");
    bytes.extend_from_slice(&[1, 2, 3]);
    bytes.extend(assign.encode().expect("ADDRESS_ASSIGN を書ける"));

    let mut decoder = CapsuleDecoder::new();
    decoder.push(&bytes).expect("バイトを追加できる");
    let decoded = decoder
        .poll()
        .expect("デコードできる")
        .expect("次のカプセルが残る");
    assert_eq!(decoded, assign);
    assert!(decoder.poll().expect("続きはエラーではない").is_none());
}

#[test]
fn oversized_datagram_is_discarded_without_failing_the_stream() {
    // RFC 9297 Section 3.5: 使えないほど長い DATAGRAM は溜めずに捨てる。
    let mut decoder = CapsuleDecoder::with_max_value_len(4);
    let mut header = Vec::new();
    varint::encode(0, &mut header).expect("DATAGRAM タイプを書ける");
    varint::encode(8, &mut header).expect("上限を超える長さを書ける");
    decoder.push(&header).expect("ヘッダを追加できる");
    assert!(
        decoder
            .poll()
            .expect("巨大 DATAGRAM ではストリームを止めない")
            .is_none()
    );
    decoder.push(&[9, 9, 9, 9]).expect("値の前半を追加できる");
    let assign = Capsule::AddressAssign(Vec::new());
    let mut rest = vec![9, 9, 9, 9];
    rest.extend(assign.encode().expect("空の ADDRESS_ASSIGN を書ける"));
    decoder
        .push(&rest)
        .expect("値の後半と次のカプセルを追加できる");
    assert_eq!(decoder.poll().expect("次のカプセルを読める"), Some(assign));
}

#[test]
fn oversized_control_capsule_aborts() {
    let mut decoder = CapsuleDecoder::with_max_value_len(4);
    let mut header = Vec::new();
    varint::encode(ADDRESS_ASSIGN, &mut header).expect("タイプを書ける");
    varint::encode(8, &mut header).expect("長さを書ける");
    decoder.push(&header).expect("ヘッダを追加できる");
    assert_eq!(decoder.poll(), Err(Error::CapsuleTooLarge));
}

#[test]
fn fin_on_a_partial_capsule_is_truncated() {
    // RFC 9297 Section 3.3。
    let mut decoder = CapsuleDecoder::new();
    decoder
        .push(&[0x00])
        .expect("タイプの 1 バイトだけを追加できる");
    assert_eq!(decoder.finish(), Err(Error::Truncated));
}

#[test]
fn capsule_protocol_header_accepts_only_a_true_boolean() {
    // RFC 9297 Section 3.4。パラメータは無視し、Boolean 以外は不在と同じ。
    assert!(capsule_protocol_header_is_true("?1"));
    assert!(capsule_protocol_header_is_true(" ?1;foo=1"));
    assert!(!capsule_protocol_header_is_true("?0"));
    assert!(!capsule_protocol_header_is_true("?1, ?1"));
    assert!(!capsule_protocol_header_is_true("1"));
}

#[test]
fn empty_address_request_is_rejected() {
    // RFC 9484 Section 4.7.2。
    let error = Capsule::AddressRequest(Vec::new()).encode();
    assert_eq!(error, Err(Error::EmptyAddressRequest));
}

#[test]
fn route_order_and_protocol_zero_overlap_are_rejected() {
    let low = RouteRange::new(
        Ipv4Addr::new(192, 0, 2, 0).into(),
        Ipv4Addr::new(192, 0, 2, 10).into(),
        0,
    )
    .expect("範囲を作れる");
    let high = RouteRange::new(
        Ipv4Addr::new(192, 0, 2, 5).into(),
        Ipv4Addr::new(192, 0, 2, 20).into(),
        17,
    )
    .expect("範囲を作れる");
    // protocol 0 が後ろの具体プロトコルとアドレスで重なる。
    assert_eq!(
        Capsule::RouteAdvertisement(vec![low, high]).encode(),
        Err(Error::RouteOverlap)
    );
    let v6 = RouteRange::new(Ipv6Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into(), 0)
        .expect("IPv6 範囲を作れる");
    // IPv6 を IPv4 より前に置くと順序違反。
    assert_eq!(
        Capsule::RouteAdvertisement(vec![v6, low]).encode(),
        Err(Error::RouteUnordered)
    );
}

#[test]
fn request_id_zero_is_rejected() {
    let requested = RequestedAddress {
        request_id: 0,
        prefix: prefix_v4([0, 0, 0, 0], 32),
    };
    assert_eq!(
        Capsule::AddressRequest(vec![requested]).encode(),
        Err(Error::RequestIdZero)
    );
}
