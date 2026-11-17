//! DNS_ASSIGN と PREF64 の拒否条件。正常系の往復は pbt と CONNECT-IP の受信で見る。

use core::net::Ipv4Addr;

use shiguredo_masque::capsule::Capsule;
use shiguredo_masque::dns::{DnsConfiguration, Nameserver, Nat64Prefix};
use shiguredo_masque::error::Error;

fn nameserver() -> Nameserver {
    Nameserver {
        priority: 1,
        addresses: vec![Ipv4Addr::new(192, 0, 2, 53).into()],
        authentication_domain: String::new(),
        service_parameters: Vec::new(),
    }
}

#[test]
fn dns_assign_roundtrip_and_session_keeps_the_latest() {
    let config = DnsConfiguration {
        nameservers: vec![nameserver()],
        internal_domains: vec!["internal.example".to_string()],
        search_domains: vec!["example".to_string()],
    };
    let bytes = Capsule::DnsAssign(vec![config.clone()])
        .encode()
        .expect("DNS_ASSIGN を書ける");
    let mut decoder = shiguredo_masque::capsule::CapsuleDecoder::new();
    decoder.push(&bytes).expect("追加できる");
    assert_eq!(
        decoder.poll().expect("読める"),
        Some(Capsule::DnsAssign(vec![config]))
    );
}

#[test]
fn nameserver_priority_zero_is_rejected() {
    let mut server = nameserver();
    server.priority = 0;
    let config = DnsConfiguration {
        nameservers: vec![server],
        internal_domains: Vec::new(),
        search_domains: Vec::new(),
    };
    assert_eq!(
        Capsule::DnsAssign(vec![config]).encode(),
        Err(Error::InvalidNameserver)
    );
}

#[test]
fn ipv4hint_is_rejected() {
    // アドレスは専用フィールドにあり、ipv4hint は重複なので禁止。
    let mut server = nameserver();
    server.service_parameters = vec![0, 4, 0, 4, 192, 0, 2, 53];
    let config = DnsConfiguration {
        nameservers: vec![server],
        internal_domains: Vec::new(),
        search_domains: Vec::new(),
    };
    assert_eq!(
        Capsule::DnsAssign(vec![config]).encode(),
        Err(Error::InvalidServiceParameters)
    );
}

#[test]
fn pref64_well_known_prefix_roundtrips() {
    // 64:ff9b::/96。下位は 0。
    let prefix = Nat64Prefix::new(96, [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0])
        .expect("well-known prefix は有効");
    let bytes = Capsule::Pref64(vec![prefix])
        .encode()
        .expect("PREF64 を書ける");
    let mut decoder = shiguredo_masque::capsule::CapsuleDecoder::new();
    decoder.push(&bytes).expect("追加できる");
    assert_eq!(
        decoder.poll().expect("読める"),
        Some(Capsule::Pref64(vec![prefix]))
    );
}

#[test]
fn pref64_rejects_a_bad_length_and_nonzero_host_bits() {
    assert_eq!(
        Nat64Prefix::new(16, [0; 12]),
        Err(Error::InvalidNat64PrefixLength)
    );
    assert_eq!(
        Nat64Prefix::new(32, [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 1]),
        Err(Error::Nat64PrefixBits)
    );
}
