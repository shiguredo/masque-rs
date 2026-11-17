//! CONNECT-IP の DNS 設定と PREF64
//!
//! draft-ietf-masque-connect-ip-dns-07。カプセル型の番号は承認時に
//! 小さい値へ置き換わる暫定値である (Section 6)。ドラフトが改訂されたら
//! この番号とフィールド並びは変わる。

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::Error;
use crate::reader::Reader;
use crate::varint;
use alloc::string::String;
use alloc::vec::Vec;

/// DNS_ASSIGN の暫定カプセル型 (draft-ietf-masque-connect-ip-dns-07 Section 6)
pub const DNS_ASSIGN: u64 = 0x1ACE_79EC;
/// PREF64 の暫定カプセル型 (draft-ietf-masque-connect-ip-dns-07 Section 6)
pub const PREF64: u64 = 0x274C_0FBC;

/// SVCB の ipv4hint (RFC 9460 Section 14.5)
const SVC_IPV4HINT: u16 = 4;
/// SVCB の ipv6hint (RFC 9460 Section 14.5)
const SVC_IPV6HINT: u16 = 6;
/// SVCB の alpn
const SVC_ALPN: u16 = 1;
/// SVCB の no-default-alpn
const SVC_NO_DEFAULT_ALPN: u16 = 2;

/// NAT64 プレフィックス (draft-ietf-masque-connect-ip-dns-07 Section 4.1)
///
/// `prefix` は常に 96 bit。`prefix_length` は 32, 40, 48, 56, 64, 96 のいずれか。
/// プレフィックス長より下のビットは 0 にする (RFC 6052 Section 2.2 の余白)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nat64Prefix {
    /// プレフィックス長
    pub prefix_length: u8,
    /// 上位 96 bit
    pub prefix: [u8; 12],
}

impl Nat64Prefix {
    /// NAT64 プレフィックスを作る
    pub fn new(prefix_length: u8, prefix: [u8; 12]) -> Result<Self, Error> {
        if !matches!(prefix_length, 32 | 40 | 48 | 56 | 64 | 96) {
            return Err(Error::InvalidNat64PrefixLength);
        }
        if !nat64_host_bits_clear(prefix_length, prefix) {
            return Err(Error::Nat64PrefixBits);
        }
        Ok(Self {
            prefix_length,
            prefix,
        })
    }
}

/// 1 台のネームサーバ (draft-ietf-masque-connect-ip-dns-07 Section 3.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nameserver {
    /// SVCB の Service Priority。0 は禁止
    pub priority: u16,
    /// 到達に使うアドレス
    pub addresses: Vec<IpAddr>,
    /// 認証ドメイン名。空なら平文 DNS だけ
    pub authentication_domain: String,
    /// SVCB Service Parameters のワイヤ形式 (RFC 9460 Section 2.2)
    pub service_parameters: Vec<u8>,
}

/// DNS_ASSIGN に並べる設定 1 件 (Section 3.3)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfiguration {
    /// この設定のネームサーバ。1 台以上
    pub nameservers: Vec<Nameserver>,
    /// このネームサーバが解ける内部ドメイン。空文字は DNS ルート
    pub internal_domains: Vec<String>,
    /// 検索ドメイン
    pub search_domains: Vec<String>,
}

pub(crate) fn encode_dns(configs: &[DnsConfiguration], out: &mut Vec<u8>) -> Result<(), Error> {
    for config in configs {
        validate_config(config)?;
        varint::encode(u64_len(config.nameservers.len())?, out)?;
        for server in &config.nameservers {
            encode_nameserver(server, out)?;
        }
        encode_domains(&config.internal_domains, out)?;
        encode_domains(&config.search_domains, out)?;
    }
    Ok(())
}

pub(crate) fn decode_dns(buf: &[u8]) -> Result<Vec<DnsConfiguration>, Error> {
    let mut reader = Reader::new(buf);
    let mut configs = Vec::new();
    while !reader.is_empty() {
        let count = reader.varint()?;
        if count == 0 {
            return Err(Error::DnsNameserverCount);
        }
        if count > reader.remaining() as u64 {
            return Err(Error::Malformed);
        }
        let mut nameservers = Vec::new();
        for _ in 0..count {
            nameservers.push(decode_nameserver(&mut reader)?);
        }
        let internal_domains = decode_domains(&mut reader)?;
        let search_domains = decode_domains(&mut reader)?;
        let config = DnsConfiguration {
            nameservers,
            internal_domains,
            search_domains,
        };
        validate_config(&config)?;
        configs.push(config);
    }
    Ok(configs)
}

pub(crate) fn encode_pref64(prefixes: &[Nat64Prefix], out: &mut Vec<u8>) {
    for prefix in prefixes {
        out.push(prefix.prefix_length);
        out.extend_from_slice(&prefix.prefix);
    }
}

pub(crate) fn decode_pref64(buf: &[u8]) -> Result<Vec<Nat64Prefix>, Error> {
    // 1 件が 13 バイト。余りが出る長さは不正 (Section 4.2)。
    if !buf.len().is_multiple_of(13) {
        return Err(Error::Malformed);
    }
    let mut prefixes = Vec::new();
    for chunk in buf.chunks(13) {
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&chunk[1..]);
        prefixes.push(Nat64Prefix::new(chunk[0], prefix)?);
    }
    Ok(prefixes)
}

fn encode_nameserver(server: &Nameserver, out: &mut Vec<u8>) -> Result<(), Error> {
    out.extend_from_slice(&server.priority.to_be_bytes());
    let (v4, v6) = split_addresses(&server.addresses)?;
    varint::encode(u64_len(v4.len())?, out)?;
    for addr in v4 {
        out.extend_from_slice(&addr.octets());
    }
    varint::encode(u64_len(v6.len())?, out)?;
    for addr in v6 {
        out.extend_from_slice(&addr.octets());
    }
    encode_domain(&server.authentication_domain, out)?;
    varint::encode(u64_len(server.service_parameters.len())?, out)?;
    out.extend_from_slice(&server.service_parameters);
    Ok(())
}

fn decode_nameserver(reader: &mut Reader<'_>) -> Result<Nameserver, Error> {
    let priority = reader.u16()?;
    let v4_count = reader.varint()?;
    if v4_count > reader.remaining() as u64 {
        return Err(Error::Malformed);
    }
    let mut addresses = Vec::new();
    for _ in 0..v4_count {
        let bytes: [u8; 4] = read_array(reader)?;
        addresses.push(IpAddr::V4(Ipv4Addr::from(bytes)));
    }
    let v6_count = reader.varint()?;
    if v6_count > reader.remaining() as u64 {
        return Err(Error::Malformed);
    }
    for _ in 0..v6_count {
        let bytes: [u8; 16] = read_array(reader)?;
        addresses.push(IpAddr::V6(Ipv6Addr::from(bytes)));
    }
    let authentication_domain = decode_domain(reader)?;
    let param_len = reader.varint()?;
    if param_len > reader.remaining() as u64 {
        return Err(Error::Malformed);
    }
    let service_parameters = reader.take(param_len as usize)?.to_vec();
    Ok(Nameserver {
        priority,
        addresses,
        authentication_domain,
        service_parameters,
    })
}

fn encode_domains(domains: &[String], out: &mut Vec<u8>) -> Result<(), Error> {
    varint::encode(u64_len(domains.len())?, out)?;
    for domain in domains {
        encode_domain(domain, out)?;
    }
    Ok(())
}

fn decode_domains(reader: &mut Reader<'_>) -> Result<Vec<String>, Error> {
    let count = reader.varint()?;
    if count > reader.remaining() as u64 {
        return Err(Error::Malformed);
    }
    let mut domains = Vec::new();
    for _ in 0..count {
        domains.push(decode_domain(reader)?);
    }
    Ok(domains)
}

fn encode_domain(domain: &str, out: &mut Vec<u8>) -> Result<(), Error> {
    validate_domain(domain)?;
    varint::encode(u64_len(domain.len())?, out)?;
    out.extend_from_slice(domain.as_bytes());
    Ok(())
}

fn decode_domain(reader: &mut Reader<'_>) -> Result<String, Error> {
    let len = reader.varint()?;
    if len > reader.remaining() as u64 {
        return Err(Error::Malformed);
    }
    let bytes = reader.take(len as usize)?;
    let domain = core::str::from_utf8(bytes).map_err(|_| Error::InvalidDomain)?;
    validate_domain(domain)?;
    Ok(String::from(domain))
}

fn validate_config(config: &DnsConfiguration) -> Result<(), Error> {
    if config.nameservers.is_empty() {
        return Err(Error::DnsNameserverCount);
    }
    for server in &config.nameservers {
        validate_nameserver(server)?;
    }
    for domain in config
        .internal_domains
        .iter()
        .chain(config.search_domains.iter())
    {
        validate_domain(domain)?;
    }
    Ok(())
}

fn validate_nameserver(server: &Nameserver) -> Result<(), Error> {
    // ServiceMode だけを使うので優先度 0 (AliasMode) は禁止 (Section 3.2)。
    if server.priority == 0 {
        return Err(Error::InvalidNameserver);
    }
    validate_domain(&server.authentication_domain)?;
    let saw = validate_svc_params(&server.service_parameters)?;
    if server.authentication_domain.is_empty() && (saw.alpn || saw.no_default_alpn) {
        return Err(Error::InvalidNameserver);
    }
    // no-default-alpn が無いときは平文 DNS も提供するので、アドレスが要る。
    if !saw.no_default_alpn && server.addresses.is_empty() {
        return Err(Error::InvalidNameserver);
    }
    Ok(())
}

struct SvcSeen {
    alpn: bool,
    no_default_alpn: bool,
}

fn validate_svc_params(buf: &[u8]) -> Result<SvcSeen, Error> {
    let mut reader = Reader::new(buf);
    let mut last_key: Option<u16> = None;
    let mut seen = SvcSeen {
        alpn: false,
        no_default_alpn: false,
    };
    while !reader.is_empty() {
        if reader.remaining() < 4 {
            return Err(Error::InvalidServiceParameters);
        }
        let key = reader.u16()?;
        let len = usize::from(reader.u16()?);
        if reader.remaining() < len {
            return Err(Error::InvalidServiceParameters);
        }
        let _value = reader.take(len)?;
        // キーは厳密増加 (RFC 9460 Section 2.2)。
        if last_key.is_some_and(|prev| key <= prev) {
            return Err(Error::InvalidServiceParameters);
        }
        last_key = Some(key);
        if key == SVC_IPV4HINT || key == SVC_IPV6HINT {
            return Err(Error::InvalidServiceParameters);
        }
        if key == SVC_ALPN {
            seen.alpn = true;
        }
        if key == SVC_NO_DEFAULT_ALPN {
            if len != 0 {
                return Err(Error::InvalidServiceParameters);
            }
            seen.no_default_alpn = true;
        }
    }
    Ok(seen)
}

/// 末尾ドット無しの表示形式 FQDN。空文字はフィールドごとの特別な意味を持つ。
///
/// 非 ASCII は拒否する。国際化ラベルは IDNA の A-label で渡す
/// (draft-ietf-masque-connect-ip-dns-07 Section 3.1)。
fn validate_domain(domain: &str) -> Result<(), Error> {
    if domain.is_empty() {
        return Ok(());
    }
    if domain.ends_with('.') || domain.len() > 253 {
        return Err(Error::InvalidDomain);
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::InvalidDomain);
        }
        let bytes = label.as_bytes();
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return Err(Error::InvalidDomain);
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return Err(Error::InvalidDomain);
        }
    }
    Ok(())
}

fn split_addresses(addresses: &[IpAddr]) -> Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>), Error> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for addr in addresses {
        match addr {
            IpAddr::V4(addr) => v4.push(*addr),
            IpAddr::V6(addr) => v6.push(*addr),
        }
    }
    Ok((v4, v6))
}

fn nat64_host_bits_clear(prefix_length: u8, prefix: [u8; 12]) -> bool {
    let mut bits = 0u128;
    for byte in prefix {
        bits = (bits << 8) | u128::from(byte);
    }
    // 96 bit フィールドの下位側を見る。上位 32 bit は使っていない。
    let host = 96 - prefix_length;
    if host == 0 {
        return true;
    }
    let mask = (1u128 << host) - 1;
    bits & mask == 0
}

fn u64_len(len: usize) -> Result<u64, Error> {
    u64::try_from(len).map_err(|_| Error::Malformed)
}

fn read_array<const N: usize>(reader: &mut Reader<'_>) -> Result<[u8; N], Error> {
    let bytes = reader.take(N)?;
    let mut array = [0u8; N];
    array.copy_from_slice(bytes);
    Ok(array)
}
