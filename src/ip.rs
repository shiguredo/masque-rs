//! IP プレフィックス、経路、IP パケット
//!
//! アドレスの代入と経路広告のワイヤ形式は RFC 9484 Section 4.7。
//! パケットの転送判定は Section 7.2。OS のルーティングテーブルは持たない。

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::Error;
use crate::reader::Reader;
use crate::varint;
use alloc::vec::Vec;

/// IPv4 ICMP (RFC 792)
pub const IPV4_ICMP: u8 = 1;
/// IPv6 ICMPv6 (RFC 4443)
pub const IPV6_ICMP: u8 = 58;

/// 代入または要求する IP プレフィックス
///
/// `prefix_length` より下のビットは 0 でなければならない
/// (RFC 9484 Section 4.7.1)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPrefix {
    /// プレフィックスのアドレス
    pub address: IpAddr,
    /// プレフィックス長 (ビット)
    pub prefix_length: u8,
}

impl IpPrefix {
    /// プレフィックスを作る
    ///
    /// 長さがアドレス長を超える、または下位ビットが 0 でないときはエラー。
    pub fn new(address: IpAddr, prefix_length: u8) -> Result<Self, Error> {
        let bits = address_bits(address);
        if prefix_length > bits {
            return Err(Error::InvalidPrefixLength);
        }
        if !host_bits_clear(address, prefix_length) {
            return Err(Error::PrefixHostBits);
        }
        Ok(Self {
            address,
            prefix_length,
        })
    }

    /// `addr` がこのプレフィックスに含まれるか
    pub fn contains(self, addr: IpAddr) -> bool {
        if version_of(self.address) != version_of(addr) {
            return false;
        }
        let bits = address_bits(self.address);
        if self.prefix_length == 0 {
            return true;
        }
        let shift = u32::from(bits - self.prefix_length);
        (to_bits(self.address) >> shift) == (to_bits(addr) >> shift)
    }
}

/// ADDRESS_ASSIGN の 1 要素 (RFC 9484 Section 4.7.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssignedAddress {
    /// 対応する ADDRESS_REQUEST の Request ID。自発代入は 0
    pub request_id: u64,
    /// 代入するプレフィックス
    pub prefix: IpPrefix,
}

/// ADDRESS_REQUEST の 1 要素 (RFC 9484 Section 4.7.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestedAddress {
    /// 0 以外の要求識別子。再利用しない
    pub request_id: u64,
    /// 希望するプレフィックス。全ビット 0 はファミリだけの希望
    pub prefix: IpPrefix,
}

/// ROUTE_ADVERTISEMENT の 1 範囲 (RFC 9484 Section 4.7.3)
///
/// `protocol == 0` は全プロトコル。ICMP は 0 以外の値でも常に通る。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRange {
    /// 範囲の始点 (含む)
    pub start: IpAddr,
    /// 範囲の終点 (含む)
    pub end: IpAddr,
    /// Internet Protocol Number。0 はすべて
    pub protocol: u8,
}

impl RouteRange {
    /// 経路範囲を作る
    ///
    /// ファミリが違う、または始点が終点より大きいときはエラー。
    pub fn new(start: IpAddr, end: IpAddr, protocol: u8) -> Result<Self, Error> {
        if version_of(start) != version_of(end) {
            return Err(Error::AddressFamilyMismatch);
        }
        if to_bits(start) > to_bits(end) {
            return Err(Error::RouteInverted);
        }
        Ok(Self {
            start,
            end,
            protocol,
        })
    }

    /// `addr` が範囲に入るか
    pub fn contains(self, addr: IpAddr) -> bool {
        version_of(self.start) == version_of(addr)
            && to_bits(self.start) <= to_bits(addr)
            && to_bits(addr) <= to_bits(self.end)
    }
}

/// リンクローカル、およびリンクローカルマルチキャストか
///
/// IPv4 は 169.254.0.0/16 と 224.0.0.0/24。
/// IPv6 は fe80::/10 と ff02::/16。
/// これらをトンネルの外へ転送しない (RFC 9484 Section 7.2)。
pub fn is_link_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            (oct[0] == 169 && oct[1] == 254) || (oct[0] == 224 && oct[1] == 0 && oct[2] == 0)
        }
        IpAddr::V6(v6) => {
            let oct = v6.octets();
            (oct[0] == 0xfe && (oct[1] & 0xc0) == 0x80) || (oct[0] == 0xff && oct[1] == 0x02)
        }
    }
}

/// 最小ヘッダの IPv4 パケットを作る
///
/// ペイロード長を足した総長が u16 に収まらないときは [`Error::Malformed`]。
pub fn encode_ipv4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    hop_limit: u8,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let total = 20usize.checked_add(payload.len()).ok_or(Error::Malformed)?;
    if total > usize::from(u16::MAX) {
        return Err(Error::Malformed);
    }
    let mut packet = Vec::new();
    packet.push(0x45);
    packet.push(0);
    packet.extend_from_slice(&(total as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.push(hop_limit);
    packet.push(protocol);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    write_ipv4_checksum(&mut packet);
    packet.extend_from_slice(payload);
    Ok(packet)
}

/// 拡張ヘッダなしの IPv6 パケットを作る
pub fn encode_ipv6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    hop_limit: u8,
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    if payload.len() > usize::from(u16::MAX) {
        return Err(Error::Malformed);
    }
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x60, 0, 0, 0]);
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.push(next_header);
    packet.push(hop_limit);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(payload);
    Ok(packet)
}

/// IP パケットから転送判定に使うフィールドを読む
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedIp {
    /// 送信元
    pub src: IpAddr,
    /// 宛先
    pub dst: IpAddr,
    /// 拡張ヘッダを辿ったあとの上位プロトコル
    ///
    /// RFC 9484 Section 4.8。Hop-by-Hop、Routing、Fragment、AH、
    /// Destination Options は飛ばす。ESP は中を読めないので 50 のままにする。
    pub protocol: u8,
    /// Hop Limit または TTL
    pub hop_limit: u8,
}

/// `packet` を 1 個の IP パケットとして読む
///
/// 総長がバッファ長と一致しないときは [`Error::Malformed`]。
pub fn parse_ip(packet: &[u8]) -> Result<ParsedIp, Error> {
    let version = packet.first().ok_or(Error::Malformed)? >> 4;
    if version == 4 {
        parse_ipv4(packet)
    } else if version == 6 {
        parse_ipv6(packet)
    } else {
        Err(Error::InvalidIpVersion)
    }
}

/// 転送する直前に Hop Limit / TTL を 1 減らしたパケットを返す
///
/// エンドポイント自身が作ったパケットには使わない (RFC 9484 Section 7.2)。
/// 減算前の値が 0 または 1 のときは `None`。呼び出し側は Time Exceeded を返す。
pub fn decrement_hop_limit(packet: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let parsed = parse_ip(packet)?;
    if parsed.hop_limit <= 1 {
        return Ok(None);
    }
    let mut out = Vec::new();
    out.extend_from_slice(packet);
    match parsed.src {
        IpAddr::V4(_) => {
            out[8] = parsed.hop_limit - 1;
            out[10] = 0;
            out[11] = 0;
            write_ipv4_checksum(&mut out);
        }
        IpAddr::V6(_) => {
            out[7] = parsed.hop_limit - 1;
        }
    }
    Ok(Some(out))
}

/// Packet Too Big または Destination Unreachable の IP パケットを作る
///
/// 送信元は元パケットの宛先、宛先は元パケットの送信元にする。
/// 呼び出し側がトンネルのアドレスへ書き換えてよい。
pub fn icmp_error(original: &[u8], kind: IcmpError, mtu: u32) -> Result<Vec<u8>, Error> {
    let parsed = parse_ip(original)?;
    match (parsed.src, parsed.dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => encode_ipv4_icmp(dst, src, original, kind, mtu),
        (IpAddr::V6(src), IpAddr::V6(dst)) => encode_ipv6_icmp(dst, src, original, kind, mtu),
        _ => Err(Error::Malformed),
    }
}

/// 返す ICMP の種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpError {
    /// 宛先への経路が無い
    NoRoute,
    /// 送信元が代入プレフィックスの外
    BadSource,
    /// 外向きリンクの MTU に入らない
    PacketTooBig,
    /// Hop Limit / TTL を減らせない
    HopLimitExceeded,
}

pub(crate) fn encode_assigned(list: &[AssignedAddress], out: &mut Vec<u8>) -> Result<(), Error> {
    for item in list {
        // 全 0 かつ最大長は「代入しなかった」印であり、ホストビット検査は通る。
        varint::encode(item.request_id, out)?;
        encode_prefix(item.prefix, out);
    }
    Ok(())
}

pub(crate) fn decode_assigned(buf: &[u8]) -> Result<Vec<AssignedAddress>, Error> {
    let mut reader = Reader::new(buf);
    let mut list = Vec::new();
    while !reader.is_empty() {
        let request_id = reader.varint()?;
        let prefix = decode_prefix(&mut reader)?;
        list.push(AssignedAddress { request_id, prefix });
    }
    Ok(list)
}

pub(crate) fn encode_requested(list: &[RequestedAddress], out: &mut Vec<u8>) -> Result<(), Error> {
    if list.is_empty() {
        return Err(Error::EmptyAddressRequest);
    }
    for item in list {
        if item.request_id == 0 {
            return Err(Error::RequestIdZero);
        }
        varint::encode(item.request_id, out)?;
        encode_prefix(item.prefix, out);
    }
    Ok(())
}

pub(crate) fn decode_requested(buf: &[u8]) -> Result<Vec<RequestedAddress>, Error> {
    let mut reader = Reader::new(buf);
    let mut list = Vec::new();
    while !reader.is_empty() {
        let request_id = reader.varint()?;
        if request_id == 0 {
            return Err(Error::RequestIdZero);
        }
        let prefix = decode_prefix(&mut reader)?;
        list.push(RequestedAddress { request_id, prefix });
    }
    if list.is_empty() {
        return Err(Error::EmptyAddressRequest);
    }
    Ok(list)
}

pub(crate) fn encode_routes(list: &[RouteRange], out: &mut Vec<u8>) -> Result<(), Error> {
    validate_route_list(list)?;
    for route in list {
        encode_route(*route, out);
    }
    Ok(())
}

pub(crate) fn decode_routes(buf: &[u8]) -> Result<Vec<RouteRange>, Error> {
    let mut reader = Reader::new(buf);
    let mut list = Vec::new();
    while !reader.is_empty() {
        list.push(decode_route(&mut reader)?);
    }
    validate_route_list(&list)?;
    Ok(list)
}

/// 代入応答の「拒否」印か
///
/// 全 0 アドレスかつ最大プレフィックス長は、要求したアドレスを代入しなかった
/// ことを示す (RFC 9484 Section 4.7.2)。使える送信元には入れない。
pub fn is_assignment_rejection(prefix: IpPrefix) -> bool {
    match prefix.address {
        IpAddr::V4(addr) => prefix.prefix_length == 32 && addr.is_unspecified(),
        IpAddr::V6(addr) => prefix.prefix_length == 128 && addr.is_unspecified(),
    }
}

fn encode_prefix(prefix: IpPrefix, out: &mut Vec<u8>) {
    match prefix.address {
        IpAddr::V4(addr) => {
            out.push(4);
            out.extend_from_slice(&addr.octets());
        }
        IpAddr::V6(addr) => {
            out.push(6);
            out.extend_from_slice(&addr.octets());
        }
    }
    out.push(prefix.prefix_length);
}

fn decode_prefix(reader: &mut Reader<'_>) -> Result<IpPrefix, Error> {
    let version = reader.u8()?;
    let address = match version {
        4 => IpAddr::V4(Ipv4Addr::from(read_array(reader)?)),
        6 => IpAddr::V6(Ipv6Addr::from(read_array::<16>(reader)?)),
        _ => return Err(Error::InvalidIpVersion),
    };
    let prefix_length = reader.u8()?;
    IpPrefix::new(address, prefix_length)
}

fn encode_route(route: RouteRange, out: &mut Vec<u8>) {
    match (route.start, route.end) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            out.push(4);
            out.extend_from_slice(&start.octets());
            out.extend_from_slice(&end.octets());
        }
        (IpAddr::V6(start), IpAddr::V6(end)) => {
            out.push(6);
            out.extend_from_slice(&start.octets());
            out.extend_from_slice(&end.octets());
        }
        _ => {
            // `RouteRange::new` がファミリの一致を保証している。
        }
    }
    out.push(route.protocol);
}

fn decode_route(reader: &mut Reader<'_>) -> Result<RouteRange, Error> {
    let version = reader.u8()?;
    let (start, end) = match version {
        4 => {
            let start = Ipv4Addr::from(read_array(reader)?);
            let end = Ipv4Addr::from(read_array(reader)?);
            (IpAddr::V4(start), IpAddr::V4(end))
        }
        6 => {
            let start = Ipv6Addr::from(read_array::<16>(reader)?);
            let end = Ipv6Addr::from(read_array::<16>(reader)?);
            (IpAddr::V6(start), IpAddr::V6(end))
        }
        _ => return Err(Error::InvalidIpVersion),
    };
    let protocol = reader.u8()?;
    RouteRange::new(start, end, protocol)
}

/// 隣接する範囲の順序と、protocol 0 の重なりを検査する
///
/// RFC 9484 Section 4.7.3。順序違反は受信側がストリームを破棄する MUST。
/// protocol 0 との重なり検出は OPTIONAL だが、検出したときは破棄する MUST。
pub(crate) fn validate_route_list(list: &[RouteRange]) -> Result<(), Error> {
    for pair in list.windows(2) {
        let before = pair[0];
        let after = pair[1];
        let before_version = version_of(before.start);
        let after_version = version_of(after.start);
        if before_version > after_version {
            return Err(Error::RouteUnordered);
        }
        if before_version == after_version && before.protocol > after.protocol {
            return Err(Error::RouteUnordered);
        }
        if before_version == after_version
            && before.protocol == after.protocol
            && to_bits(before.end) >= to_bits(after.start)
        {
            return Err(Error::RouteUnordered);
        }
    }
    for (index, route) in list.iter().enumerate() {
        if route.protocol != 0 {
            continue;
        }
        for other in list.iter().skip(index + 1) {
            if version_of(route.start) != version_of(other.start) {
                continue;
            }
            if ranges_overlap(*route, *other) {
                return Err(Error::RouteOverlap);
            }
        }
    }
    Ok(())
}

fn ranges_overlap(left: RouteRange, right: RouteRange) -> bool {
    to_bits(left.start) <= to_bits(right.end) && to_bits(right.start) <= to_bits(left.end)
}

fn parse_ipv4(packet: &[u8]) -> Result<ParsedIp, Error> {
    if packet.len() < 20 {
        return Err(Error::Malformed);
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return Err(Error::Malformed);
    }
    let total = u16::from_be_bytes([packet[2], packet[3]]);
    if usize::from(total) != packet.len() || usize::from(total) < ihl {
        return Err(Error::Malformed);
    }
    if internet_checksum(&packet[..ihl]) != 0 {
        return Err(Error::Malformed);
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Ok(ParsedIp {
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        protocol: packet[9],
        hop_limit: packet[8],
    })
}

fn parse_ipv6(packet: &[u8]) -> Result<ParsedIp, Error> {
    if packet.len() < 40 {
        return Err(Error::Malformed);
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]);
    if packet.len() != 40 + usize::from(payload_len) {
        return Err(Error::Malformed);
    }
    let src = Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[8..24])
            .expect("IPv6 送信元は 16 バイト (実装バグならパニック)"),
    );
    let dst = Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[24..40])
            .expect("IPv6 宛先は 16 バイト (実装バグならパニック)"),
    );
    let protocol = walk_ipv6_headers(packet, packet[6])?;
    Ok(ParsedIp {
        src: IpAddr::V6(src),
        dst: IpAddr::V6(dst),
        protocol,
        hop_limit: packet[7],
    })
}

/// 最初の非拡張ヘッダのプロトコル番号を返す
///
/// 拡張ヘッダは Hop-by-Hop (0)、Routing (43)、Fragment (44)、AH (51)、
/// Destination Options (60)。ESP (50) はここで止める。
fn walk_ipv6_headers(packet: &[u8], mut next: u8) -> Result<u8, Error> {
    let mut offset = 40usize;
    for _ in 0..16 {
        if !is_ipv6_extension(next) {
            return Ok(next);
        }
        if offset >= packet.len() {
            return Err(Error::Malformed);
        }
        let header_len = ipv6_extension_len(packet, offset, next)?;
        if packet.len() - offset < header_len {
            return Err(Error::Malformed);
        }
        next = packet[offset];
        offset += header_len;
    }
    Err(Error::Malformed)
}

fn is_ipv6_extension(protocol: u8) -> bool {
    matches!(protocol, 0 | 43 | 44 | 51 | 60)
}

fn ipv6_extension_len(packet: &[u8], offset: usize, protocol: u8) -> Result<usize, Error> {
    if protocol == 44 {
        return Ok(8);
    }
    if packet.len() - offset < 2 {
        return Err(Error::Malformed);
    }
    let length_field = usize::from(packet[offset + 1]);
    if protocol == 51 {
        // AH の Payload Len は 4 バイト単位で、先頭 8 バイトを除いた長さ。
        Ok((length_field + 2) * 4)
    } else {
        Ok((length_field + 1) * 8)
    }
}

fn encode_ipv4_icmp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    original: &[u8],
    kind: IcmpError,
    mtu: u32,
) -> Result<Vec<u8>, Error> {
    let (icmp_type, code) = ipv4_icmp_type(kind);
    let quoted = &original[..original.len().min(20 + 8).min(original.len())];
    let mut icmp = Vec::new();
    icmp.push(icmp_type);
    icmp.push(code);
    icmp.extend_from_slice(&[0, 0]);
    if kind == IcmpError::PacketTooBig {
        icmp.extend_from_slice(&0u16.to_be_bytes());
        let mtu16 = u16::try_from(mtu).unwrap_or(u16::MAX);
        icmp.extend_from_slice(&mtu16.to_be_bytes());
    } else {
        icmp.extend_from_slice(&[0, 0, 0, 0]);
    }
    icmp.extend_from_slice(quoted);
    let sum = internet_checksum(&icmp);
    icmp[2] = (sum >> 8) as u8;
    icmp[3] = sum as u8;
    encode_ipv4(src, dst, IPV4_ICMP, 64, &icmp)
}

fn encode_ipv6_icmp(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    original: &[u8],
    kind: IcmpError,
    mtu: u32,
) -> Result<Vec<u8>, Error> {
    let (icmp_type, code) = ipv6_icmp_type(kind);
    let quoted = &original[..original.len().min(128)];
    let mut icmp = Vec::new();
    icmp.push(icmp_type);
    icmp.push(code);
    icmp.extend_from_slice(&[0, 0]);
    if kind == IcmpError::PacketTooBig {
        icmp.extend_from_slice(&mtu.to_be_bytes());
    } else {
        icmp.extend_from_slice(&[0, 0, 0, 0]);
    }
    icmp.extend_from_slice(quoted);
    let sum = icmpv6_checksum(src, dst, &icmp);
    icmp[2] = (sum >> 8) as u8;
    icmp[3] = sum as u8;
    encode_ipv6(src, dst, IPV6_ICMP, 64, &icmp)
}

fn ipv4_icmp_type(kind: IcmpError) -> (u8, u8) {
    match kind {
        // Destination Unreachable, host unreachable。
        IcmpError::NoRoute => (3, 1),
        // Administratively prohibited。
        IcmpError::BadSource => (3, 10),
        // Fragmentation Needed。
        IcmpError::PacketTooBig => (3, 4),
        // Time Exceeded, TTL。
        IcmpError::HopLimitExceeded => (11, 0),
    }
}

fn ipv6_icmp_type(kind: IcmpError) -> (u8, u8) {
    match kind {
        // No route to destination (RFC 4443 Section 3.1)。
        IcmpError::NoRoute => (1, 0),
        // Source address failed ingress/egress policy (RFC 9484 Section 7.2.1)。
        IcmpError::BadSource => (1, 5),
        IcmpError::PacketTooBig => (2, 0),
        IcmpError::HopLimitExceeded => (3, 0),
    }
}

fn write_ipv4_checksum(header: &mut [u8]) {
    header[10] = 0;
    header[11] = 0;
    let ihl = usize::from(header[0] & 0x0f) * 4;
    let sum = internet_checksum(&header[..ihl]);
    header[10] = (sum >> 8) as u8;
    header[11] = sum as u8;
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut index = 0;
    while index + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[index], data[index + 1]]));
        index += 2;
    }
    if index < data.len() {
        sum += u32::from(data[index]) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, IPV6_ICMP]);
    pseudo.extend_from_slice(icmp);
    internet_checksum(&pseudo)
}

fn read_array<const N: usize>(reader: &mut Reader<'_>) -> Result<[u8; N], Error> {
    let bytes = reader.take(N)?;
    let mut array = [0u8; N];
    array.copy_from_slice(bytes);
    Ok(array)
}

fn address_bits(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn version_of(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 6,
    }
}

fn to_bits(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(addr) => u128::from(u32::from(addr)),
        IpAddr::V6(addr) => u128::from(addr),
    }
}

fn host_bits_clear(addr: IpAddr, prefix_length: u8) -> bool {
    let bits = address_bits(addr);
    let host = bits - prefix_length;
    if host == 0 {
        return true;
    }
    if host == 128 {
        return to_bits(addr) == 0;
    }
    let mask = (1u128 << host) - 1;
    to_bits(addr) & mask == 0
}
