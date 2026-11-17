//! CONNECT-UDP Bind (draft-ietf-masque-connect-udp-listen-16)
//!
//! Context ID の登録と、圧縮しない UDP データグラムの形を扱う。
//! ドラフト段階であり、カプセル型やフィールドは変わる可能性がある。

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::capsule::Capsule;
use crate::error::Error;
use crate::reader::Reader;
use crate::varint;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// COMPRESSION_ASSIGN (draft-ietf-masque-connect-udp-listen-16 Section 3.1)
pub const COMPRESSION_ASSIGN: u64 = 0x11;
/// COMPRESSION_ACK (Section 3.2)
pub const COMPRESSION_ACK: u64 = 0x12;
/// COMPRESSION_CLOSE (Section 3.3)
pub const COMPRESSION_CLOSE: u64 = 0x13;

/// 登録する宛先。IP Version 0 は圧縮しない Context ID
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressionTarget {
    /// データグラムごとに宛先を載せる
    Uncompressed,
    /// 登録時に宛先を一度だけ交換する
    Compressed {
        /// 宛先アドレス
        address: IpAddr,
        /// 宛先 UDP ポート
        port: u16,
    },
}

/// COMPRESSION_ASSIGN の中身
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionAssign {
    /// 0 以外。クライアントは偶数、プロキシは奇数
    pub context_id: u64,
    /// この Context ID の宛先
    pub target: CompressionTarget,
}

pub(crate) fn encode_assign(assign: &CompressionAssign, out: &mut Vec<u8>) -> Result<(), Error> {
    if assign.context_id == 0 {
        return Err(Error::ContextIdZero);
    }
    varint::encode(assign.context_id, out)?;
    match &assign.target {
        CompressionTarget::Uncompressed => out.push(0),
        CompressionTarget::Compressed { address, port } => {
            match address {
                IpAddr::V4(addr) => {
                    out.push(4);
                    out.extend_from_slice(&addr.octets());
                }
                IpAddr::V6(addr) => {
                    out.push(6);
                    out.extend_from_slice(&addr.octets());
                }
            }
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

pub(crate) fn decode_assign(buf: &[u8]) -> Result<CompressionAssign, Error> {
    let mut reader = Reader::new(buf);
    let context_id = reader.varint()?;
    if context_id == 0 {
        return Err(Error::ContextIdZero);
    }
    let version = reader.u8()?;
    let target = match version {
        0 => {
            if !reader.is_empty() {
                return Err(Error::Malformed);
            }
            CompressionTarget::Uncompressed
        }
        4 => {
            let octets: [u8; 4] = read_array(&mut reader)?;
            let port = reader.u16()?;
            reader.finish_empty()?;
            CompressionTarget::Compressed {
                address: IpAddr::V4(Ipv4Addr::from(octets)),
                port,
            }
        }
        6 => {
            let octets: [u8; 16] = read_array(&mut reader)?;
            let port = reader.u16()?;
            reader.finish_empty()?;
            CompressionTarget::Compressed {
                address: IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            }
        }
        _ => return Err(Error::InvalidIpVersion),
    };
    Ok(CompressionAssign { context_id, target })
}

pub(crate) fn encode_context_id(context_id: u64, out: &mut Vec<u8>) -> Result<(), Error> {
    if context_id == 0 {
        return Err(Error::ContextIdZero);
    }
    varint::encode(context_id, out)
}

pub(crate) fn decode_context_id(buf: &[u8]) -> Result<u64, Error> {
    let mut reader = Reader::new(buf);
    let context_id = reader.varint()?;
    reader.finish_empty()?;
    if context_id == 0 {
        return Err(Error::ContextIdZero);
    }
    Ok(context_id)
}

/// 圧縮しない UDP データグラムの宛先とペイロード
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UncompressedUdp {
    /// クライアントから見ると送信先、プロキシから見ると送信元
    pub address: IpAddr,
    /// UDP ポート
    pub port: u16,
    /// UDP ペイロード
    pub payload: Vec<u8>,
}

pub(crate) fn encode_uncompressed(
    packet: &UncompressedUdp,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    match packet.address {
        IpAddr::V4(addr) => {
            out.push(4);
            out.extend_from_slice(&addr.octets());
        }
        IpAddr::V6(addr) => {
            out.push(6);
            out.extend_from_slice(&addr.octets());
        }
    }
    out.extend_from_slice(&packet.port.to_be_bytes());
    out.extend_from_slice(&packet.payload);
    Ok(())
}

pub(crate) fn decode_uncompressed(buf: &[u8]) -> Result<UncompressedUdp, Error> {
    let mut reader = Reader::new(buf);
    let version = reader.u8()?;
    let address = match version {
        4 => IpAddr::V4(Ipv4Addr::from(read_array::<4>(&mut reader)?)),
        6 => IpAddr::V6(Ipv6Addr::from(read_array::<16>(&mut reader)?)),
        _ => return Err(Error::InvalidIpVersion),
    };
    let port = reader.u16()?;
    let payload = reader.rest().to_vec();
    Ok(UncompressedUdp {
        address,
        port,
        payload,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Registration {
    context_id: u64,
    target: CompressionTarget,
    opened_by_local: bool,
    closed: bool,
}

/// Bind の登録状態
#[derive(Debug, Clone)]
pub struct UdpBind {
    enabled: bool,
    /// target が `*` のとき Context ID 0 は使えない
    wildcard: bool,
    local_is_client: bool,
    entries: Vec<Registration>,
    uncompressed_closed: bool,
}

impl UdpBind {
    pub(crate) fn inactive() -> Self {
        Self {
            enabled: false,
            wildcard: false,
            local_is_client: true,
            entries: Vec::new(),
            uncompressed_closed: false,
        }
    }

    /// Bind を有効にする
    ///
    /// `wildcard` は URI の target_host と target_port が `*` のとき真。
    /// そのとき Context ID 0 の受信はストリームを止める (Section 3)。
    pub fn enable(&mut self, local_is_client: bool, wildcard: bool) {
        self.enabled = true;
        self.local_is_client = local_is_client;
        self.wildcard = wildcard;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn wildcard(&self) -> bool {
        self.wildcard
    }

    /// 登録を送り、状態に記録する
    pub fn queue_assign(&mut self, assign: CompressionAssign) -> Result<Capsule, Error> {
        self.ensure_enabled()?;
        validate_local_assign(self, &assign)?;
        self.entries.push(Registration {
            context_id: assign.context_id,
            target: assign.target.clone(),
            opened_by_local: true,
            closed: false,
        });
        Ok(Capsule::CompressionAssign(assign))
    }

    /// 受信した COMPRESSION_ASSIGN を受理または拒否する
    ///
    /// 受理なら ACK、同じ宛先をプロキシも開いていたらプロキシ側を CLOSE する。
    pub fn receive_assign(&mut self, assign: CompressionAssign) -> Result<Vec<Capsule>, Error> {
        self.ensure_enabled()?;
        if assign.context_id == 0
            || self
                .entries
                .iter()
                .any(|entry| entry.context_id == assign.context_id)
        {
            return Err(Error::DuplicateContext);
        }
        if !parity_ok(!self.local_is_client, assign.context_id) {
            return Err(Error::BadContextParity);
        }
        if matches!(assign.target, CompressionTarget::Uncompressed) {
            if self.local_is_client {
                return Err(Error::UncompressedForbidden);
            }
            if self.entries.iter().any(|entry| {
                !entry.closed && matches!(entry.target, CompressionTarget::Uncompressed)
            }) {
                return Err(Error::DuplicateContext);
            }
        }
        if let CompressionTarget::Compressed { address, port } = assign.target.clone()
            && let Some(existing) = self
                .entries
                .iter()
                .find(|entry| !entry.closed && same_target(&entry.target, &address, port))
        {
            if !existing.opened_by_local {
                return Err(Error::DuplicateContext);
            }
            // 両側が同じ宛先を開いた。プロキシが開いた方を閉じる。
            return Ok(self.close_proxy_side(assign, address, port));
        }
        if !self.local_is_client
            && self.uncompressed_closed
            && matches!(assign.target, CompressionTarget::Compressed { .. })
        {
            return Err(Error::ClosedContext);
        }
        let context_id = assign.context_id;
        self.entries.push(Registration {
            context_id,
            target: assign.target,
            opened_by_local: false,
            closed: false,
        });
        Ok(vec![Capsule::CompressionAck(context_id)])
    }

    pub fn receive_ack(&mut self, context_id: u64) -> Result<(), Error> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.context_id == context_id && entry.opened_by_local)
            .ok_or(Error::Malformed)?;
        if entry.closed {
            return Err(Error::ClosedContext);
        }
        Ok(())
    }

    pub fn close(&mut self, context_id: u64) -> Result<Capsule, Error> {
        self.mark_closed(context_id)?;
        Ok(Capsule::CompressionClose(context_id))
    }

    pub fn receive_close(&mut self, context_id: u64) -> Result<(), Error> {
        self.mark_closed(context_id)
    }

    pub fn lookup(&self, context_id: u64) -> Option<&CompressionTarget> {
        self.entries.iter().find_map(|entry| {
            if entry.context_id == context_id && !entry.closed {
                Some(&entry.target)
            } else {
                None
            }
        })
    }

    pub fn is_closed(&self, context_id: u64) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.context_id == context_id && entry.closed)
    }

    fn mark_closed(&mut self, context_id: u64) -> Result<(), Error> {
        if context_id == 0 {
            return Err(Error::ContextIdZero);
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.context_id == context_id)
            .ok_or(Error::Malformed)?;
        if matches!(entry.target, CompressionTarget::Uncompressed) {
            self.uncompressed_closed = true;
        }
        entry.closed = true;
        Ok(())
    }

    fn ensure_enabled(&self) -> Result<(), Error> {
        if self.enabled {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }

    fn close_proxy_side(
        &mut self,
        assign: CompressionAssign,
        address: IpAddr,
        port: u16,
    ) -> Vec<Capsule> {
        let proxy_is_local = !self.local_is_client;
        let mut capsules = Vec::new();
        if let Some(existing) = self.entries.iter_mut().find(|entry| {
            entry.opened_by_local == proxy_is_local
                && !entry.closed
                && same_target(&entry.target, &address, port)
        }) {
            existing.closed = true;
            capsules.push(Capsule::CompressionClose(existing.context_id));
        }
        let context_id = assign.context_id;
        self.entries.push(Registration {
            context_id,
            target: assign.target,
            opened_by_local: false,
            closed: false,
        });
        capsules.push(Capsule::CompressionAck(context_id));
        capsules
    }
}

fn validate_local_assign(bind: &UdpBind, assign: &CompressionAssign) -> Result<(), Error> {
    if bind
        .entries
        .iter()
        .any(|entry| entry.context_id == assign.context_id)
    {
        return Err(Error::DuplicateContext);
    }
    if !parity_ok(bind.local_is_client, assign.context_id) {
        return Err(Error::BadContextParity);
    }
    match &assign.target {
        CompressionTarget::Uncompressed => {
            if !bind.local_is_client {
                return Err(Error::UncompressedForbidden);
            }
            if bind.entries.iter().any(|entry| {
                !entry.closed && matches!(entry.target, CompressionTarget::Uncompressed)
            }) {
                return Err(Error::DuplicateContext);
            }
        }
        CompressionTarget::Compressed { address, port } => {
            if !bind.local_is_client && bind.uncompressed_closed {
                return Err(Error::ClosedContext);
            }
            if bind
                .entries
                .iter()
                .any(|entry| !entry.closed && same_target(&entry.target, address, *port))
            {
                return Err(Error::DuplicateContext);
            }
        }
    }
    Ok(())
}

fn parity_ok(is_client: bool, context_id: u64) -> bool {
    let odd = context_id % 2 == 1;
    if is_client { !odd } else { odd }
}

fn same_target(target: &CompressionTarget, address: &IpAddr, port: u16) -> bool {
    matches!(target, CompressionTarget::Compressed { address: found, port: found_port }
        if found == address && *found_port == port)
}

fn read_array<const N: usize>(reader: &mut Reader<'_>) -> Result<[u8; N], Error> {
    let bytes = reader.take(N)?;
    let mut array = [0u8; N];
    array.copy_from_slice(bytes);
    Ok(array)
}

/// `Proxy-Public-Address` を組み立てる
///
/// 各要素は `"192.0.2.1:443"` または `"[2001:db8::1]:443"` という文字列である
/// (draft-ietf-masque-connect-udp-listen-16 Section 7)。
pub fn format_public_addresses(addresses: &[(IpAddr, u16)]) -> String {
    let mut out = String::new();
    for (index, (addr, port)) in addresses.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push('"');
        match addr {
            IpAddr::V4(addr) => {
                out.push_str(&format_v4(*addr));
                out.push(':');
                push_port(&mut out, *port);
            }
            IpAddr::V6(addr) => {
                out.push('[');
                out.push_str(&format_v6(*addr));
                out.push(']');
                out.push(':');
                push_port(&mut out, *port);
            }
        }
        out.push('"');
    }
    out
}

fn format_v4(addr: Ipv4Addr) -> String {
    let o = addr.octets();
    let mut out = String::new();
    push_u8(&mut out, o[0]);
    out.push('.');
    push_u8(&mut out, o[1]);
    out.push('.');
    push_u8(&mut out, o[2]);
    out.push('.');
    push_u8(&mut out, o[3]);
    out
}

fn format_v6(addr: Ipv6Addr) -> String {
    let segments = addr.segments();
    let mut out = String::new();
    for (index, segment) in segments.iter().enumerate() {
        if index > 0 {
            out.push(':');
        }
        push_hex(&mut out, *segment);
    }
    out
}

fn push_u8(out: &mut String, value: u8) {
    if value >= 100 {
        out.push(char::from(b'0' + value / 100));
    }
    if value >= 10 {
        out.push(char::from(b'0' + (value / 10) % 10));
    }
    out.push(char::from(b'0' + value % 10));
}

fn push_port(out: &mut String, port: u16) {
    let mut buf = [0u8; 5];
    let mut value = port;
    let mut index = 5;
    loop {
        index -= 1;
        buf[index] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for byte in &buf[index..] {
        out.push(char::from(*byte));
    }
}

fn push_hex(out: &mut String, value: u16) {
    let digits = b"0123456789abcdef";
    let mut started = false;
    for shift in [12, 8, 4, 0] {
        let nibble = ((value >> shift) & 0xf) as usize;
        if nibble != 0 || started || shift == 0 {
            out.push(char::from(digits[nibble]));
            started = true;
        }
    }
}
