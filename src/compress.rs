//! HTTP Datagram のテンプレート圧縮 (draft-ietf-masque-http-datagram-compression-02)
//!
//! 静的セグメントの抜き差しと、IPv4 Total Length / IPv6 Payload Length /
//! IPv4 ヘッダチェックサムの派生フィールドを実装する。
//! カプセル型はドラフトの暫定値であり、公開前に小さい値へ置き換わる。

use crate::error::Error;
use crate::reader::Reader;
use crate::varint;
use alloc::vec;
use alloc::vec::Vec;

/// TEMPLATE_ASSIGN
pub const TEMPLATE_ASSIGN: u64 = 0x3ee3_143f;
/// TEMPLATE_ACK
pub const TEMPLATE_ACK: u64 = 0x3ee3_1440;
/// TEMPLATE_CLOSE
pub const TEMPLATE_CLOSE: u64 = 0x3ee3_1441;
/// DERIVED_ASSIGN
pub const DERIVED_ASSIGN: u64 = 0x3ee3_1442;
/// DERIVED_ACK
pub const DERIVED_ACK: u64 = 0x3ee3_1443;
/// DERIVED_CLOSE
pub const DERIVED_CLOSE: u64 = 0x3ee3_1444;
/// CHECKSUM_ASSIGN
pub const CHECKSUM_ASSIGN: u64 = 0x3ee3_1445;
/// CHECKSUM_ACK
pub const CHECKSUM_ACK: u64 = 0x3ee3_1446;
/// CHECKSUM_CLOSE
pub const CHECKSUM_CLOSE: u64 = 0x3ee3_1447;

/// ipv4-total-length (Section 9.3)
pub const IPV4_TOTAL_LENGTH: u64 = 0;
/// ipv6-payload-length
pub const IPV6_PAYLOAD_LENGTH: u64 = 1;
/// ipv4-header-checksum
pub const IPV4_HEADER_CHECKSUM: u64 = 4;

/// 再構成後のパケット上の静的バイト列
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticSegment {
    /// 再構成後パケットの先頭からの位置
    pub offset: usize,
    /// 挿入するバイト
    pub payload: Vec<u8>,
}

/// テンプレート。可変部だけをデータグラムに載せる
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateAssign {
    /// この処理コンテキストの Context ID
    pub context_id: u64,
    /// 次のコンテキスト。終端なら IP パケットなどの Context ID
    pub next_context_id: u64,
    /// オフセット昇順で重ならない静的セグメント
    pub segments: Vec<StaticSegment>,
}

pub(crate) fn encode_template(template: &TemplateAssign, out: &mut Vec<u8>) -> Result<(), Error> {
    validate_segments(&template.segments)?;
    varint::encode(template.context_id, out)?;
    varint::encode(template.next_context_id, out)?;
    if template.segments.is_empty() {
        return Err(Error::Malformed);
    }
    for segment in &template.segments {
        varint::encode(
            u64::try_from(segment.offset).map_err(|_| Error::Malformed)?,
            out,
        )?;
        varint::encode(
            u64::try_from(segment.payload.len()).map_err(|_| Error::Malformed)?,
            out,
        )?;
        out.extend_from_slice(&segment.payload);
    }
    Ok(())
}

pub(crate) fn decode_template(buf: &[u8]) -> Result<TemplateAssign, Error> {
    let mut reader = Reader::new(buf);
    let context_id = reader.varint()?;
    let next_context_id = reader.varint()?;
    let mut segments = Vec::new();
    while !reader.is_empty() {
        let offset = usize::try_from(reader.varint()?).map_err(|_| Error::Malformed)?;
        let length = usize::try_from(reader.varint()?).map_err(|_| Error::Malformed)?;
        segments.push(StaticSegment {
            offset,
            payload: reader.take(length)?.to_vec(),
        });
    }
    validate_segments(&segments)?;
    Ok(TemplateAssign {
        context_id,
        next_context_id,
        segments,
    })
}

/// 派生フィールド。送信側は該当オクテットを載せず、受信側が計算して埋める
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedAssign {
    /// この処理コンテキストの Context ID
    pub context_id: u64,
    /// 次のコンテキスト
    pub next_context_id: u64,
    /// Derived Field Type。重複は不正
    pub fields: Vec<u64>,
}

pub(crate) fn encode_derived(derived: &DerivedAssign, out: &mut Vec<u8>) -> Result<(), Error> {
    if derived.fields.is_empty() || has_duplicate(&derived.fields) {
        return Err(Error::Malformed);
    }
    varint::encode(derived.context_id, out)?;
    varint::encode(derived.next_context_id, out)?;
    for field in &derived.fields {
        varint::encode(*field, out)?;
    }
    Ok(())
}

pub(crate) fn decode_derived(buf: &[u8]) -> Result<DerivedAssign, Error> {
    let mut reader = Reader::new(buf);
    let context_id = reader.varint()?;
    let next_context_id = reader.varint()?;
    let mut fields = Vec::new();
    while !reader.is_empty() {
        fields.push(reader.varint()?);
    }
    if fields.is_empty() || has_duplicate(&fields) {
        return Err(Error::Malformed);
    }
    Ok(DerivedAssign {
        context_id,
        next_context_id,
        fields,
    })
}

/// チェックサムオフロード。Start Offset 0 は不正 (Section 4.4.1.1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumAssign {
    /// この処理コンテキストの Context ID
    pub context_id: u64,
    /// 次のコンテキスト
    pub next_context_id: u64,
    /// 16 bit チェックサム欄の位置
    pub field_offset: usize,
    /// カバレッジ開始位置。0 は禁止
    pub start_offset: usize,
}

pub(crate) fn encode_checksum(checksum: &ChecksumAssign, out: &mut Vec<u8>) -> Result<(), Error> {
    if checksum.start_offset == 0 {
        return Err(Error::Malformed);
    }
    varint::encode(checksum.context_id, out)?;
    varint::encode(checksum.next_context_id, out)?;
    varint::encode(
        u64::try_from(checksum.field_offset).map_err(|_| Error::Malformed)?,
        out,
    )?;
    varint::encode(
        u64::try_from(checksum.start_offset).map_err(|_| Error::Malformed)?,
        out,
    )?;
    Ok(())
}

pub(crate) fn decode_checksum(buf: &[u8]) -> Result<ChecksumAssign, Error> {
    let mut reader = Reader::new(buf);
    let checksum = ChecksumAssign {
        context_id: reader.varint()?,
        next_context_id: reader.varint()?,
        field_offset: usize::try_from(reader.varint()?).map_err(|_| Error::Malformed)?,
        start_offset: usize::try_from(reader.varint()?).map_err(|_| Error::Malformed)?,
    };
    reader.finish_empty()?;
    if checksum.start_offset == 0 {
        return Err(Error::Malformed);
    }
    Ok(checksum)
}

pub(crate) fn encode_ack(context_id: u64, out: &mut Vec<u8>) -> Result<(), Error> {
    varint::encode(context_id, out)
}

pub(crate) fn decode_ack(buf: &[u8]) -> Result<u64, Error> {
    let mut reader = Reader::new(buf);
    let context_id = reader.varint()?;
    reader.finish_empty()?;
    Ok(context_id)
}

/// 完全なパケットから、静的セグメントを除いた可変部を作る
pub fn compress_template(packet: &[u8], segments: &[StaticSegment]) -> Result<Vec<u8>, Error> {
    validate_segments(segments)?;
    let mut out = Vec::new();
    let mut cursor = 0usize;
    for segment in segments {
        if segment.offset > packet.len() || segment.offset + segment.payload.len() > packet.len() {
            return Err(Error::Malformed);
        }
        if packet[segment.offset..segment.offset + segment.payload.len()] != segment.payload[..] {
            return Err(Error::Malformed);
        }
        out.extend_from_slice(&packet[cursor..segment.offset]);
        cursor = segment.offset + segment.payload.len();
    }
    out.extend_from_slice(&packet[cursor..]);
    Ok(out)
}

/// 可変部に静的セグメントを戻す
pub fn expand_template(payload: &[u8], segments: &[StaticSegment]) -> Result<Vec<u8>, Error> {
    validate_segments(segments)?;
    let mut out = Vec::new();
    let mut payload_pos = 0usize;
    let mut cursor = 0usize;
    for segment in segments {
        if segment.offset < cursor {
            return Err(Error::Malformed);
        }
        let gap = segment.offset - cursor;
        let end = payload_pos.checked_add(gap).ok_or(Error::Malformed)?;
        if end > payload.len() {
            return Err(Error::Malformed);
        }
        out.extend_from_slice(&payload[payload_pos..end]);
        payload_pos = end;
        out.extend_from_slice(&segment.payload);
        cursor = segment.offset + segment.payload.len();
    }
    out.extend_from_slice(&payload[payload_pos..]);
    Ok(out)
}

/// 派生フィールドを除いた送信ペイロードを作る
///
/// CONNECT-IP では IP ヘッダがオフセット 0 にあるものとして扱う (Section 6.2.1)。
pub fn strip_derived_fields(packet: &[u8], fields: &[u64]) -> Result<Vec<u8>, Error> {
    let mut removed = Vec::new();
    for field in fields {
        removed.push(derived_range(*field, packet)?);
    }
    removed.sort_by_key(|range| range.0);
    let mut out = Vec::new();
    let mut cursor = 0usize;
    for (offset, len) in removed {
        if offset < cursor {
            return Err(Error::Malformed);
        }
        out.extend_from_slice(&packet[cursor..offset]);
        cursor = offset + len;
    }
    out.extend_from_slice(&packet[cursor..]);
    Ok(out)
}

/// 除かれていた派生フィールドを計算して戻す
pub fn insert_derived_fields(payload: &[u8], fields: &[u64]) -> Result<Vec<u8>, Error> {
    let mut ranges = Vec::new();
    for field in fields {
        ranges.push((*field, derived_span(*field)?));
    }
    let removed: usize = ranges.iter().map(|(_, span)| span_len(*span)).sum();
    let total = payload.len().checked_add(removed).ok_or(Error::Malformed)?;
    let mut packet = vec![0u8; total];
    let mut payload_pos = 0usize;
    let mut cursor = 0usize;
    let mut ordered = ranges;
    ordered.sort_by_key(|(_, span)| span_offset(*span));
    for (_, span) in &ordered {
        let offset = span_offset(*span);
        let len = span_len(*span);
        if offset < cursor || offset > total {
            return Err(Error::Malformed);
        }
        let gap = offset - cursor;
        if payload_pos + gap > payload.len() {
            return Err(Error::Malformed);
        }
        packet[cursor..offset].copy_from_slice(&payload[payload_pos..payload_pos + gap]);
        payload_pos += gap;
        cursor = offset + len;
    }
    if payload_pos > payload.len() || cursor > total {
        return Err(Error::Malformed);
    }
    packet[cursor..cursor + (payload.len() - payload_pos)].copy_from_slice(&payload[payload_pos..]);
    for field in fields {
        write_derived(*field, &mut packet)?;
    }
    Ok(packet)
}

fn derived_range(field: u64, packet: &[u8]) -> Result<(usize, usize), Error> {
    let (offset, len) = derived_span(field)?;
    if offset + len > packet.len() {
        return Err(Error::Malformed);
    }
    Ok((offset, len))
}

fn derived_span(field: u64) -> Result<(usize, usize), Error> {
    match field {
        IPV4_TOTAL_LENGTH => Ok((2, 2)),
        IPV6_PAYLOAD_LENGTH => Ok((4, 2)),
        IPV4_HEADER_CHECKSUM => Ok((10, 2)),
        _ => Err(Error::Malformed),
    }
}

fn span_offset(span: (usize, usize)) -> usize {
    span.0
}

fn span_len(span: (usize, usize)) -> usize {
    span.1
}

fn write_derived(field: u64, packet: &mut [u8]) -> Result<(), Error> {
    match field {
        IPV4_TOTAL_LENGTH => {
            let total = u16::try_from(packet.len()).map_err(|_| Error::Malformed)?;
            packet[2..4].copy_from_slice(&total.to_be_bytes());
        }
        IPV6_PAYLOAD_LENGTH => {
            if packet.len() < 40 {
                return Err(Error::Malformed);
            }
            let payload = u16::try_from(packet.len() - 40).map_err(|_| Error::Malformed)?;
            if payload == 0 {
                return Err(Error::Malformed);
            }
            packet[4..6].copy_from_slice(&payload.to_be_bytes());
        }
        IPV4_HEADER_CHECKSUM => {
            if packet.len() < 20 {
                return Err(Error::Malformed);
            }
            let ihl = usize::from(packet[0] & 0x0f) * 4;
            if ihl < 20 || packet.len() < ihl {
                return Err(Error::Malformed);
            }
            packet[10] = 0;
            packet[11] = 0;
            let sum = internet_checksum(&packet[..ihl]);
            packet[10] = (sum >> 8) as u8;
            packet[11] = sum as u8;
        }
        _ => return Err(Error::Malformed),
    }
    Ok(())
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut index = 0;
    while index + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[index], data[index + 1]]));
        index += 2;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn validate_segments(segments: &[StaticSegment]) -> Result<(), Error> {
    if segments.is_empty() {
        return Err(Error::Malformed);
    }
    let mut previous_end = None;
    for segment in segments {
        if segment.payload.is_empty() {
            return Err(Error::Malformed);
        }
        if let Some(end) = previous_end {
            // 連続する静的セグメントの間には 1 バイト以上の可変部がある (Section 4.2.1.1)。
            if segment.offset <= end {
                return Err(Error::Malformed);
            }
        }
        previous_end = Some(segment.offset + segment.payload.len() - 1);
    }
    Ok(())
}

fn has_duplicate(values: &[u64]) -> bool {
    for index in 0..values.len() {
        for other in (index + 1)..values.len() {
            if values[index] == values[other] {
                return true;
            }
        }
    }
    false
}
