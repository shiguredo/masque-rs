//! ECN と DSCP を Context ID で表す (draft-ietf-masque-connect-udp-ecn-dscp-02)
//!
//! カプセル型はドラフトが TBA のままなので、圧縮カプセルと重ならない暫定値を使う。
//! IANA が 0x00-0x3f の値を割り当てたら差し替える。ドラフトが改訂されると変わる。

use crate::error::Error;
use crate::reader::Reader;
use crate::varint;
use alloc::vec::Vec;

/// 暫定の ECN_DSCP_CONTEXT_ASSIGN
pub const ECN_DSCP_CONTEXT_ASSIGN: u64 = 0x3ee3_1451;
/// 暫定の ECN_DSCP_CONTEXT_ACK
pub const ECN_DSCP_CONTEXT_ACK: u64 = 0x3ee3_1452;
/// 暫定の ECN_DSCP_CONTEXT_CLOSE
pub const ECN_DSCP_CONTEXT_CLOSE: u64 = 0x3ee3_1453;

/// 1 つの DSCP に対する 4 つの Context ID (Section 4.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcnDscpAssignment {
    /// DSCP。0 から 63
    pub dscp: u8,
    /// Not-ECT
    pub not_ect: u64,
    /// ECT(1)
    pub ect_1: u64,
    /// ECT(0)
    pub ect_0: u64,
    /// CE
    pub ce: u64,
}

impl EcnDscpAssignment {
    /// 4 つの Context ID がすべて異なり、DSCP が 6 bit に収まることを確認する
    pub fn new(dscp: u8, not_ect: u64, ect_1: u64, ect_0: u64, ce: u64) -> Result<Self, Error> {
        if dscp > 63 {
            return Err(Error::Malformed);
        }
        let ids = [not_ect, ect_1, ect_0, ce];
        for index in 0..ids.len() {
            for other in (index + 1)..ids.len() {
                if ids[index] == ids[other] {
                    return Err(Error::DuplicateContext);
                }
            }
        }
        Ok(Self {
            dscp,
            not_ect,
            ect_1,
            ect_0,
            ce,
        })
    }

    /// ECN コードポイント 0 Not-ECT、1 ECT(1)、2 ECT(0)、3 CE の Context ID
    pub fn context_id(self, ecn: u8) -> Option<u64> {
        match ecn {
            0 => Some(self.not_ect),
            1 => Some(self.ect_1),
            2 => Some(self.ect_0),
            3 => Some(self.ce),
            _ => None,
        }
    }
}

pub(crate) fn encode_assignments(
    list: &[EcnDscpAssignment],
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    for item in list {
        // DSCP は上位 6 bit、下位 2 bit は予約で 0 (Section 4.1)。
        out.push(item.dscp << 2);
        varint::encode(item.not_ect, out)?;
        varint::encode(item.ect_1, out)?;
        varint::encode(item.ect_0, out)?;
        varint::encode(item.ce, out)?;
    }
    Ok(())
}

pub(crate) fn decode_assignments(buf: &[u8]) -> Result<Vec<EcnDscpAssignment>, Error> {
    let mut reader = Reader::new(buf);
    let mut list = Vec::new();
    let mut seen = Vec::new();
    while !reader.is_empty() {
        let first = reader.u8()?;
        if first & 0b11 != 0 {
            return Err(Error::Malformed);
        }
        let dscp = first >> 2;
        let assignment = EcnDscpAssignment::new(
            dscp,
            reader.varint()?,
            reader.varint()?,
            reader.varint()?,
            reader.varint()?,
        )?;
        for id in [
            assignment.not_ect,
            assignment.ect_1,
            assignment.ect_0,
            assignment.ce,
        ] {
            if seen.contains(&id) {
                return Err(Error::DuplicateContext);
            }
            seen.push(id);
        }
        list.push(assignment);
    }
    Ok(list)
}

/// `ECN-DSCP-Context-ID` ヘッダを読む
///
/// `(46,8,10,12,14), (0,0,2,4,6)` の形。空なら拡張の支持だけを表す (Section 4.2)。
pub fn parse_ecn_dscp_header(value: &str) -> Result<Vec<EcnDscpAssignment>, Error> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut list = Vec::new();
    for item in split_inner_lists(value)? {
        let numbers = parse_integers(item)?;
        if numbers.len() != 5 {
            return Err(Error::Malformed);
        }
        let dscp = u8::try_from(numbers[0]).map_err(|_| Error::Malformed)?;
        list.push(EcnDscpAssignment::new(
            dscp, numbers[1], numbers[2], numbers[3], numbers[4],
        )?);
    }
    Ok(list)
}

fn split_inner_lists(value: &str) -> Result<Vec<&str>, Error> {
    let mut lists = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        let open = rest.strip_prefix('(').ok_or(Error::Malformed)?;
        let end = open.find(')').ok_or(Error::Malformed)?;
        lists.push(&open[..end]);
        rest = open[end + 1..].trim_start();
        if let Some(stripped) = rest.strip_prefix(',') {
            rest = stripped;
        } else if !rest.is_empty() {
            return Err(Error::Malformed);
        }
    }
    Ok(lists)
}

fn parse_integers(value: &str) -> Result<Vec<u64>, Error> {
    let mut numbers = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::Malformed);
        }
        numbers.push(part.parse().map_err(|_| Error::Malformed)?);
    }
    Ok(numbers)
}
