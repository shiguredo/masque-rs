//! QUIC 可変長整数 (RFC 9000 Section 16)
//!
//! MASQUE のカプセル長、Context ID、Request ID はすべてこの形式である
//! (RFC 9297 Section 3.2、RFC 9484 Section 2)。
//! 値は 0 から 2^62-1 まで。非最小エンコーディングもデコードする。
//! エンコードは最小バイト数で書く。
//!
//! この符号化は RFC 9000 の規定であり、MOQT の vi64 とはバイト長の段階が違う。

use crate::error::Error;
use alloc::vec::Vec;

/// 可変長整数の最大値 (2^62 - 1)
pub const MAX: u64 = (1 << 62) - 1;

/// `value` を最小バイト数で `out` に追記する
///
/// `value` が [`MAX`] を超えるときは [`Error::VarintOutOfRange`] を返す。
pub fn encode(value: u64, out: &mut Vec<u8>) -> Result<(), Error> {
    if value > MAX {
        return Err(Error::VarintOutOfRange);
    }
    if value <= 63 {
        out.push(value as u8);
    } else if value <= 16_383 {
        out.push(0x40 | (value >> 8) as u8);
        out.push(value as u8);
    } else if value <= 1_073_741_823 {
        out.push(0x80 | (value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    } else {
        out.push(0xc0 | (value >> 56) as u8);
        out.push((value >> 48) as u8);
        out.push((value >> 40) as u8);
        out.push((value >> 32) as u8);
        out.push((value >> 24) as u8);
        out.push((value >> 16) as u8);
        out.push((value >> 8) as u8);
        out.push(value as u8);
    }
    Ok(())
}

/// `buf` の先頭から可変長整数を読む
///
/// バイトが足りないときは `None`。足りていれば `(値, 消費バイト数)`。
/// 上位 2 bit が長さを表すため、値が 2^62-1 を超えることはない。
pub fn decode(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in buf.iter().take(len).skip(1) {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}
