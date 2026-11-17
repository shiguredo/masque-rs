//! HTTP Datagram ペイロード
//!
//! Quarter Stream ID はここには含まれない。それは HTTP/3 の仕事である
//! (RFC 9297 Section 2.1)。ここが扱うのはその次の Context ID とペイロード。
//! CONNECT-IP も CONNECT-UDP も同じ先頭フィールドを使う
//! (RFC 9484 Section 6、RFC 9298 Section 5)。

use crate::error::Error;
use crate::varint::{self, MAX};
use alloc::vec::Vec;

/// Context ID と、その意味が拡張ごとに決まるペイロード
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpDatagram {
    /// 0 は IP パケットまたは UDP ペイロード。それ以外は登録が要る
    pub context_id: u64,
    /// Context ID のうしろのバイト列。空でもよい
    pub payload: Vec<u8>,
}

impl HttpDatagram {
    /// HTTP Datagram ペイロードをエンコードする
    ///
    /// `context_id` が 2^62-1 を超えるときは [`Error::VarintOutOfRange`]。
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.context_id > MAX {
            return Err(Error::VarintOutOfRange);
        }
        varint::encode(self.context_id, out)?;
        out.extend_from_slice(&self.payload);
        Ok(())
    }

    /// 1 個分の HTTP Datagram ペイロードをデコードする
    ///
    /// 入力はカプセル値、または Quarter Stream ID を取り除いた残り全体。
    /// Context ID が途中で切れているときは [`Error::Malformed`]。
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let (context_id, len) = varint::decode(buf).ok_or(Error::Malformed)?;
        Ok(Self {
            context_id,
            payload: buf[len..].to_vec(),
        })
    }
}
