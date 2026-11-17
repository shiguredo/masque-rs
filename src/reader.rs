//! カプセル値の読み取りカーソル
//!
//! ここに渡すスライスは、カプセル長がすでに確定した値である。
//! 途中で尽きるのはストリームの未着ではなく、長さと中身の不一致なので
//! [`Error::Malformed`] にする (RFC 9297 Section 3.3)。

use crate::error::Error;
use crate::varint;

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        let byte = self.take(1)?;
        Ok(byte[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn varint(&mut self) -> Result<u64, Error> {
        let rest = &self.buf[self.pos..];
        let (value, len) = varint::decode(rest).ok_or(Error::Malformed)?;
        self.pos += len;
        Ok(value)
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(len).ok_or(Error::Malformed)?;
        if end > self.buf.len() {
            return Err(Error::Malformed);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub(crate) fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// 余りバイトは不正なカプセルである (RFC 9297 Section 3.3)
    pub(crate) fn finish_empty(self) -> Result<(), Error> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }
}
