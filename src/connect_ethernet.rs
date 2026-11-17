//! CONNECT-ETHERNET (draft-ietf-masque-connect-ethernet-18)
//!
//! Context ID 0 のペイロードは、宛先アドレスから FCS の直前までの Ethernet フレーム。
//! FCS は運ばない。ブリッジのループ防止は呼び出し側の仕事である (Section 7)。
//! ドラフト段階であり、将来変わる可能性がある。

use crate::datagram::HttpDatagram;
use crate::error::Error;
use alloc::vec::Vec;

/// 宛先 MAC、送信元 MAC、EtherType を含む最短長
const MIN_FRAME_LEN: usize = 14;

/// Ethernet トンネルの 1 ストリーム
#[derive(Debug)]
pub struct ConnectEthernet {
    max_frame_len: Option<usize>,
}

/// フレームを HTTP Datagram に載せる前の拒否
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// 14 バイトに満たない、または FCS を含むと判断できる形ではない
    TooShort,
    /// 設定した最大長を超えている
    TooBig {
        /// 許される最大フレーム長
        max: usize,
    },
}

/// 受信した結果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecvFrame {
    /// Context ID 0 の Ethernet フレーム。FCS は付いていない
    Frame(Vec<u8>),
    /// 登録されていない Context ID
    UnknownContext {
        /// 未知の Context ID
        context_id: u64,
    },
}

impl ConnectEthernet {
    /// セッションを作る
    pub fn new() -> Self {
        Self {
            max_frame_len: None,
        }
    }

    /// QUIC DATAGRAM に入るフレームの最大長
    pub fn set_max_frame_len(&mut self, max: usize) {
        self.max_frame_len = Some(max);
    }

    /// FCS を除いた Ethernet フレームを HTTP Datagram ペイロードにする
    pub fn send_frame(&self, frame: &[u8]) -> Result<Vec<u8>, SendError> {
        if frame.len() < MIN_FRAME_LEN {
            return Err(SendError::TooShort);
        }
        if let Some(max) = self.max_frame_len
            && frame.len() > max
        {
            return Err(SendError::TooBig { max });
        }
        let mut out = Vec::new();
        HttpDatagram {
            context_id: 0,
            payload: frame.to_vec(),
        }
        .encode(&mut out)
        .expect("Context ID 0 は可変長整数に収まる (実装バグならパニック)");
        Ok(out)
    }

    /// Quarter Stream ID を除いた HTTP Datagram をフレームとして読む
    pub fn recv_http_datagram(&self, payload: &[u8]) -> Result<RecvFrame, Error> {
        let datagram = HttpDatagram::decode(payload)?;
        if datagram.context_id != 0 {
            return Ok(RecvFrame::UnknownContext {
                context_id: datagram.context_id,
            });
        }
        if datagram.payload.len() < MIN_FRAME_LEN {
            return Err(Error::Malformed);
        }
        Ok(RecvFrame::Frame(datagram.payload))
    }
}

impl Default for ConnectEthernet {
    fn default() -> Self {
        Self::new()
    }
}
