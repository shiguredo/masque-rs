//! CONNECT-UDP の 1 ストリーム (RFC 9298)
//!
//! ターゲットのホストとポートは HTTP リクエストの URI テンプレートにあり、
//! このセッションはデータストリームが始まったあとだけを扱う。
//! Context ID 0 が UDP ペイロードである。0 以外の登録方法はこの RFC には無いので、
//! 未知の Context ID は捨てる (Section 5)。

use core::net::IpAddr;

use crate::capsule::{Capsule, CapsuleDecoder, Outbox};
use crate::datagram::HttpDatagram;
use crate::error::Error;
use crate::udp_bind::{self, CompressionAssign, CompressionTarget, UdpBind, UncompressedUdp};
use alloc::vec::Vec;

/// Context ID 0 の UDP ペイロードの最大長 (RFC 9298 Section 5)
pub const MAX_UDP_PAYLOAD: usize = 65_527;

/// HTTP における役割
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// CONNECT を送る側
    Client,
    /// UDP プロキシ
    Proxy,
}

/// CONNECT-UDP セッション
#[derive(Debug)]
pub struct ConnectUdp {
    role: Role,
    decoder: CapsuleDecoder,
    outbox: Outbox,
    events: Vec<Event>,
    aborted: bool,
    max_udp_payload: Option<usize>,
    bind: UdpBind,
}

/// UDP ペイロードを HTTP Datagram に載せる前の拒否
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpSendError {
    /// セッションはすでに破棄されている
    Aborted,
    /// 65527 バイトを超える。ストリームは破棄しない
    PayloadTooLong,
    /// QUIC DATAGRAM に入らない。呼び出し側が ICMP Packet Too Big を返す (RFC 9298 Section 6.1)
    DoesNotFit {
        /// 入る最大の UDP ペイロード長
        max_payload: usize,
    },
    /// Bind の登録が無い、または閉じている
    Unregistered,
}

/// 受信イベント
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Context ID 0 の UDP ペイロード
    UdpPayload(Vec<u8>),
    /// Bind で宛先が付いた UDP ペイロード
    Bound {
        /// クライアントから見ると送信先、プロキシから見ると送信元
        address: IpAddr,
        /// UDP ポート
        port: u16,
        /// UDP ペイロード
        payload: Vec<u8>,
    },
    /// 登録されていない Context ID。データグラムは捨てる
    UnknownContext {
        /// 未知の Context ID
        context_id: u64,
    },
}

impl ConnectUdp {
    /// セッションを作る
    pub fn new(role: Role) -> Self {
        Self {
            role,
            decoder: CapsuleDecoder::new(),
            outbox: Outbox::default(),
            events: Vec::new(),
            aborted: false,
            max_udp_payload: None,
            bind: UdpBind::inactive(),
        }
    }

    /// HTTP 上の役割
    pub fn role(&self) -> Role {
        self.role
    }

    /// ストリームを破棄済みか
    pub fn is_aborted(&self) -> bool {
        self.aborted
    }

    /// QUIC DATAGRAM に入る UDP ペイロードの最大長
    ///
    /// 超えた送信は捨て、ストリームは破棄しない (RFC 9298 Section 6.1)。
    pub fn set_max_udp_payload(&mut self, max: usize) {
        self.max_udp_payload = Some(max);
    }

    /// CONNECT-UDP Bind を有効にする
    ///
    /// `wildcard` は target_host と target_port が `*` のとき真。
    pub fn enable_bind(&mut self, wildcard: bool) {
        self.bind
            .enable(matches!(self.role, Role::Client), wildcard);
    }

    /// COMPRESSION_ASSIGN を送る
    pub fn register_context(&mut self, assign: CompressionAssign) -> Result<(), Error> {
        self.ensure()?;
        let capsule = self.bind.queue_assign(assign)?;
        self.outbox.push(capsule.encode()?);
        Ok(())
    }

    /// データストリームのバイトを入れる
    pub fn recv_stream(&mut self, data: &[u8], fin: bool) -> Result<(), Error> {
        self.ensure()?;
        if let Err(err) = self.decoder.push(data) {
            self.aborted = true;
            return Err(err);
        }
        loop {
            match self.decoder.poll() {
                Ok(Some(capsule)) => self.apply(capsule)?,
                Ok(None) => break,
                Err(err) => {
                    self.aborted = true;
                    return Err(err);
                }
            }
        }
        if fin && let Err(err) = self.decoder.finish() {
            self.aborted = true;
            return Err(err);
        }
        Ok(())
    }

    /// Quarter Stream ID を除いた HTTP Datagram ペイロードを入れる
    ///
    /// Context ID 0 で 65527 バイトを超えるペイロードはストリームを破棄する
    /// (RFC 9298 Section 5)。
    pub fn recv_http_datagram(&mut self, payload: &[u8]) -> Result<(), Error> {
        self.ensure()?;
        let datagram = HttpDatagram::decode(payload)?;
        self.take_datagram(datagram)
    }

    /// 次の受信イベント
    pub fn poll_event(&mut self) -> Option<Event> {
        if self.events.is_empty() {
            None
        } else {
            Some(self.events.remove(0))
        }
    }

    /// 次にデータストリームへ書くカプセル
    pub fn poll_capsule(&mut self) -> Option<Vec<u8>> {
        self.outbox.pop()
    }

    /// UDP ペイロードを Context ID 0 の HTTP Datagram ペイロードにする
    ///
    /// 65527 バイトを超えるときは送らず、セッションは破棄しない。
    pub fn send_udp_payload(&mut self, payload: &[u8]) -> Result<Vec<u8>, UdpSendError> {
        if self.aborted {
            return Err(UdpSendError::Aborted);
        }
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(UdpSendError::PayloadTooLong);
        }
        if let Some(max) = self.max_udp_payload
            && payload.len() > max
        {
            return Err(UdpSendError::DoesNotFit { max_payload: max });
        }
        encode_context_payload(0, payload)
    }

    /// 圧縮した Bind コンテキストで UDP ペイロードを送る
    pub fn send_compressed(
        &mut self,
        context_id: u64,
        payload: &[u8],
    ) -> Result<Vec<u8>, UdpSendError> {
        if self.aborted {
            return Err(UdpSendError::Aborted);
        }
        if !matches!(
            self.bind.lookup(context_id),
            Some(CompressionTarget::Compressed { .. })
        ) {
            return Err(UdpSendError::Unregistered);
        }
        if payload.len() > MAX_UDP_PAYLOAD {
            return Err(UdpSendError::PayloadTooLong);
        }
        encode_context_payload(context_id, payload)
    }

    /// 圧縮しない Bind コンテキストで宛先付き UDP を送る
    pub fn send_uncompressed(
        &mut self,
        context_id: u64,
        packet: &UncompressedUdp,
    ) -> Result<Vec<u8>, UdpSendError> {
        if self.aborted {
            return Err(UdpSendError::Aborted);
        }
        if !matches!(
            self.bind.lookup(context_id),
            Some(CompressionTarget::Uncompressed)
        ) {
            return Err(UdpSendError::Unregistered);
        }
        let mut body = Vec::new();
        udp_bind::encode_uncompressed(packet, &mut body).map_err(|_| UdpSendError::Unregistered)?;
        encode_context_payload(context_id, &body)
    }

    fn apply(&mut self, capsule: Capsule) -> Result<(), Error> {
        match capsule {
            Capsule::Datagram(datagram) => self.take_datagram(datagram),
            Capsule::CompressionAssign(assign) => {
                for response in self.bind.receive_assign(assign)? {
                    self.outbox.push(response.encode()?);
                }
                Ok(())
            }
            Capsule::CompressionAck(context_id) => self.bind.receive_ack(context_id),
            Capsule::CompressionClose(context_id) => self.bind.receive_close(context_id),
            _ => Ok(()),
        }
    }

    fn take_datagram(&mut self, datagram: HttpDatagram) -> Result<(), Error> {
        if self.bind.wildcard() && datagram.context_id == 0 {
            self.aborted = true;
            return Err(Error::ContextIdZero);
        }
        if datagram.context_id == 0 && datagram.payload.len() > MAX_UDP_PAYLOAD {
            self.aborted = true;
            return Err(Error::UdpPayloadTooLong);
        }
        if self.bind.is_closed(datagram.context_id) {
            return Ok(());
        }
        if let Some(target) = self.bind.lookup(datagram.context_id).cloned() {
            match target {
                CompressionTarget::Uncompressed => {
                    let packet = udp_bind::decode_uncompressed(&datagram.payload)?;
                    self.events.push(Event::Bound {
                        address: packet.address,
                        port: packet.port,
                        payload: packet.payload,
                    });
                }
                CompressionTarget::Compressed { address, port } => {
                    self.events.push(Event::Bound {
                        address,
                        port,
                        payload: datagram.payload,
                    });
                }
            }
            return Ok(());
        }
        if datagram.context_id == 0 {
            self.events.push(Event::UdpPayload(datagram.payload));
        } else {
            self.events.push(Event::UnknownContext {
                context_id: datagram.context_id,
            });
        }
        Ok(())
    }

    fn ensure(&self) -> Result<(), Error> {
        if self.aborted {
            Err(Error::Aborted)
        } else {
            Ok(())
        }
    }
}

fn encode_context_payload(context_id: u64, payload: &[u8]) -> Result<Vec<u8>, UdpSendError> {
    let mut out = Vec::new();
    HttpDatagram {
        context_id,
        payload: payload.to_vec(),
    }
    .encode(&mut out)
    .map_err(|_| UdpSendError::Unregistered)?;
    Ok(out)
}
