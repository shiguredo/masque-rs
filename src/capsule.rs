//! Capsule Protocol (RFC 9297 Section 3.2)
//!
//! 未知のカプセル型は捨てて次を読む (Section 3.2)。
//! DATAGRAM カプセル (0x00) の値が上限を超えるときは、中身を溜めずに捨てる
//! (Section 3.5)。制御カプセルが上限を超えたときはストリームを止める。
//!
//! CONNECT-IP と CONNECT-UDP のカプセル型は、それぞれの RFC で登録された値を使う。
//! DNS_ASSIGN と PREF64 の番号はドラフトの暫定値である。

use crate::compress::{self, ChecksumAssign, DerivedAssign, TemplateAssign};
use crate::datagram::HttpDatagram;
use crate::dns::{self, DnsConfiguration, Nat64Prefix};
use crate::ecn::{self, EcnDscpAssignment};
use crate::error::Error;
use crate::ip::{self, AssignedAddress, RequestedAddress, RouteRange};
use crate::quic_proxy::{self, NewTargetVcid, RegisterClientCid, RegisterTargetCid};
use crate::udp_bind::{self, CompressionAssign};
use crate::varint;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// DATAGRAM カプセル (RFC 9297 Section 3.5)
pub const DATAGRAM: u64 = 0x00;
/// ADDRESS_ASSIGN (RFC 9484 Section 4.7.1)
pub const ADDRESS_ASSIGN: u64 = 0x01;
/// ADDRESS_REQUEST (RFC 9484 Section 4.7.2)
pub const ADDRESS_REQUEST: u64 = 0x02;
/// ROUTE_ADVERTISEMENT (RFC 9484 Section 4.7.3)
pub const ROUTE_ADVERTISEMENT: u64 = 0x03;

/// 制御カプセル値の既定上限
///
/// IP パケット 1 個がストリーム上の DATAGRAM カプセルに入る余地は残し、
/// 制御メッセージがメモリを食い潰さない長さにする。
pub const DEFAULT_MAX_VALUE_LEN: usize = 65_535;

/// カプセル 1 個
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capsule {
    /// HTTP Datagram ペイロードそのもの (Quarter Stream ID は含まない)
    Datagram(HttpDatagram),
    /// ピアへアドレスを代入する。空リストは全部の取り下げ
    AddressAssign(Vec<AssignedAddress>),
    /// アドレス代入を要求する
    AddressRequest(Vec<RequestedAddress>),
    /// 転送するアドレス範囲。空リストは全部の取り下げ
    RouteAdvertisement(Vec<RouteRange>),
    /// DNS リゾルバ設定。空リストは設定の取り下げ
    DnsAssign(Vec<DnsConfiguration>),
    /// NAT64 プレフィックス。空リストは取り下げ
    Pref64(Vec<Nat64Prefix>),
    /// CONNECT-UDP Bind の Context ID 登録
    CompressionAssign(CompressionAssign),
    /// 登録の受理
    CompressionAck(u64),
    /// 登録の拒否または閉鎖
    CompressionClose(u64),
    /// ECN / DSCP の Context ID 割当
    EcnDscpAssign(Vec<EcnDscpAssignment>),
    /// ECN / DSCP 割当の確認
    EcnDscpAck(Vec<EcnDscpAssignment>),
    /// ECN / DSCP の Context ID を閉じる
    EcnDscpClose(u64),
    /// 静的セグメントによるテンプレート
    TemplateAssign(TemplateAssign),
    /// テンプレートの確認
    TemplateAck(u64),
    /// テンプレートを閉じる
    TemplateClose(u64),
    /// 派生フィールド
    DerivedAssign(DerivedAssign),
    /// 派生フィールドの確認
    DerivedAck(u64),
    /// 派生フィールドを閉じる
    DerivedClose(u64),
    /// チェックサムオフロード
    ChecksumAssign(ChecksumAssign),
    /// チェックサムオフロードの確認
    ChecksumAck(u64),
    /// チェックサムオフロードを閉じる
    ChecksumClose(u64),
    /// クライアント CID の登録
    RegisterClientCid(RegisterClientCid),
    /// ターゲット CID の登録
    RegisterTargetCid(RegisterTargetCid),
    /// クライアント CID 登録の確認
    AckClientCid(u64),
    /// ターゲット CID 登録の確認
    AckTargetCid(u64),
    /// クライアント CID 登録の拒否
    RejectClientCid(u64),
    /// ターゲット CID 登録の拒否
    RejectTargetCid(u64),
    /// クライアント CID の引退
    RetireClientCid(u64),
    /// ターゲット CID の引退
    RetireTargetCid(u64),
    /// ターゲット仮想 CID の発行
    NewTargetVcid(NewTargetVcid),
}

impl Capsule {
    /// カプセルをエンコードする
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut value = Vec::new();
        let type_id = match self {
            Self::Datagram(datagram) => {
                datagram.encode(&mut value)?;
                DATAGRAM
            }
            Self::AddressAssign(list) => {
                ip::encode_assigned(list, &mut value)?;
                ADDRESS_ASSIGN
            }
            Self::AddressRequest(list) => {
                ip::encode_requested(list, &mut value)?;
                ADDRESS_REQUEST
            }
            Self::RouteAdvertisement(list) => {
                ip::encode_routes(list, &mut value)?;
                ROUTE_ADVERTISEMENT
            }
            Self::DnsAssign(list) => {
                dns::encode_dns(list, &mut value)?;
                dns::DNS_ASSIGN
            }
            Self::Pref64(list) => {
                dns::encode_pref64(list, &mut value);
                dns::PREF64
            }
            Self::CompressionAssign(assign) => {
                udp_bind::encode_assign(assign, &mut value)?;
                udp_bind::COMPRESSION_ASSIGN
            }
            Self::CompressionAck(context_id) => {
                udp_bind::encode_context_id(*context_id, &mut value)?;
                udp_bind::COMPRESSION_ACK
            }
            Self::CompressionClose(context_id) => {
                udp_bind::encode_context_id(*context_id, &mut value)?;
                udp_bind::COMPRESSION_CLOSE
            }
            Self::EcnDscpAssign(list) => {
                ecn::encode_assignments(list, &mut value)?;
                ecn::ECN_DSCP_CONTEXT_ASSIGN
            }
            Self::EcnDscpAck(list) => {
                ecn::encode_assignments(list, &mut value)?;
                ecn::ECN_DSCP_CONTEXT_ACK
            }
            Self::EcnDscpClose(context_id) => {
                udp_bind::encode_context_id(*context_id, &mut value)?;
                ecn::ECN_DSCP_CONTEXT_CLOSE
            }
            Self::TemplateAssign(template) => {
                compress::encode_template(template, &mut value)?;
                compress::TEMPLATE_ASSIGN
            }
            Self::TemplateAck(context_id) => {
                compress::encode_ack(*context_id, &mut value)?;
                compress::TEMPLATE_ACK
            }
            Self::TemplateClose(context_id) => {
                compress::encode_ack(*context_id, &mut value)?;
                compress::TEMPLATE_CLOSE
            }
            Self::DerivedAssign(derived) => {
                compress::encode_derived(derived, &mut value)?;
                compress::DERIVED_ASSIGN
            }
            Self::DerivedAck(context_id) => {
                compress::encode_ack(*context_id, &mut value)?;
                compress::DERIVED_ACK
            }
            Self::DerivedClose(context_id) => {
                compress::encode_ack(*context_id, &mut value)?;
                compress::DERIVED_CLOSE
            }
            Self::ChecksumAssign(checksum) => {
                compress::encode_checksum(checksum, &mut value)?;
                compress::CHECKSUM_ASSIGN
            }
            Self::ChecksumAck(context_id) => {
                compress::encode_ack(*context_id, &mut value)?;
                compress::CHECKSUM_ACK
            }
            Self::ChecksumClose(context_id) => {
                compress::encode_ack(*context_id, &mut value)?;
                compress::CHECKSUM_CLOSE
            }
            Self::RegisterClientCid(cid) => {
                quic_proxy::encode_register_client(cid, &mut value)?;
                quic_proxy::REGISTER_CLIENT_CID
            }
            Self::RegisterTargetCid(cid) => {
                quic_proxy::encode_register_target(cid, &mut value)?;
                quic_proxy::REGISTER_TARGET_CID
            }
            Self::AckClientCid(sequence) => {
                quic_proxy::encode_sequence(*sequence, &mut value)?;
                quic_proxy::ACK_CLIENT_CID
            }
            Self::AckTargetCid(sequence) => {
                quic_proxy::encode_sequence(*sequence, &mut value)?;
                quic_proxy::ACK_TARGET_CID
            }
            Self::RejectClientCid(sequence) => {
                quic_proxy::encode_sequence(*sequence, &mut value)?;
                quic_proxy::REJECT_CLIENT_CID
            }
            Self::RejectTargetCid(sequence) => {
                quic_proxy::encode_sequence(*sequence, &mut value)?;
                quic_proxy::REJECT_TARGET_CID
            }
            Self::RetireClientCid(sequence) => {
                quic_proxy::encode_sequence(*sequence, &mut value)?;
                quic_proxy::RETIRE_CLIENT_CID
            }
            Self::RetireTargetCid(sequence) => {
                quic_proxy::encode_sequence(*sequence, &mut value)?;
                quic_proxy::RETIRE_TARGET_CID
            }
            Self::NewTargetVcid(vcid) => {
                quic_proxy::encode_new_target_vcid(vcid, &mut value)?;
                quic_proxy::NEW_TARGET_VCID
            }
        };
        let mut out = Vec::new();
        varint::encode(type_id, &mut out)?;
        varint::encode(
            u64::try_from(value.len()).map_err(|_| Error::Malformed)?,
            &mut out,
        )?;
        out.extend_from_slice(&value);
        Ok(out)
    }
}

/// 増分カプセルデコーダ
///
/// `push` で受信バイトを足し、`poll` で揃ったカプセルを 1 個ずつ取る。
/// `finish` は FIN を受けたときに呼ぶ。途中のカプセルが残っていれば
/// [`Error::Truncated`] (RFC 9297 Section 3.3)。
#[derive(Debug, Clone)]
pub struct CapsuleDecoder {
    buf: Vec<u8>,
    skip_remaining: Option<u64>,
    max_value_len: usize,
    finished: bool,
}

impl Default for CapsuleDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl CapsuleDecoder {
    /// 既定の値長上限でデコーダを作る
    pub fn new() -> Self {
        Self::with_max_value_len(DEFAULT_MAX_VALUE_LEN)
    }

    /// 値長の上限を指定してデコーダを作る
    pub fn with_max_value_len(max_value_len: usize) -> Self {
        Self {
            buf: Vec::new(),
            skip_remaining: None,
            max_value_len,
            finished: false,
        }
    }

    /// 受信したバイト列を追加する
    ///
    /// `finish` のあとには呼ばない。
    pub fn push(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.finished {
            return Err(Error::Aborted);
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// 揃ったカプセルを 1 個返す
    ///
    /// まだ足りないときは `Ok(None)`。未知タイプは内部で読み飛ばす。
    pub fn poll(&mut self) -> Result<Option<Capsule>, Error> {
        if self.finished {
            return Err(Error::Aborted);
        }
        loop {
            if let Some(remaining) = self.skip_remaining {
                let take = usize::try_from(remaining)
                    .unwrap_or(usize::MAX)
                    .min(self.buf.len());
                self.buf.drain(..take);
                let left = remaining - take as u64;
                if left > 0 {
                    self.skip_remaining = Some(left);
                    return Ok(None);
                }
                self.skip_remaining = None;
            }
            match self.pull()? {
                Pull::NeedMore => return Ok(None),
                Pull::Skip(len) => {
                    self.skip_remaining = Some(len);
                }
                Pull::Ready(capsule) => return Ok(Some(capsule)),
            }
        }
    }

    /// ストリームの FIN を通知する
    ///
    /// 未完了のカプセルや、捨て途中の値が残っていれば [`Error::Truncated`]。
    pub fn finish(&mut self) -> Result<(), Error> {
        self.finished = true;
        if self.skip_remaining.is_some_and(|left| left > 0) || !self.buf.is_empty() {
            return Err(Error::Truncated);
        }
        Ok(())
    }

    fn pull(&mut self) -> Result<Pull, Error> {
        let Some((type_id, type_len)) = varint::decode(&self.buf) else {
            return Ok(Pull::NeedMore);
        };
        let Some((value_len, len_len)) = varint::decode(&self.buf[type_len..]) else {
            return Ok(Pull::NeedMore);
        };
        let header = type_len + len_len;
        let value_len_usize = usize::try_from(value_len).map_err(|_| Error::Malformed)?;
        let known_control = is_known_control(type_id);
        if value_len_usize > self.max_value_len {
            // 制御カプセルの巨大な値はストリームを止める。
            // DATAGRAM と未知タイプは溜めずに捨てる (RFC 9297 Section 3.2 / 3.5)。
            if known_control {
                return Err(Error::CapsuleTooLarge);
            }
            self.buf.drain(..header);
            return Ok(Pull::Skip(value_len));
        }
        if self.buf.len() < header + value_len_usize {
            return Ok(Pull::NeedMore);
        }
        let value = self.buf[header..header + value_len_usize].to_vec();
        self.buf.drain(..header + value_len_usize);
        if !known_control && type_id != DATAGRAM {
            // 未知タイプは通知せず捨てる。
            return Ok(Pull::Skip(0));
        }
        Ok(Pull::Ready(decode_known(type_id, &value)?))
    }
}

enum Pull {
    NeedMore,
    Skip(u64),
    Ready(Capsule),
}

fn is_known_control(type_id: u64) -> bool {
    matches!(
        type_id,
        ADDRESS_ASSIGN
            | ADDRESS_REQUEST
            | ROUTE_ADVERTISEMENT
            | dns::DNS_ASSIGN
            | dns::PREF64
            | udp_bind::COMPRESSION_ASSIGN
            | udp_bind::COMPRESSION_ACK
            | udp_bind::COMPRESSION_CLOSE
            | ecn::ECN_DSCP_CONTEXT_ASSIGN
            | ecn::ECN_DSCP_CONTEXT_ACK
            | ecn::ECN_DSCP_CONTEXT_CLOSE
            | compress::TEMPLATE_ASSIGN
            | compress::TEMPLATE_ACK
            | compress::TEMPLATE_CLOSE
            | compress::DERIVED_ASSIGN
            | compress::DERIVED_ACK
            | compress::DERIVED_CLOSE
            | compress::CHECKSUM_ASSIGN
            | compress::CHECKSUM_ACK
            | compress::CHECKSUM_CLOSE
            | quic_proxy::REGISTER_CLIENT_CID
            | quic_proxy::REGISTER_TARGET_CID
            | quic_proxy::ACK_CLIENT_CID
            | quic_proxy::ACK_TARGET_CID
            | quic_proxy::REJECT_CLIENT_CID
            | quic_proxy::REJECT_TARGET_CID
            | quic_proxy::RETIRE_CLIENT_CID
            | quic_proxy::RETIRE_TARGET_CID
            | quic_proxy::NEW_TARGET_VCID
    )
}

fn decode_known(type_id: u64, value: &[u8]) -> Result<Capsule, Error> {
    match type_id {
        DATAGRAM => Ok(Capsule::Datagram(HttpDatagram::decode(value)?)),
        ADDRESS_ASSIGN => Ok(Capsule::AddressAssign(ip::decode_assigned(value)?)),
        ADDRESS_REQUEST => Ok(Capsule::AddressRequest(ip::decode_requested(value)?)),
        ROUTE_ADVERTISEMENT => Ok(Capsule::RouteAdvertisement(ip::decode_routes(value)?)),
        dns::DNS_ASSIGN => Ok(Capsule::DnsAssign(dns::decode_dns(value)?)),
        dns::PREF64 => Ok(Capsule::Pref64(dns::decode_pref64(value)?)),
        udp_bind::COMPRESSION_ASSIGN => {
            Ok(Capsule::CompressionAssign(udp_bind::decode_assign(value)?))
        }
        udp_bind::COMPRESSION_ACK => {
            Ok(Capsule::CompressionAck(udp_bind::decode_context_id(value)?))
        }
        udp_bind::COMPRESSION_CLOSE => Ok(Capsule::CompressionClose(udp_bind::decode_context_id(
            value,
        )?)),
        ecn::ECN_DSCP_CONTEXT_ASSIGN => Ok(Capsule::EcnDscpAssign(ecn::decode_assignments(value)?)),
        ecn::ECN_DSCP_CONTEXT_ACK => Ok(Capsule::EcnDscpAck(ecn::decode_assignments(value)?)),
        ecn::ECN_DSCP_CONTEXT_CLOSE => {
            Ok(Capsule::EcnDscpClose(udp_bind::decode_context_id(value)?))
        }
        compress::TEMPLATE_ASSIGN => Ok(Capsule::TemplateAssign(compress::decode_template(value)?)),
        compress::TEMPLATE_ACK => Ok(Capsule::TemplateAck(compress::decode_ack(value)?)),
        compress::TEMPLATE_CLOSE => Ok(Capsule::TemplateClose(compress::decode_ack(value)?)),
        compress::DERIVED_ASSIGN => Ok(Capsule::DerivedAssign(compress::decode_derived(value)?)),
        compress::DERIVED_ACK => Ok(Capsule::DerivedAck(compress::decode_ack(value)?)),
        compress::DERIVED_CLOSE => Ok(Capsule::DerivedClose(compress::decode_ack(value)?)),
        compress::CHECKSUM_ASSIGN => Ok(Capsule::ChecksumAssign(compress::decode_checksum(value)?)),
        compress::CHECKSUM_ACK => Ok(Capsule::ChecksumAck(compress::decode_ack(value)?)),
        compress::CHECKSUM_CLOSE => Ok(Capsule::ChecksumClose(compress::decode_ack(value)?)),
        quic_proxy::REGISTER_CLIENT_CID => Ok(Capsule::RegisterClientCid(
            quic_proxy::decode_register_client(value)?,
        )),
        quic_proxy::REGISTER_TARGET_CID => Ok(Capsule::RegisterTargetCid(
            quic_proxy::decode_register_target(value)?,
        )),
        quic_proxy::ACK_CLIENT_CID => {
            Ok(Capsule::AckClientCid(quic_proxy::decode_sequence(value)?))
        }
        quic_proxy::ACK_TARGET_CID => {
            Ok(Capsule::AckTargetCid(quic_proxy::decode_sequence(value)?))
        }
        quic_proxy::REJECT_CLIENT_CID => Ok(Capsule::RejectClientCid(quic_proxy::decode_sequence(
            value,
        )?)),
        quic_proxy::REJECT_TARGET_CID => Ok(Capsule::RejectTargetCid(quic_proxy::decode_sequence(
            value,
        )?)),
        quic_proxy::RETIRE_CLIENT_CID => Ok(Capsule::RetireClientCid(quic_proxy::decode_sequence(
            value,
        )?)),
        quic_proxy::RETIRE_TARGET_CID => Ok(Capsule::RetireTargetCid(quic_proxy::decode_sequence(
            value,
        )?)),
        quic_proxy::NEW_TARGET_VCID => Ok(Capsule::NewTargetVcid(
            quic_proxy::decode_new_target_vcid(value)?,
        )),
        _ => Err(Error::Malformed),
    }
}

/// `Capsule-Protocol` ヘッダ値が真の Boolean か
///
/// RFC 9297 Section 3.4。`?1` だけを真とする。パラメータは無視する。
/// リストなど Boolean 以外は、ヘッダが無いのと同じなので false。
pub fn capsule_protocol_header_is_true(value: &str) -> bool {
    let value = value.trim();
    let rest = value.strip_prefix("?1");
    match rest {
        Some("") => true,
        Some(rest) => rest.starts_with(';') || rest.starts_with(' '),
        None => false,
    }
}

/// 送信待ちカプセルを溜める
#[derive(Debug, Default)]
pub(crate) struct Outbox {
    queue: VecDeque<Vec<u8>>,
}

impl Outbox {
    pub(crate) fn push(&mut self, bytes: Vec<u8>) {
        self.queue.push_back(bytes);
    }

    pub(crate) fn pop(&mut self) -> Option<Vec<u8>> {
        self.queue.pop_front()
    }
}
