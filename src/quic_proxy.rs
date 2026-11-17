//! QUIC を意識した UDP プロキシ (draft-ietf-masque-quic-proxy-10)
//!
//! クライアント CID とターゲット CID の登録、仮想 CID の発行、
//! ロングヘッダはトンネル、ショートヘッダは登録済み DCID なら転送、を扱う。
//! カプセル型はドラフトの暫定値であり、公開前に小さい値へ置き換わる。

use crate::error::Error;
use crate::reader::Reader;
use crate::varint;
use alloc::vec::Vec;

/// REGISTER_CLIENT_CID
pub const REGISTER_CLIENT_CID: u64 = 0xffe900;
/// REGISTER_TARGET_CID
pub const REGISTER_TARGET_CID: u64 = 0xffe901;
/// ACK_CLIENT_CID
pub const ACK_CLIENT_CID: u64 = 0xffe902;
/// ACK_TARGET_CID
pub const ACK_TARGET_CID: u64 = 0xffe903;
/// REJECT_CLIENT_CID
pub const REJECT_CLIENT_CID: u64 = 0xffe904;
/// REJECT_TARGET_CID
pub const REJECT_TARGET_CID: u64 = 0xffe905;
/// RETIRE_CLIENT_CID
pub const RETIRE_CLIENT_CID: u64 = 0xffe906;
/// RETIRE_TARGET_CID
pub const RETIRE_TARGET_CID: u64 = 0xffe907;
/// NEW_TARGET_VCID
pub const NEW_TARGET_VCID: u64 = 0xffe90a;

/// クライアントが自分の Connection ID を登録する
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterClientCid {
    /// 登録のシーケンス番号
    pub sequence: u64,
    /// Connection ID。QUIC 不変条件では 0 から 255 バイト
    pub connection_id: Vec<u8>,
}

/// ターゲットの Connection ID と Stateless Reset Token
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterTargetCid {
    /// 登録のシーケンス番号
    pub sequence: u64,
    /// 本当のターゲット CID
    pub connection_id: Vec<u8>,
    /// Stateless Reset Token。長さはカプセルの残り
    pub reset_token: Vec<u8>,
}

/// プロキシが発行するターゲット仮想 CID
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTargetVcid {
    /// 対応するターゲット CID 登録のシーケンス番号
    pub cid_sequence: u64,
    /// 仮想 CID のシーケンス番号
    pub vcid_sequence: u64,
    /// これ未満の仮想 CID を引退させる。vcid_sequence 以下
    pub retire_prior_to: u64,
    /// 仮想 CID。1 バイト以上
    pub virtual_connection_id: Vec<u8>,
    /// Stateless Reset Token。空ならリセットを使わない
    pub reset_token: Vec<u8>,
}

pub(crate) fn encode_register_client(
    cid: &RegisterClientCid,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    check_cid(&cid.connection_id)?;
    varint::encode(cid.sequence, out)?;
    out.extend_from_slice(&cid.connection_id);
    Ok(())
}

pub(crate) fn decode_register_client(buf: &[u8]) -> Result<RegisterClientCid, Error> {
    let mut reader = Reader::new(buf);
    let sequence = reader.varint()?;
    let connection_id = reader.rest().to_vec();
    check_cid(&connection_id)?;
    Ok(RegisterClientCid {
        sequence,
        connection_id,
    })
}

pub(crate) fn encode_register_target(
    cid: &RegisterTargetCid,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    check_cid(&cid.connection_id)?;
    varint::encode(cid.sequence, out)?;
    varint::encode(
        u64::try_from(cid.connection_id.len()).map_err(|_| Error::Malformed)?,
        out,
    )?;
    out.extend_from_slice(&cid.connection_id);
    out.extend_from_slice(&cid.reset_token);
    Ok(())
}

pub(crate) fn decode_register_target(buf: &[u8]) -> Result<RegisterTargetCid, Error> {
    let mut reader = Reader::new(buf);
    let sequence = reader.varint()?;
    let length = usize::try_from(reader.varint()?).map_err(|_| Error::Malformed)?;
    let connection_id = reader.take(length)?.to_vec();
    check_cid(&connection_id)?;
    Ok(RegisterTargetCid {
        sequence,
        connection_id,
        reset_token: reader.rest().to_vec(),
    })
}

pub(crate) fn encode_sequence(sequence: u64, out: &mut Vec<u8>) -> Result<(), Error> {
    varint::encode(sequence, out)
}

pub(crate) fn decode_sequence(buf: &[u8]) -> Result<u64, Error> {
    let mut reader = Reader::new(buf);
    let sequence = reader.varint()?;
    reader.finish_empty()?;
    Ok(sequence)
}

pub(crate) fn encode_new_target_vcid(vcid: &NewTargetVcid, out: &mut Vec<u8>) -> Result<(), Error> {
    if vcid.virtual_connection_id.is_empty() || vcid.virtual_connection_id.len() > 255 {
        return Err(Error::Malformed);
    }
    if vcid.retire_prior_to > vcid.vcid_sequence {
        return Err(Error::Malformed);
    }
    varint::encode(vcid.cid_sequence, out)?;
    varint::encode(vcid.vcid_sequence, out)?;
    varint::encode(vcid.retire_prior_to, out)?;
    varint::encode(
        u64::try_from(vcid.virtual_connection_id.len()).map_err(|_| Error::Malformed)?,
        out,
    )?;
    out.extend_from_slice(&vcid.virtual_connection_id);
    out.extend_from_slice(&vcid.reset_token);
    Ok(())
}

pub(crate) fn decode_new_target_vcid(buf: &[u8]) -> Result<NewTargetVcid, Error> {
    let mut reader = Reader::new(buf);
    let vcid = NewTargetVcid {
        cid_sequence: reader.varint()?,
        vcid_sequence: reader.varint()?,
        retire_prior_to: reader.varint()?,
        virtual_connection_id: Vec::new(),
        reset_token: Vec::new(),
    };
    if vcid.retire_prior_to > vcid.vcid_sequence {
        return Err(Error::Malformed);
    }
    let length = usize::try_from(reader.varint()?).map_err(|_| Error::Malformed)?;
    let mut vcid = vcid;
    vcid.virtual_connection_id = reader.take(length)?.to_vec();
    if vcid.virtual_connection_id.is_empty() {
        return Err(Error::Malformed);
    }
    vcid.reset_token = reader.rest().to_vec();
    Ok(vcid)
}

fn check_cid(connection_id: &[u8]) -> Result<(), Error> {
    if connection_id.len() > 255 {
        Err(Error::Malformed)
    } else {
        Ok(())
    }
}

/// ショートヘッダの転送か、ロングヘッダのトンネルか
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Forwarding {
    /// ロングヘッダ、または未知の DCID。CONNECT-UDP で包む
    Tunnelled,
    /// 登録済みの仮想 CID 宛。包まずに転送する
    Forwarded {
        /// 一致した仮想 CID
        virtual_connection_id: Vec<u8>,
    },
}

/// QUIC パケットの宛先 CID を、登録済みの仮想 CID と比べる
///
/// 先頭ビットが 1 のロングヘッダは常にトンネルする (draft-ietf-masque-quic-proxy-10 Section 1)。
/// ショートヘッダの DCID 長は呼び出し側が知っている接続の CID 長を渡す。
pub fn classify_packet(packet: &[u8], dcid_len: usize, virtual_cids: &[Vec<u8>]) -> Forwarding {
    let Some(first) = packet.first() else {
        return Forwarding::Tunnelled;
    };
    if first & 0x80 != 0 {
        return Forwarding::Tunnelled;
    }
    if packet.len() < 1 + dcid_len {
        return Forwarding::Tunnelled;
    }
    let dcid = &packet[1..1 + dcid_len];
    for virtual_cid in virtual_cids {
        if virtual_cid.as_slice() == dcid {
            return Forwarding::Forwarded {
                virtual_connection_id: virtual_cid.clone(),
            };
        }
    }
    Forwarding::Tunnelled
}
