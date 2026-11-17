#![no_std]
#![forbid(unsafe_code)]

//! shiguredo_masque: MASQUE の Sans I/O ライブラリ
//!
//! HTTP と QUIC は持たない。カプセルと HTTP Datagram ペイロード、
//! 1 本の CONNECT ストリームに閉じた状態だけを扱う。
//! ソケット、TUN、NAT、名前解決の実行は呼び出し側である。
//!
//! 対象は次のとおり。
//!
//! - RFC 9297 のカプセルと DATAGRAM カプセル
//! - RFC 9484 の CONNECT-IP
//! - RFC 9298 の CONNECT-UDP
//! - draft-ietf-masque-connect-ip-dns-07 の DNS_ASSIGN と PREF64
//!
//! DNS と PREF64 のカプセル型番号はドラフトの暫定値であり、改訂で変わる。

extern crate alloc;

/// README のコード例を doctest で検証するためのフック
///
/// `no_run` フェンスはコンパイルのみ行われるため、コピーして動く例であることを確認できる (実行はしない)。
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

/// カプセルのエンコードと増分デコード (RFC 9297)
pub mod capsule;
/// HTTP Datagram のテンプレート圧縮 (draft-ietf-masque-http-datagram-compression-02)
pub mod compress;
/// CONNECT-ETHERNET セッション (draft-ietf-masque-connect-ethernet-18)
pub mod connect_ethernet;
/// CONNECT-IP セッション (RFC 9484)
pub mod connect_ip;
/// CONNECT-UDP セッション (RFC 9298)
pub mod connect_udp;
/// HTTP Datagram ペイロードの Context ID
pub mod datagram;
/// DNS_ASSIGN と PREF64 (draft-ietf-masque-connect-ip-dns-07)
pub mod dns;
/// ECN と DSCP の Context ID (draft-ietf-masque-connect-udp-ecn-dscp-02)
pub mod ecn;
/// プロトコルエラー
pub mod error;
/// IP プレフィックス、経路、IP パケット
pub mod ip;
/// QUIC-aware proxy の CID 登録 (draft-ietf-masque-quic-proxy-10)
pub mod quic_proxy;
/// CONNECT-UDP Bind (draft-ietf-masque-connect-udp-listen-16)
pub mod udp_bind;
/// QUIC 可変長整数 (RFC 9000 Section 16)
pub mod varint;

pub(crate) mod reader;
