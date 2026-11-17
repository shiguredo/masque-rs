//! CONNECT-IP を 1 台のプロキシで中継して試す。
//!
//! `proxy` がアドレスを配り、つながっているクライアント同士の IP パケットを渡す。
//! クライアントは TUN を開いて、そのパケットを OS とトンネルの間で渡せる。
//! NAT、認証、ノード探索は持たない。

use std::net::Ipv4Addr;

pub mod client;
pub mod proxy;
pub mod tun;

/// 実験で固定する CONNECT のパス
///
/// URI テンプレートの対象は埋めず、この文字列のまま使う。
pub(crate) const CONNECT_PATH: &[u8] = b"/.well-known/masque/ip/*/*/";

/// プロキシが配る IPv4 ネットワーク。RFC 5737 の TEST-NET-1
pub(crate) const POOL_PREFIX: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 0);

/// [`POOL_PREFIX`] のプレフィックス長
pub(crate) const POOL_PREFIX_LEN: u8 = 24;
