//! tobi-quic と http3-rs を CONNECT ストリームと HTTP Datagram に結ぶ。
//!
//! MASQUE の状態機械は [`shiguredo_masque`] にあり、このクレートはバイト列を運ぶだけである。

pub mod endpoint;
pub mod h3;
