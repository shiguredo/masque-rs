# masque-rs

[![shiguredo_masque](https://img.shields.io/crates/v/shiguredo_masque.svg)](https://crates.io/crates/shiguredo_masque)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?logo=discord&logoColor=white)](https://discord.gg/shiguredo)

> [!WARNING]
> このライブラリは開発中であり、仕様が積極的に変更される場合があります。

## About Shiguredo's open source software

We will not respond to PRs or issues that have not been discussed on Discord. Also, Discord is only available in Japanese.

Please read <https://github.com/shiguredo/oss> before use.

## 時雨堂のオープンソースソフトウェアについて

利用前に <https://github.com/shiguredo/oss> をお読みください。

## 概要

MASQUE (Multiplexed Application Substrate over QUIC Encryption) を Rust で利用するためのライブラリです。HTTP の CONNECT の上で IP パケットや UDP ペイロードを運ぶプロトコルです。

出口へのトンネルや、コネクタが内側の経路を広告する VPN のクライアントとサーバーを実装する場合に利用できます。

## 特徴

- Sans I/O で実装しており、ネットワーク、タイマー、スレッドを扱いません
- `no_std` に対応しており、`alloc` だけで動作します
- 依存ライブラリはありません
- インクリメンタルデコーダー
  - 受信バッファにデータを追加しながら、カプセルを 1 つずつデコードできます
- CONNECT-IP の状態
  - アドレス代入、経路広告、DNS 設定、NAT64 プレフィックスを 1 本の CONNECT ストリームに閉じた状態として保持します
  - IP パケットを HTTP Datagram ペイロードにするとき、送信元、宛先、Hop Limit、MTU を検査します
- CONNECT-UDP
  - Context ID 0 の UDP ペイロードを HTTP Datagram ペイロードにします
- 対応仕様
  - [HTTP Datagrams and the Capsule Protocol](https://www.rfc-editor.org/rfc/rfc9297) `RFC 9297`
  - [Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298) `RFC 9298`
  - [Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484) `RFC 9484`
  - [DNS and PREF64 Configuration for Proxying IP in HTTP](https://datatracker.ietf.org/doc/html/draft-ietf-masque-connect-ip-dns-07) `draft-07`
  - [Proxying Bound UDP in HTTP](https://datatracker.ietf.org/doc/html/draft-ietf-masque-connect-udp-listen-16) `draft-16`
  - [ECN and DSCP support for HTTPS's Connect-UDP](https://datatracker.ietf.org/doc/html/draft-ietf-masque-connect-udp-ecn-dscp-02) `draft-02`
  - [Proxying Ethernet Frames in HTTP](https://datatracker.ietf.org/doc/html/draft-ietf-masque-connect-ethernet-18) `draft-18`
  - [Extensions to Compress and Derive Fields in HTTP Datagrams](https://datatracker.ietf.org/doc/html/draft-ietf-masque-http-datagram-compression-02) `draft-02`
  - [QUIC-Aware Proxying Using HTTP](https://datatracker.ietf.org/doc/html/draft-ietf-masque-quic-proxy-10) `draft-10`
    - ドラフトのカプセル型番号には暫定値がある。改訂で変わる

QUIC、HTTP、TUN、NAT、DNS の問い合わせはライブラリ本体にはありません。HTTP/3 と QUIC への結線は [tokio-masque](crates/tokio-masque/README.md) です。待受と接続を試す `masque` コマンドは [crates/masque](crates/masque/README.md) です。

## 使い方

### カプセルをバイト列にする

ADDRESS_ASSIGN などの制御はカプセルです。このライブラリはカプセルをバイト列にし、受信したバイト列からカプセルを取り出します。

```rust,no_run
use core::net::Ipv4Addr;
use shiguredo_masque::capsule::Capsule;
use shiguredo_masque::error::Error;
use shiguredo_masque::ip::{AssignedAddress, IpPrefix};

fn main() -> Result<(), Error> {
    let prefix = IpPrefix::new(Ipv4Addr::new(192, 0, 2, 11).into(), 32)?;
    let capsule = Capsule::AddressAssign(vec![AssignedAddress {
        request_id: 1,
        prefix,
    }]);
    let bytes = capsule.encode()?;
    // bytes を CONNECT のデータストリームに書き出す
    let _ = bytes;
    Ok(())
}
```

### 受信したデータを少しずつデコードする

カプセルは一度に全部届くとは限りません。受信した分をバッファに追加しながら、揃ったカプセルを 1 つずつ取り出せます。

```rust,no_run
use shiguredo_masque::capsule::CapsuleDecoder;
use shiguredo_masque::error::Error;

fn main() -> Result<(), Error> {
    let mut decoder = CapsuleDecoder::new();
    let data: &[u8] = &[];
    decoder.push(data)?;
    while let Some(capsule) = decoder.poll()? {
        let _ = capsule;
    }
    Ok(())
}
```

### CONNECT-IP の状態を管理する

アドレスの代入、経路の広告、IP パケットの転送判定は `ConnectIp` が行います。アプリケーションは、送るカプセルと HTTP Datagram ペイロードを取り出して書き出します。Quarter Stream ID は HTTP/3 側で付けます。

```rust,no_run
use core::net::Ipv4Addr;
use shiguredo_masque::connect_ip::{ConnectIp, Role};
use shiguredo_masque::error::Error;
use shiguredo_masque::ip::{self, AssignedAddress, IpPrefix, RequestedAddress, RouteRange};

fn main() -> Result<(), Error> {
    let mut client = ConnectIp::new(Role::Client);
    let mut proxy = ConnectIp::new(Role::Proxy);

    client.queue_address_request(vec![RequestedAddress {
        request_id: 1,
        prefix: IpPrefix::new(Ipv4Addr::UNSPECIFIED.into(), 32)?,
    }])?;
    let request = client.poll_capsule().expect("アドレス要求のカプセルがある");
    proxy.recv_stream(&request, false)?;

    proxy.queue_address_assign(vec![AssignedAddress {
        request_id: 1,
        prefix: IpPrefix::new(Ipv4Addr::new(192, 0, 2, 11).into(), 32)?,
    }])?;
    proxy.queue_route_advertisement(vec![RouteRange::new(
        Ipv4Addr::UNSPECIFIED.into(),
        Ipv4Addr::new(255, 255, 255, 255).into(),
        0,
    )?])?;
    while let Some(bytes) = proxy.poll_capsule() {
        client.recv_stream(&bytes, false)?;
    }
    while let Some(event) = client.poll_event() {
        let _ = event;
    }

    let packet = ip::encode_ipv4(
        Ipv4Addr::new(192, 0, 2, 11),
        Ipv4Addr::new(198, 51, 100, 1),
        17,
        64,
        b"ping",
    )?;
    // HTTP Datagram ペイロード。Quarter Stream ID は含まない
    let datagram = client
        .send_ip_packet(&packet, false)
        .expect("代入と経路のあと、IP パケットをカプセル化できる");
    let _ = datagram;
    Ok(())
}
```

## サンプル

プロキシが待ち合わせになります。別のシグナリングサーバーは要りません。詳細は [crates/README.md](crates/README.md) を参照してください。

```bash
cargo run -p masque -- proxy
cargo run -p masque -- client --insecure
cargo run -p masque -- client --insecure --to 192.0.2.1
```

## ライセンス

Apache License 2.0

```text
Copyright 2026 Shiguredo Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
