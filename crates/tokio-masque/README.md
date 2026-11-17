# tokio-masque

Sans I/O な `shiguredo_masque` を、tobi-quic と http3-rs に結ぶトランスポート層のライブラリです。crates.io へは公開しません (`publish = false`)。

確立済みの QUIC 接続の上で HTTP/3 を駆動し、CONNECT のデータストリームと HTTP Datagram をアプリケーションに渡します。アドレス代入、経路、IP パケットの判定は `ConnectIp` が行います。

## 提供する範囲

- `h3::H3Handle`：1 本の QUIC 接続上の HTTP/3
  - `spawn_client` / `spawn_server`：制御ストリーム、QPACK ストリーム、バックグラウンド駆動を開始する
  - `request`：Extended CONNECT を含むリクエストを送り、ストリーム ID を返す
  - `respond`：レスポンスヘッダを返す
  - `send_body`：データストリームへカプセルのバイト列を書く
  - `send_datagram`：HTTP Datagram ペイロードに Quarter Stream ID を付け、QUIC DATAGRAM で送る
  - `recv`：ピアの SETTINGS、ヘッダ、DATA、HTTP Datagram ペイロードを受け取る
- `h3::H3Event`：上記の受信イベント
- `endpoint::Listener`：localhost 向けの自己署名証明書で UDP を待ち受け、接続ごとに `H3Handle` を返す
- `endpoint::connect`：プロキシへ QUIC と HTTP/3 の接続を張る。証明書検証を省略できる

すでに張った QUIC 接続は、これまでどおり `H3Handle::spawn_client` / `spawn_server` に渡せます。DATAGRAM を有効にした接続を渡してください。

このクレートが持たないものは次のとおりです。

- TUN、OS の経路表、NAT
- 認証
- DNS の問い合わせ。`DNS_ASSIGN` の解釈は `shiguredo_masque` が行い、OS への反映はアプリケーションが行います

## テスト

ループバックで CONNECT-IP を 1 本張り、プロキシが `192.0.2.11/32` と IPv4 のデフォルト経路を配ったあと、IP パケットが往復することを確認します。

```bash
cargo test -p tokio-masque --test connect_ip
```
