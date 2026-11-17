# MASQUE の結線と実験用コマンド

CONNECT-IP を HTTP/3 の上で運ぶクレートです。RFC 9484、RFC 9297、RFC 9298、draft-ietf-masque-connect-ip-dns-07 のうち、ライブラリ本体が実装している範囲を使います。

- [tokio-masque](tokio-masque/README.md)：tobi-quic と http3-rs を Sans I/O な `shiguredo_masque` に結ぶトランスポート層 (ライブラリ)
- [masque](masque/README.md)：`masque proxy` と `masque client` の実行ファイル。プロキシがクライアント同士の IP パケットを中継する

[Tokio](https://github.com/tokio-rs/tokio)、[tobi-quic](https://github.com/shiguredo/tobi-quic)、[http3-rs](https://github.com/shiguredo/http3-rs) を利用しています。QUIC は tobi-quic です。プロトコル本体は tobi-quic に依存しません。

`masque client --tun` は代入アドレスの utun を作ります。NAT、認証、DNS の問い合わせは含みません。

Rust 1.95 以降が必要です。

## 実行例

プロキシを起動し、2 つのクライアントで試験パケットを往復します。

```bash
cargo run -p masque -- proxy
cargo run -p masque -- client --insecure
cargo run -p masque -- client --insecure --to 192.0.2.1
```

待受は `127.0.0.1:4443` です。`--to` を付けないクライアントが表示したアドレスを、もう一方の `--to` に渡します。

ループバックの UDP ソケットだけで同じ往復を確認するテストは次です。

```bash
cargo test -p masque --test forward
cargo test -p tokio-masque --test connect_ip
```
