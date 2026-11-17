# masque

CONNECT-IP を試す実行ファイルです。crates.io へは公開しません (`publish = false`)。

`masque proxy` が待ち受け、`masque client` が接続します。プロキシが待ち合わせになるので、別のシグナリングサーバーは要りません。

## すること

- `127.0.0.1:4443` で UDP を待ち受ける。ALPN は `h3`
- localhost 向けの自己署名証明書を、起動のたびにメモリ上で作る
- 固定のパス `/.well-known/masque/ip/*/*/` で CONNECT-IP を受け、200 を返す
- `192.0.2.0/24` (TEST-NET-1) からアドレスを 1 つずつ配る。`192.0.2.0` と `192.0.2.255` は配らない
- クライアントへ `0.0.0.0/0` を広告する
- 届いた IPv4 パケットの宛先が、今つながっている誰かの代入アドレスなら、そのクライアントへ渡す
- それ以外の宛先は捨てる

`--tun` を付けると、代入アドレスの utun を作り、OS とトンネルの間で IP パケットを渡します。NAT、認証、DNS の問い合わせ、ノード探索はしません。

## 実行例

3 つの端末を使います。最初のクライアントが表示したアドレスを、3 つ目の `--to` に渡します。`--insecure` は自己署名証明書の検証を省略します。

```bash
cargo run -p masque -- proxy
cargo run -p masque -- client --insecure
cargo run -p masque -- client --insecure --to 192.0.2.1
```

`--to` を付けないクライアントは、受け取った試験パケットを送り主へ返します。`--to` を付けたクライアントは 1 つ送って返事を表示し、終了します。

OS から `192.0.2.0/24` へパケットを出すには `--tun` を使います。アドレスと経路を足すので root が要ります。同じホストで `--tun` を 2 つ起動すると、経路は後勝ちになります。

```bash
cargo build -p masque
sudo ./target/debug/masque client --insecure --tun
```

`RUST_LOG` が無いときは `info` を出します。
