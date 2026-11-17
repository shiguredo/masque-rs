//! 自己署名証明書で QUIC を待ち受け、接続する。
//!
//! tobi-quic はこのモジュールに閉じる。呼び出し側は HTTP/3 の [`crate::h3::H3Handle`] だけを受け取る。

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::PrivatePkcs8KeyDer;
use tobi_quic::{
    Client, ClientTlsConfig, Connect, DatagramConfig, IoConfig, Server, ServerTlsConfig,
};

use crate::h3::H3Handle;

const ALPN_H3: &[u8] = b"h3";

/// UDP で待ち受ける QUIC サーバー
///
/// 証明書は起動のたびに作る localhost 向けの自己署名である。秘密鍵はメモリだけに置く。
pub struct Listener {
    server: Server,
}

impl Listener {
    /// `addr` で UDP を待ち受ける
    ///
    /// ポート 0 は OS が空いているポートを選ぶ。実際のアドレスは [`Self::local_addr`]。
    pub fn bind(addr: SocketAddr) -> Result<Self, String> {
        install_crypto();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|err| err.to_string())?;
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
            )
            .map_err(|err| err.to_string())?;
        server_tls.alpn_protocols = vec![ALPN_H3.to_vec()];
        let server = Server::builder()
            .with_tls(ServerTlsConfig::new(Arc::new(server_tls)))
            .with_io(IoConfig::new(addr))
            .with_datagram(DatagramConfig::default())
            .start()
            .map_err(|err| err.to_string())?;
        Ok(Self { server })
    }

    /// 実際に bind したアドレス
    pub fn local_addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    /// ハンドシェイクが終わった接続の HTTP/3 を返す
    ///
    /// 待受ソケットは [`Listener`] が持つ。この値を落とすと、以降の接続を受け取れない。
    pub async fn accept(&mut self) -> Result<H3Handle, String> {
        let connection = self.server.accept().await.map_err(|err| err.to_string())?;
        H3Handle::spawn_server(connection).await
    }
}

/// `addr` のプロキシへ QUIC と HTTP/3 のクライアント接続を張る
///
/// `server_name` は TLS のサーバ名である。`insecure` が真のときは証明書を検証しない。
/// 戻ったあとの UDP ソケットは接続が持つので、この関数の中で作ったクライアント端点はここで捨ててよい。
pub async fn connect(
    addr: SocketAddr,
    server_name: &str,
    insecure: bool,
) -> Result<H3Handle, String> {
    install_crypto();
    let client = Client::builder()
        .with_tls(ClientTlsConfig::new(client_tls(insecure)))
        .with_io(IoConfig::new(loopback_ephemeral()))
        .with_datagram(DatagramConfig::default())
        .start()
        .map_err(|err| err.to_string())?;
    let connection = client
        .connect(Connect::new(addr, server_name))
        .await
        .map_err(|err| err.to_string())?;
    H3Handle::spawn_client(connection).await
}

fn loopback_ephemeral() -> SocketAddr {
    "127.0.0.1:0"
        .parse()
        .expect("127.0.0.1:0 is a valid socket address")
}

fn install_crypto() {
    // 2 回目以降は既に入っているので失敗してよい。
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn client_tls(insecure: bool) -> Arc<rustls::ClientConfig> {
    let mut config = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth()
    };
    config.alpn_protocols = vec![ALPN_H3.to_vec()];
    Arc::new(config)
}

/// サーバー証明書を無条件に受け入れる
///
/// `--insecure` の実験用である。rustls の検証口に差し込むため、このトレイトを実装する。
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
