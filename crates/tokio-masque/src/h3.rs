//! 確立済みの tobi-quic 接続の上で HTTP/3 を駆動する。
//!
//! 制御ストリームは接続が終わるまで開いたままにする (RFC 9114 Section 6.2.1)。
//! HTTP Datagram は `http3-rs` の Quarter Stream ID を付けてから QUIC DATAGRAM に載せる。

use std::collections::HashMap;

use shiguredo_http3::webtransport::Datagram;
use shiguredo_http3::{ClientConnection, Event, H3InitData, Header, ServerConnection, Settings};
use tobi_quic::{Connection, PeerStream, ReceiveStream, SendStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// 駆動タスクへの操作
enum Command {
    /// Extended CONNECT を含むリクエストを送る
    Request {
        /// 疑似ヘッダとヘッダ。名前、値の順
        headers: Vec<(Vec<u8>, Vec<u8>)>,
        /// 割り当てた QUIC ストリーム ID
        reply: oneshot::Sender<Result<u64, String>>,
    },
    /// レスポンスヘッダを送る
    Respond {
        /// リクエストのストリーム ID
        stream_id: u64,
        /// `:status` を含むヘッダ
        headers: Vec<(Vec<u8>, Vec<u8>)>,
        /// 送信結果
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// リクエストストリームへ DATA を書く
    Body {
        /// ストリーム ID
        stream_id: u64,
        /// HTTP/3 DATA の中身。カプセルバイト列
        data: Vec<u8>,
        /// 送信結果
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// HTTP Datagram ペイロードを QUIC DATAGRAM で送る
    Datagram {
        /// CONNECT ストリーム ID。4 の倍数
        stream_id: u64,
        /// Quarter Stream ID を含まないペイロード
        payload: Vec<u8>,
        /// 送信結果
        reply: oneshot::Sender<Result<(), String>>,
    },
}

/// ピアから届いた HTTP/3 の出来事
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3Event {
    /// ピアの SETTINGS
    PeerSettings {
        /// SETTINGS_ENABLE_CONNECT_PROTOCOL
        enable_connect_protocol: Option<bool>,
        /// SETTINGS_H3_DATAGRAM
        h3_datagram: Option<bool>,
    },
    /// ヘッダセクションが終わった
    Headers {
        /// ストリーム ID
        stream_id: u64,
        /// 受信したフィールド
        fields: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// DATA フレームの中身
    Data {
        /// ストリーム ID
        stream_id: u64,
        /// ペイロード
        data: Vec<u8>,
    },
    /// Quarter Stream ID を外した HTTP Datagram ペイロード
    Datagram {
        /// CONNECT ストリーム ID
        stream_id: u64,
        /// HTTP Datagram ペイロード
        payload: Vec<u8>,
    },
    /// 駆動が止まった
    Failed(String),
}

/// ヘッダの名前と値
type HeaderFields = Vec<(Vec<u8>, Vec<u8>)>;

enum Inbound {
    Stream { id: u64, data: Vec<u8>, fin: bool },
    Datagram(Vec<u8>),
    PeerSend { id: u64, send: SendStream },
}

enum Http3 {
    Client(ClientConnection),
    Server(ServerConnection),
}

impl Http3 {
    fn feed(&mut self, id: u64, data: &[u8], fin: bool) -> Result<(), String> {
        match self {
            Self::Client(conn) => conn
                .feed_stream(id, data, fin)
                .map_err(|err| err.to_string()),
            Self::Server(conn) => conn
                .feed_stream(id, data, fin)
                .map_err(|err| err.to_string()),
        }
    }

    fn poll(&mut self) -> Result<Option<Event>, String> {
        match self {
            Self::Client(conn) => conn.poll_event().map_err(|err| err.to_string()),
            Self::Server(conn) => conn.poll_event().map_err(|err| err.to_string()),
        }
    }

    fn take(&mut self, id: u64) -> Option<(Vec<u8>, bool)> {
        match self {
            Self::Client(conn) => conn.take_stream_data(id),
            Self::Server(conn) => conn.take_stream_data(id),
        }
    }

    fn request(&mut self, headers: &[Header]) -> Result<u64, String> {
        match self {
            Self::Client(conn) => conn
                .send_request(headers, false)
                .map_err(|err| err.to_string()),
            Self::Server(_) => Err("server cannot send a request".to_string()),
        }
    }

    fn respond(&mut self, id: u64, headers: &[Header]) -> Result<(), String> {
        match self {
            Self::Server(conn) => conn
                .send_response(id, headers, false)
                .map_err(|err| err.to_string()),
            Self::Client(_) => Err("client cannot send a response".to_string()),
        }
    }

    fn body(&mut self, id: u64, data: &[u8]) -> Result<(), String> {
        match self {
            Self::Client(conn) => conn
                .send_body(id, data, false)
                .map_err(|err| err.to_string()),
            Self::Server(conn) => conn
                .send_body(id, data, false)
                .map_err(|err| err.to_string()),
        }
    }
}

/// 1 本の QUIC 接続上の HTTP/3
pub struct H3Handle {
    commands: mpsc::Sender<Command>,
    events: mpsc::UnboundedReceiver<H3Event>,
    task: JoinHandle<()>,
}

impl Drop for H3Handle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl H3Handle {
    /// クライアント側の HTTP/3 を駆動する
    ///
    /// `connection` はハンドシェイク済みで、DATAGRAM が有効であること。
    pub async fn spawn_client(connection: Connection) -> Result<Self, String> {
        Self::spawn(connection, true).await
    }

    /// サーバー側の HTTP/3 を駆動する
    pub async fn spawn_server(connection: Connection) -> Result<Self, String> {
        Self::spawn(connection, false).await
    }

    /// CONNECT リクエストを送り、ストリーム ID を返す
    pub async fn request(&self, headers: Vec<(Vec<u8>, Vec<u8>)>) -> Result<u64, String> {
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command::Request { headers, reply })
            .await
            .map_err(|_| "h3 driver stopped".to_string())?;
        rx.await.map_err(|_| "h3 driver stopped".to_string())?
    }

    /// レスポンスヘッダを送る
    pub async fn respond(
        &self,
        stream_id: u64,
        headers: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command::Respond {
                stream_id,
                headers,
                reply,
            })
            .await
            .map_err(|_| "h3 driver stopped".to_string())?;
        rx.await.map_err(|_| "h3 driver stopped".to_string())?
    }

    /// ストリームへカプセル列を書く
    pub async fn send_body(&self, stream_id: u64, data: Vec<u8>) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command::Body {
                stream_id,
                data,
                reply,
            })
            .await
            .map_err(|_| "h3 driver stopped".to_string())?;
        rx.await.map_err(|_| "h3 driver stopped".to_string())?
    }

    /// HTTP Datagram ペイロードを送る
    pub async fn send_datagram(&self, stream_id: u64, payload: Vec<u8>) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command::Datagram {
                stream_id,
                payload,
                reply,
            })
            .await
            .map_err(|_| "h3 driver stopped".to_string())?;
        rx.await.map_err(|_| "h3 driver stopped".to_string())?
    }

    /// 次のイベント。駆動が終わったら `None`
    pub async fn recv(&mut self) -> Option<H3Event> {
        self.events.recv().await
    }

    async fn spawn(connection: Connection, client: bool) -> Result<Self, String> {
        connection
            .enable_background_driver()
            .await
            .map_err(|err| err.to_string())?;
        let (commands_tx, commands_rx) = mpsc::channel(16);
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            if let Err(err) = drive(connection, client, commands_rx, events_tx.clone()).await {
                let _ = events_tx.send(H3Event::Failed(err));
            }
        });
        Ok(Self {
            commands: commands_tx,
            events: events_rx,
            task,
        })
    }
}

async fn drive(
    connection: Connection,
    client: bool,
    mut commands: mpsc::Receiver<Command>,
    events: mpsc::UnboundedSender<H3Event>,
) -> Result<(), String> {
    let settings = Settings::new()
        .h3_datagram(true)
        .enable_connect_protocol(true);
    let mut http = if client {
        Http3::Client(ClientConnection::new(settings))
    } else {
        Http3::Server(ServerConnection::new(settings))
    };
    let mut sends = HashMap::new();
    // 単方向ストリームを閉じると相手が H3_CLOSED_CRITICAL_STREAM で接続を切る。
    let mut critical = Vec::new();
    open_unidirectional(&connection, &mut http, &mut critical).await?;

    let (inbound_tx, mut inbound) = mpsc::channel(64);
    tokio::spawn(accept_streams(connection.clone(), inbound_tx.clone()));
    tokio::spawn(read_datagrams(connection.clone(), inbound_tx.clone()));

    let mut headers: HashMap<u64, HeaderFields> = HashMap::new();
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { return Ok(()) };
                match command {
                    Command::Request { headers: fields, reply } => {
                        let result = send_request(
                            &connection,
                            &mut http,
                            &mut sends,
                            inbound_tx.clone(),
                            fields,
                        )
                        .await;
                        let _ = reply.send(result);
                    }
                    Command::Respond { stream_id, headers: fields, reply } => {
                        let result = send_response(&mut http, &mut sends, stream_id, fields).await;
                        let _ = reply.send(result);
                    }
                    Command::Body { stream_id, data, reply } => {
                        let result = send_body(&mut http, &mut sends, stream_id, &data).await;
                        let _ = reply.send(result);
                    }
                    Command::Datagram { stream_id, payload, reply } => {
                        let result = send_datagram(&connection, stream_id, payload).await;
                        let _ = reply.send(result);
                    }
                }
                publish(&mut http, &mut headers, &events)?;
                drain_output(&mut http, &mut sends).await?;
            }
            incoming = inbound.recv() => {
                let Some(incoming) = incoming else { return Ok(()) };
                match incoming {
                    Inbound::PeerSend { id, send } => {
                        sends.insert(id, send);
                    }
                    Inbound::Stream { id, data, fin } => {
                        http.feed(id, &data, fin)?;
                        publish(&mut http, &mut headers, &events)?;
                        drain_output(&mut http, &mut sends).await?;
                    }
                    Inbound::Datagram(bytes) => {
                        if let Ok((datagram, _)) = Datagram::decode(&bytes) {
                            let _ = events.send(H3Event::Datagram {
                                stream_id: datagram.session_id,
                                payload: datagram.payload,
                            });
                        }
                    }
                }
            }
        }
    }
}

async fn open_unidirectional(
    connection: &Connection,
    http: &mut Http3,
    critical: &mut Vec<SendStream>,
) -> Result<(), String> {
    let control = connection
        .open_send_stream()
        .await
        .map_err(|err| err.to_string())?;
    let encoder = connection
        .open_send_stream()
        .await
        .map_err(|err| err.to_string())?;
    let decoder = connection
        .open_send_stream()
        .await
        .map_err(|err| err.to_string())?;
    let init: H3InitData = match http {
        Http3::Client(conn) => conn
            .init_h3_streams(control.id(), encoder.id(), decoder.id())
            .map_err(|err| err.to_string())?,
        Http3::Server(conn) => conn
            .init_h3_streams(control.id(), encoder.id(), decoder.id())
            .map_err(|err| err.to_string())?,
    };
    let mut control = control;
    let mut encoder = encoder;
    let mut decoder = decoder;
    control
        .send_all(&init.control_data)
        .await
        .map_err(|err| err.to_string())?;
    encoder
        .send_all(&init.encoder_data)
        .await
        .map_err(|err| err.to_string())?;
    decoder
        .send_all(&init.decoder_data)
        .await
        .map_err(|err| err.to_string())?;
    // クリティカルストリームは接続の終わりまでドロップしない。
    critical.push(control);
    critical.push(encoder);
    critical.push(decoder);
    Ok(())
}

async fn accept_streams(connection: Connection, inbound: mpsc::Sender<Inbound>) {
    loop {
        let accepted = match connection.accept_stream().await {
            Ok(stream) => stream,
            Err(_) => return,
        };
        match accepted {
            PeerStream::Receive(stream) => {
                let tx = inbound.clone();
                tokio::spawn(read_stream(stream, tx));
            }
            PeerStream::Bidirectional(stream) => {
                let id = stream.id();
                let (send, recv) = stream.split();
                if inbound.send(Inbound::PeerSend { id, send }).await.is_err() {
                    return;
                }
                let tx = inbound.clone();
                tokio::spawn(read_stream(recv, tx));
            }
        }
    }
}

async fn read_stream(mut stream: ReceiveStream, inbound: mpsc::Sender<Inbound>) {
    let id = stream.id();
    loop {
        match stream.receive_vec(16 * 1024).await {
            Ok(chunk) => {
                let fin = chunk.fin;
                if inbound
                    .send(Inbound::Stream {
                        id,
                        data: chunk.data,
                        fin,
                    })
                    .await
                    .is_err()
                {
                    return;
                }
                if fin {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

async fn read_datagrams(connection: Connection, inbound: mpsc::Sender<Inbound>) {
    loop {
        match connection.receive_datagram().await {
            Ok(bytes) => {
                if inbound.send(Inbound::Datagram(bytes)).await.is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

async fn send_request(
    connection: &Connection,
    http: &mut Http3,
    sends: &mut HashMap<u64, SendStream>,
    inbound: mpsc::Sender<Inbound>,
    fields: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<u64, String> {
    let stream = connection
        .open_bidirectional_stream()
        .await
        .map_err(|err| err.to_string())?;
    let id = stream.id();
    let (send, recv) = stream.split();
    sends.insert(id, send);
    // 自分で開いた双方向ストリームは accept では届かない。ここで読む。
    tokio::spawn(read_stream(recv, inbound));
    let headers = fields_to_headers(fields)?;
    let http_id = http.request(&headers)?;
    if http_id != id {
        return Err(format!(
            "http3 stream id {http_id} does not match quic stream id {id}"
        ));
    }
    Ok(id)
}

fn fields_to_headers(fields: Vec<(Vec<u8>, Vec<u8>)>) -> Result<Vec<Header>, String> {
    let mut headers = Vec::new();
    for (name, value) in fields {
        headers.push(Header::new(&name, &value).map_err(|err| err.to_string())?);
    }
    Ok(headers)
}

async fn send_response(
    http: &mut Http3,
    sends: &mut HashMap<u64, SendStream>,
    stream_id: u64,
    fields: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<(), String> {
    if !sends.contains_key(&stream_id) {
        return Err(format!("no send stream for {stream_id}"));
    }
    let headers = fields_to_headers(fields)?;
    http.respond(stream_id, &headers)
}

async fn send_body(
    http: &mut Http3,
    sends: &mut HashMap<u64, SendStream>,
    stream_id: u64,
    data: &[u8],
) -> Result<(), String> {
    if !sends.contains_key(&stream_id) {
        return Err(format!("no send stream for {stream_id}"));
    }
    http.body(stream_id, data)
}

async fn send_datagram(
    connection: &Connection,
    stream_id: u64,
    payload: Vec<u8>,
) -> Result<(), String> {
    let datagram = Datagram::new(stream_id, payload).map_err(|err| format!("{err:?}"))?;
    let mut bytes = Vec::new();
    datagram.encode(&mut bytes);
    connection
        .send_datagram(bytes)
        .await
        .map_err(|err| err.to_string())
}

fn publish(
    http: &mut Http3,
    headers: &mut HashMap<u64, HeaderFields>,
    events: &mpsc::UnboundedSender<H3Event>,
) -> Result<(), String> {
    while let Some(event) = http.poll()? {
        match event {
            Event::SettingsReceived { settings, .. } => {
                let _ = events.send(H3Event::PeerSettings {
                    enable_connect_protocol: settings.enable_connect_protocol,
                    h3_datagram: settings.h3_datagram,
                });
            }
            Event::Header {
                stream_id,
                name,
                value,
            } => {
                headers.entry(stream_id).or_default().push((name, value));
            }
            Event::HeadersEnd { stream_id } => {
                let fields = headers.remove(&stream_id).unwrap_or_default();
                let _ = events.send(H3Event::Headers { stream_id, fields });
            }
            Event::Data { stream_id, data } => {
                let _ = events.send(H3Event::Data { stream_id, data });
            }
            _ => {}
        }
    }
    Ok(())
}

async fn drain_output(
    http: &mut Http3,
    sends: &mut HashMap<u64, SendStream>,
) -> Result<(), String> {
    let ids: Vec<u64> = sends.keys().copied().collect();
    for id in ids {
        while let Some((data, fin)) = http.take(id) {
            if data.is_empty() && !fin {
                break;
            }
            let Some(send) = sends.get_mut(&id) else {
                break;
            };
            if !data.is_empty() {
                send.send_all(&data).await.map_err(|err| err.to_string())?;
            }
            if fin {
                send.finish().await.map_err(|err| err.to_string())?;
                break;
            }
        }
    }
    Ok(())
}
