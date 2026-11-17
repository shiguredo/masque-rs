//! `masque proxy` で待ち受け、`masque client` で接続する。

use std::net::{Ipv4Addr, SocketAddr};

fn main() -> noargs::Result<()> {
    let command = parse()?;
    let Some(command) = command else {
        return Ok(());
    };
    init_tracing();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(dispatch(command))?;
    Ok(())
}

enum Command {
    Proxy {
        listen: SocketAddr,
    },
    Client {
        proxy: SocketAddr,
        insecure: bool,
        to: Option<Ipv4Addr>,
        payload: String,
        tun: bool,
    },
}

fn parse() -> noargs::Result<Option<Command>> {
    let mut args = noargs::raw_args();
    args.metadata_mut().app_name = env!("CARGO_PKG_NAME");
    args.metadata_mut().app_description = env!("CARGO_PKG_DESCRIPTION");

    if noargs::VERSION_FLAG.take(&mut args).is_present() {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(None);
    }
    noargs::HELP_FLAG.take_help(&mut args);

    let command = if noargs::cmd("proxy")
        .doc("Listen for CONNECT-IP and forward IP packets between clients")
        .take(&mut args)
        .is_present()
    {
        let listen = noargs::opt("listen")
            .short('l')
            .ty("ADDR")
            .default("127.0.0.1:4443")
            .doc("UDP address to bind")
            .take(&mut args)
            .then(|opt| opt.value().parse())?;
        Some(Command::Proxy { listen })
    } else if noargs::cmd("client")
        .doc("Connect to a proxy, print the assigned address, and exchange a test packet")
        .take(&mut args)
        .is_present()
    {
        let proxy = noargs::opt("proxy")
            .short('p')
            .ty("URL")
            .default("https://127.0.0.1:4443/")
            .doc("Proxy URL (https://host:port/) or host:port")
            .take(&mut args)
            .then(|opt| parse_proxy(opt.value()))?;
        let insecure = noargs::flag("insecure")
            .short('k')
            .doc("Skip TLS certificate verification")
            .take(&mut args)
            .is_present();
        let to = noargs::opt("to")
            .short('t')
            .ty("ADDR")
            .doc("Send one test packet to this IPv4 address and print the reply")
            .take(&mut args)
            .present_and_then(|opt| opt.value().parse())?;
        let payload = noargs::opt("payload")
            .ty("TEXT")
            .default("ping")
            .doc("Payload of the test packet")
            .take(&mut args)
            .then(|opt| opt.value().parse())?;
        let tun = noargs::flag("tun")
            .doc("Create a TUN interface and bridge IP packets to the tunnel")
            .take(&mut args)
            .is_present();
        Some(Command::Client {
            proxy,
            insecure,
            to,
            payload,
            tun,
        })
    } else {
        None
    };

    if let Some(help) = args.finish()? {
        print!("{help}");
        return Ok(None);
    }
    if let Some(Command::Client {
        tun: true,
        to: Some(_),
        ..
    }) = &command
    {
        return Err("--tun and --to cannot be used together".into());
    }
    Ok(command)
}

fn parse_proxy(value: &str) -> Result<SocketAddr, String> {
    let without_scheme = value.strip_prefix("https://").unwrap_or(value);
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    if host_port.is_empty() {
        return Err(format!("empty proxy address: {value}"));
    }
    host_port
        .parse()
        .map_err(|_| format!("proxy address must be host:port or https://host:port/: {value}"))
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn dispatch(command: Command) -> Result<(), String> {
    match command {
        Command::Proxy { listen } => {
            let proxy = masque::proxy::Proxy::bind(listen)?;
            masque::proxy::serve(proxy).await
        }
        Command::Client {
            proxy,
            insecure,
            to,
            payload,
            tun,
        } => masque::client::run(proxy, insecure, to, payload.as_bytes(), tun).await,
    }
}
