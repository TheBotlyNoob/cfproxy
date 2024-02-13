use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use boringtun::{
    noise::{Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use color_eyre::eyre::{eyre, Result};
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;
use url::Url;

const PRIV_KEY: &str = "gJh9TfAy2MugDBzHqUQoe2XB05qaqi+N9JQRpndeO0E=";
const PUB_KEY: &str = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
const ENDPOINT: &str = "engage.cloudflareclient.com:2408";

/// gets gradually incremented if fails.
const DEFAULT_PORT: u16 = 51820;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let endpoint = Url::parse(ENDPOINT)?;
    let endpoint_port = endpoint
        .port()
        .unwrap_or_else(|| endpoint.path().parse().unwrap_or(51820));
    let endpoint_host = endpoint.host_str().unwrap_or_else(|| endpoint.scheme());

    let resolver =
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default());

    let ip = resolver
        .lookup_ip(endpoint_host)
        .await?
        .iter()
        .next()
        .ok_or_else(|| eyre!("DNS request failed; no IP found for endpoint."))?;

    dbg!((ip, endpoint_port));

    // now the real shit happens

    let priv_key: [u8; 32] = BASE64
        .decode(PRIV_KEY)?
        .try_into()
        .map_err(|_| eyre!("invalid private key"))?;
    let pub_key: [u8; 32] = BASE64
        .decode(PUB_KEY)?
        .try_into()
        .map_err(|_| eyre!("invalid public key"))?;

    let priv_key = StaticSecret::from(priv_key);
    let pub_key = PublicKey::from(pub_key);

    let mut bind_port = DEFAULT_PORT;
    let socket = loop {
        match UdpSocket::bind((Ipv4Addr::new(0, 0, 0, 0), bind_port)).await {
            Ok(s) => break s,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => bind_port += 1,
            Err(e) => return Err(e.into()),
        };
    };

    socket.connect((ip, endpoint_port)).await?;

    let mut tunn = Tunn::new(priv_key, pub_key, None, None, 0, None).map_err(|e| eyre!("{e}"))?;

    const BUF_SIZE: usize = 1024;

    let mut recv_buf = Vec::with_capacity(BUF_SIZE);
    let mut send_buf = Vec::with_capacity(BUF_SIZE);
    loop {
        let recvd = socket.recv_buf(&mut recv_buf).await?;
        match dbg!(tunn.decapsulate(None, &recv_buf[0..recvd], &mut send_buf)) {
            TunnResult::Done => {}
            TunnResult::WriteToNetwork(bytes) => {
                socket.send(bytes).await?;
            }
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => unreachable!(),
            TunnResult::Err(e) => return Err(eyre!("wireguard error: {e:#?}")),
        };
    }
}
