use crate::conf::Conf;
use crate::device::{Device, DeviceConfig};
use crate::peer::{Peer, PeerName};
use anyhow::{bail, Context};
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use tracing::level_filters::LevelFilter;
use tracing::Level;
use tracing_subscriber::{fmt::Layer, layer::SubscriberExt, util::SubscriberInitExt, Layer as _};

mod allowed_ip;
mod conf;
mod device;
mod packet;
mod peer;
mod poll;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    conf: PathBuf,
    #[arg(long)]
    log_level: Option<Level>,
}

fn run(tun_name: &str, conf: Conf) -> anyhow::Result<()> {
    let mut dev = Device::new(DeviceConfig::new(
        PeerName::new(&conf.interface.name)?,
        tun_name,
        conf.interface.listen_port,
        true,
    ))?;

    for peer_conf in &conf.peers {
        let peer_name = PeerName::new(&peer_conf.name)?;
        let mut peer = Peer::default();
        if let Some(endpoint) = peer_conf.endpoint {
            peer.set_endpoint(endpoint);
        }
        for (ip, cidr) in &peer_conf.allowed_ips {
            peer.add_allowed_ip(ip.clone(), *cidr);
        }
        dev.add_peer(peer_name, peer);
    }

    dev.start()?;
    dev.wait();

    Ok(())
}

fn main() -> anyhow::Result<()> {
    println!(
        r#"
                      __
  ____ _____    _____/  |_ __ __  ____
_/ ___\\__  \ _/ __ \   __\  |  \/    \
\  \___ / __ \\  ___/|  | |  |  /   |  \
 \___  >____  /\___  >__| |____/|___|  /
     \/     \/     \/                \/
    "#
    );

    let args = Cli::parse();

    let Some(tun) = args.conf.file_stem().and_then(|s| s.to_str()) else {
        bail!("invalid filename")
    };
    let conf = fs::read_to_string(&args.conf).context("failed to read config")?;
    let conf = Conf::parse_from(&conf)?;

    let layer = Layer::new()
        .event_format(tracing_subscriber::fmt::format().with_source_location(true))
        .with_filter(
            args.log_level
                .map_or(LevelFilter::DEBUG, LevelFilter::from_level),
        );
    tracing_subscriber::registry().with(layer).init();

    run(tun, conf)?;

    Ok(())
}
