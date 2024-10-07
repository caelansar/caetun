use crate::device::{Device, DeviceConfig};
use clap::Parser;
use std::io;
use std::net::SocketAddr;
use tracing::level_filters::LevelFilter;
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
    peer: Option<String>,
}

fn run(peer_addr: Option<&str>) -> io::Result<()> {
    let peer = peer_addr
        .and_then(|addr| addr.parse::<SocketAddr>().ok())
        .and_then(|addr| {
            if let SocketAddr::V4(addr) = addr {
                Some(addr)
            } else {
                None
            }
        });

    let dev = Device::new(DeviceConfig::new("tun0", 19988, peer))?;

    dev.start()?;
    dev.wait();

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let layer = Layer::new()
        .event_format(tracing_subscriber::fmt::format().with_source_location(true))
        .with_filter(LevelFilter::DEBUG);
    tracing_subscriber::registry().with(layer).init();

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

    run(args.peer.as_deref())?;

    Ok(())
}
