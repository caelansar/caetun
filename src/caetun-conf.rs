use caetun::conf::Conf;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[arg(long, short)]
    conf: PathBuf,

    #[arg(long, short)]
    pretty: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let conf = std::fs::read_to_string(&args.conf)?;
    let conf = Conf::parse_from(&conf)?;

    let json = if args.pretty {
        serde_json::to_string_pretty(&conf)?
    } else {
        serde_json::to_string(&conf)?
    };

    println!("{json}");

    Ok(())
}
