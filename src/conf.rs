use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;

use ip_network::IpNetworkParseError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum ConfError {
    #[error("invalid ini: {0}")]
    Ini(#[from] serde_ini::de::Error),

    #[error("invalid cidr address: {0}")]
    IpFormat(String),

    #[error("invalid cidr notation: {0}")]
    IpNetworkParseError(#[from] IpNetworkParseError),

    #[error("multiple interface definition")]
    ExtraInterface,

    #[error("missing interface definition")]
    MissingInterface,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Conf {
    pub interface: InterfaceConf,
    pub peers: Vec<PeerConf>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InterfaceConf {
    pub name: String,
    pub address: (Ipv4Addr, u8),
    pub listen_port: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PeerConf {
    pub name: String,
    pub endpoint: Option<SocketAddrV4>,
    pub allowed_ips: Vec<(Ipv4Addr, u8)>,
}

impl Conf {
    pub const DEFAULT_LISTEN_PORT: u16 = 19988;

    pub fn parse_from(source: &str) -> Result<Self, ConfError> {
        let sections: Vec<Section> = serde_ini::from_str(source)?;

        let mut interface = None;
        let mut peers = vec![];

        for section in sections.into_iter() {
            match section {
                Section::Peer {
                    Name,
                    Endpoint,
                    AllowedIPs,
                } => {
                    let allowed_ips: Result<Vec<_>, _> = AllowedIPs
                        .as_deref()
                        .unwrap_or("")
                        .split(',')
                        .filter_map(|allowed_ip| Some(allowed_ip.trim()).filter(|s| !s.is_empty()))
                        .map(|allowed_ip| -> Result<_, IpNetworkParseError> {
                            let ipn = ip_network::Ipv4Network::from_str_truncate(allowed_ip)?;
                            Ok((ipn.network_address(), ipn.netmask()))
                        })
                        .collect();
                    let endpoint = Endpoint.and_then(|ep| SocketAddrV4::from_str(&ep).ok());
                    let peer = PeerConf {
                        name: Name,
                        allowed_ips: allowed_ips?,
                        endpoint,
                    };
                    peers.push(peer);
                }
                Section::Interface {
                    Name,
                    Address,
                    ListenPort,
                } => {
                    if interface.is_none() {
                        let address = parse_cidr(Address.trim())?;
                        interface = Some(InterfaceConf {
                            name: Name,
                            address,
                            listen_port: ListenPort.unwrap_or(Self::DEFAULT_LISTEN_PORT),
                        });
                    } else {
                        return Err(ConfError::ExtraInterface);
                    }
                }
            }
        }
        if let Some(interface) = interface {
            Ok(Conf { interface, peers })
        } else {
            Err(ConfError::MissingInterface)
        }
    }
}

fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), ConfError> {
    let (ip_str, subnet_str) = cidr
        .split_once('/')
        .ok_or_else(|| ConfError::IpFormat("Invalid CIDR format: {cidr}".to_string()))?;

    let ip = ip_str
        .parse::<Ipv4Addr>()
        .map_err(|_| ConfError::IpFormat("Invalid IP address: {cidr}".to_string()))?;

    let subnet = subnet_str
        .parse::<u8>()
        .map_err(|_| ConfError::IpFormat("Invalid subnet mask: {cidr}".to_string()))?;

    if subnet > 32 {
        return Err(ConfError::IpFormat(
            "Subnet mask must be in the range 0-32: {cidr}".to_string(),
        ));
    }

    Ok((ip, subnet))
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[allow(non_snake_case)]
pub enum Section {
    Interface {
        Name: String,
        Address: String,
        ListenPort: Option<u16>,
    },
    Peer {
        Name: String,
        Endpoint: Option<String>,
        AllowedIPs: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let input = r#"
[Interface]
Name=server
Address=192.0.2.2/24
ListenPort=19988

[Peer]
Name=client1

[Peer]
Name=client2
AllowedIPs=192.0.2.1/24
"#;

        let conf = Conf::parse_from(input).unwrap();
        assert_eq!(
            Conf {
                interface: InterfaceConf {
                    name: "server".into(),
                    address: (Ipv4Addr::from([192, 0, 2, 2]), 24),
                    listen_port: 19988
                },
                peers: vec![
                    PeerConf {
                        name: "client1".into(),
                        endpoint: None,
                        allowed_ips: vec![],
                    },
                    PeerConf {
                        name: "client2".into(),
                        endpoint: None,
                        allowed_ips: vec![(Ipv4Addr::from([192, 0, 2, 0]), 24)],
                    }
                ],
            },
            conf
        );
    }
}
