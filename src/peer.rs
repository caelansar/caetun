use crate::device::{new_udp_socket, Endpoint};
use parking_lot::{RwLock, RwLockReadGuard};
use std::io;
use std::net::{SocketAddrV4, UdpSocket};
use std::sync::Arc;
use tracing::info;

#[derive(Debug)]
pub struct Peer {
    endpoint: RwLock<Endpoint>,
}

#[derive(Debug, PartialEq)]
pub struct PeerName<T>(T);

impl<'a> From<&'a [u8]> for PeerName<&'a [u8]> {
    fn from(slice: &'a [u8]) -> Self {
        PeerName(slice)
    }
}

impl<'a> PeerName<&'a [u8]> {
    pub fn as_slice(&self) -> &'a [u8] {
        self.0
    }
}

const PEER_NAME_MAX_LEN: usize = 100;

impl PeerName<[u8; PEER_NAME_MAX_LEN]> {
    pub const fn max_len() -> usize {
        PEER_NAME_MAX_LEN
    }

    pub fn new(name: &str) -> Result<Self, String> {
        let mut bytes = [0u8; PEER_NAME_MAX_LEN];
        let name_bytes = name.as_bytes();
        let len = name_bytes.len();

        if len > PEER_NAME_MAX_LEN {
            Err(format!("`{name}` too long"))
        } else {
            bytes[..len].copy_from_slice(name_bytes);
            Ok(PeerName(bytes))
        }
    }

    pub fn as_ref(&self) -> PeerName<&[u8]> {
        PeerName(self.0.as_slice())
    }
}

impl Peer {
    pub fn new(peer: Endpoint) -> Self {
        Self {
            endpoint: RwLock::new(peer),
        }
    }
    pub fn endpoint(&self) -> RwLockReadGuard<Endpoint> {
        self.endpoint.read()
    }

    // updates the peer endpoint address, and returns if it had a different address
    // and a previous connected UdpSocket
    pub fn set_endpoint(&self, addr: SocketAddrV4) -> (bool, Option<Arc<UdpSocket>>) {
        let endpoint = self.endpoint.read();

        if endpoint.addr.is_some_and(|a| a == addr) {
            return (false, None);
        }
        drop(endpoint);

        let mut endpoint = self.endpoint.write();
        endpoint.addr = Some(addr);

        (true, endpoint.conn.take())
    }

    pub fn connect_endpoint(&self, port: u16) -> io::Result<Arc<UdpSocket>> {
        info!("[peer] connect endpoint, peer: {:?}", self);

        let mut endpoint = self.endpoint.write();
        let addr = endpoint.addr.expect("addr must not be None");

        assert!(endpoint.conn.is_none());

        let conn = new_udp_socket(port)?;
        // connect to peer
        conn.connect(addr)?;

        let conn = Arc::new(conn);
        endpoint.conn = Some(conn.clone());

        Ok(conn)
    }
}
