use crate::device::{new_udp_socket, Endpoint};
use parking_lot::{RwLock, RwLockReadGuard};
use std::io;
use std::net::{SocketAddrV4, UdpSocket};
use std::sync::Arc;

pub struct Peer {
    endpoint: RwLock<Endpoint>,
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
