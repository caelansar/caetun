use std::io;
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};

use tun_tap::Iface;

use parking_lot::{Mutex, MutexGuard};
use socket2::{Domain, Protocol, Socket, Type};

pub struct Peer {
    endpoint: Mutex<Option<SocketAddrV4>>,
}

pub struct Device {
    udp: UdpSocket,
    iface: Iface,
    peer: Peer,
}

fn new_udp_socket(port: u16) -> io::Result<UdpSocket> {
    let socket_addr = SocketAddr::from(([0, 0, 0, 0], port));

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;

    socket.bind(&socket_addr.into())?;

    Ok(socket.into())
}

impl Device {
    pub fn new(iface: Iface, peer: Option<SocketAddrV4>) -> Self {
        // start listening udp
        let udp = new_udp_socket(19988).unwrap();
        Self {
            udp,
            iface,
            peer: Peer {
                endpoint: Mutex::new(peer),
            },
        }
    }

    pub fn loop_listen_iface(&self) -> io::Result<()> {
        // handshake
        {
            let peer = self.peer.endpoint();

            if let Some(peer_addr) = peer.as_ref() {
                eprintln!("initiating \"handshake\" to peer: {peer_addr}");

                self.udp.send_to("hello?".as_bytes(), peer_addr)?;
            }
        }

        // a large enough buffer, the MTU on iface was to be set to 1472
        let mut buf = [0u8; 1504];

        loop {
            let nbytes = self.iface.recv(&mut buf[..])?;
            match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
                Ok(iph) => {
                    let src = iph.source_addr();
                    let dst = iph.destination_addr();
                    eprintln!("got Ipv4 packet of size: {nbytes}, {src} -> {dst}, from tun0");
                }
                Err(e) => {
                    eprintln!("failed to parse packet header: {:?}", e)
                }
            }
            let peer = self.peer.endpoint();
            if let Some(peer_addr) = peer.as_ref() {
                self.udp.send_to(&buf[..nbytes], peer_addr)?;
            } else {
                eprintln!("..no peer");
            }
        }
    }

    pub fn loop_listen_udp(&self) -> io::Result<()> {
        let mut buf = [0u8; 1504];

        loop {
            let (nbytes, peer_addr) = self.udp.recv_from(&mut buf[..])?;
            eprintln!("got packet of size: {nbytes}, from {peer_addr}");

            match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
                Ok(iph) => {
                    let src = iph.source_addr();
                    let dst = iph.destination_addr();
                    eprintln!("  {src} -> {dst}");
                }
                _ => {
                    eprintln!("not an Ipv4 packet");
                }
            }

            if let SocketAddr::V4(peer_addr_v4) = peer_addr {
                if &buf[..nbytes] == b"hello?" {
                    eprintln!("received handshake");
                    self.peer.set_endpoint(peer_addr_v4);
                    continue;
                }
                self.iface.send(&buf[..nbytes])?;
            }
        }
    }
}

impl Peer {
    fn endpoint(&self) -> MutexGuard<Option<SocketAddrV4>> {
        self.endpoint.lock()
    }

    fn set_endpoint(&self, addr: SocketAddrV4) {
        let mut endpoint = self.endpoint.lock();

        if endpoint.is_none() {
            *endpoint = Some(addr);
        }
    }
}
