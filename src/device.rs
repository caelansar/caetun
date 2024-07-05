use std::io;
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::Arc;
use tun_tap::Iface;

use crate::peer::Peer;
use crate::poll::{Poll, SockID, Token};
use socket2::{Domain, Protocol, Socket, Type};

const HANDSHAKE: &str = "hello?";

pub struct Device {
    udp: Arc<UdpSocket>,
    iface: Iface,
    peer: Peer,
    poll: Poll,
    use_connected_peer: bool,
    listen_port: u16,
}

#[derive(Default)]
pub struct Endpoint {
    pub addr: Option<SocketAddrV4>,
    pub conn: Option<Arc<UdpSocket>>,
}

pub struct DeviceConfig<'a> {
    listen_port: u16,
    tun_name: &'a str,
    peer_addr: Option<SocketAddrV4>,
}

impl<'a> DeviceConfig<'a> {
    pub fn new(tun_name: &'a str, listen_port: u16, peer_addr: Option<SocketAddrV4>) -> Self {
        Self {
            tun_name,
            listen_port,
            peer_addr,
        }
    }
}

pub fn new_udp_socket(port: u16) -> io::Result<UdpSocket> {
    let socket_addr = SocketAddr::from(([0, 0, 0, 0], port));

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    socket.bind(&socket_addr.into())?;

    Ok(socket.into())
}

impl Device {
    pub fn new(config: DeviceConfig) -> io::Result<Self> {
        let iface = tun_tap::Iface::without_packet_info(config.tun_name, tun_tap::Mode::Tun)?;
        iface.set_non_blocking()?;

        let poll = Poll::new()?;
        let peer = Peer::new(Endpoint::default());
        let udp = if let Some(addr) = config.peer_addr {
            peer.set_endpoint(addr);
            peer.connect_endpoint(config.listen_port)?
        } else {
            Arc::new(new_udp_socket(config.listen_port)?)
        };

        Ok(Self {
            udp,
            iface,
            peer,
            poll,
            use_connected_peer: config.peer_addr.is_some(),
            listen_port: config.listen_port,
        })
    }

    pub fn wait(&self) {
        let mut buf = [0u8; 1504];

        // there will be three IO resources in this loop
        //
        // 1. the tun interface
        // 2. a bind-only UdpSocket to handle the initial client handshake
        // 3. a connected peer UdpSocket to transmit subsequent data packets over
        while let Ok(token) = self.poll.wait() {
            match token {
                Token::Tun => {
                    eprintln!("handle Token::Tun");
                    if let Err(err) = self.handle_tun(&mut buf) {
                        eprintln!("tun error: {:?}", err);
                    }
                }
                Token::Sock(SockID::UnConnected) => {
                    eprintln!("handle Token::Sock(SockID::BindOnly)");
                    if let Err(err) = self.handle_udp(&mut buf) {
                        eprintln!("udp error: {:?}", err);
                    }
                }
                Token::Sock(SockID::Connected) => {
                    eprintln!("handle Token::Sock(SockID::ConnectedPeer)");
                    if let Some(conn) = self.peer.endpoint().conn.as_deref() {
                        if let Err(err) = self.handle_connected_peer(conn, &mut buf) {
                            eprintln!("udp error: {:?}", err);
                        }
                    }
                }
            }
        }
    }

    pub fn start(&self) -> io::Result<()> {
        eprintln!("start caetun");

        let tun = unsafe { BorrowedFd::borrow_raw(self.iface.as_raw_fd()) };

        self.poll
            .register_read(Token::Sock(SockID::UnConnected), self.udp.as_ref())?;
        self.poll.register_read::<_, SockID>(Token::Tun, &tun)?;

        self.initiate_handshake()
    }

    fn initiate_handshake(&self) -> io::Result<()> {
        let msg = HANDSHAKE.as_bytes();

        let endpoint = self.peer.endpoint();

        match (&endpoint.conn, endpoint.addr) {
            ((Some(conn), _)) => {
                eprintln!("[handshake] initiating handshake using conn..");

                conn.send(msg)?;
            }
            ((_, Some(addr))) => {
                eprintln!("[handshake] initiating handshake using addr..");

                self.udp.send_to(msg, addr)?;
            }
            _ => {
                eprintln!("[handshake] both conn and addr is absent");
            }
        }

        Ok(())
    }

    // Handle incoming data from tun interface
    pub fn handle_tun(&self, buf: &mut [u8]) -> io::Result<()> {
        while let Ok(n) = self.iface.recv(buf) {
            match etherparse::Ipv4HeaderSlice::from_slice(&buf[..n]) {
                Ok(h) => {
                    let src = h.source_addr();
                    let dst = h.destination_addr();
                    eprintln!(
                        "got Ipv4 packet of size: {n}, {src} -> {dst}, from {}",
                        self.iface.name()
                    );
                }
                Err(e) => {
                    eprintln!("not an Ipv4 packet: {:?}", e);
                    continue;
                }
            }
            let endpoint = self.peer.endpoint();

            // if peer is "connected", we prefer to send data over the connected UdpSocket.
            // otherwise, we will use the main listening socket self.udp and a send_to call.
            let send_bytes = match (&endpoint.conn, endpoint.addr) {
                (Some(conn), _) => conn.send(&buf[..n])?,
                (_, Some(addr)) => self.udp.send_to(&buf[..n], addr)?,
                _ => 0,
            };
            eprintln!("[handle_tun] send {send_bytes} bytes")
        }

        Ok(())
    }

    // Handle incoming data from an unconnected UdpSocket
    pub fn handle_udp(&self, buf: &mut [u8]) -> io::Result<()> {
        while let Ok((n, addr)) = self.udp.recv_from(buf) {
            eprintln!("got packet of size: {n}, from {addr}");

            match etherparse::Ipv4HeaderSlice::from_slice(&buf[..n]) {
                Ok(iph) => {
                    let src = iph.source_addr();
                    let dst = iph.destination_addr();
                    eprintln!("{src} -> {dst}");
                }
                Err(e) => {
                    eprintln!("not an Ipv4 packet: {:?}", e);
                    continue;
                }
            }

            if let SocketAddr::V4(addr_v4) = addr {
                // handle our handshake packet
                if &buf[..n] == HANDSHAKE.as_bytes() {
                    eprintln!("received handshake..");

                    let (endpoint_changed, conn) = self.peer.set_endpoint(addr_v4);
                    if let Some(conn) = conn {
                        self.poll.delete(conn.as_ref()).expect("poll delete");
                        drop(conn);
                    }

                    if endpoint_changed && self.use_connected_peer {
                        // once a client peer handshakes to the server, we shall open a new UdpSocket
                        // and connect it to the client’s public ip address and port.
                        match self.peer.connect_endpoint(self.listen_port) {
                            Ok(conn) => {
                                self.poll
                                    .register_read(Token::Sock(SockID::Connected), &*conn)
                                    .expect("poll register_read");
                            }
                            Err(err) => {
                                eprintln!("error connecting to peer: {:?}", err);
                            }
                        }
                    }
                    continue;
                }
                let _ = self.iface.send(&buf[..n]);
            }
        }

        Ok(())
    }

    // Handle incoming data from a connected UdpSocket
    pub fn handle_connected_peer(&self, socket: &UdpSocket, buf: &mut [u8]) -> io::Result<()> {
        // since this socket is "connected", so we can recv from it directly
        while let Ok(n) = socket.recv(&mut buf[..]) {
            eprintln!("got packet of size: {n}, from a connected peer");

            match etherparse::Ipv4HeaderSlice::from_slice(&buf[..n]) {
                Ok(iph) => {
                    let src = iph.source_addr();
                    let dst = iph.destination_addr();
                    eprintln!("  {src} -> {dst}");
                }
                _ => {
                    eprintln!("not an Ipv4 packet: {:?}", &buf[..n]);
                }
            }

            let _ = self.iface.send(&buf[..n]);
        }
        Ok(())
    }

    #[deprecated]
    pub fn loop_listen_iface(&self) -> io::Result<()> {
        // handshake
        {
            let peer = self.peer.endpoint();

            if let Some(peer_addr) = peer.addr.as_ref() {
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
            if let Some(peer_addr) = peer.addr.as_ref() {
                self.udp.send_to(&buf[..nbytes], peer_addr)?;
            } else {
                eprintln!("..no peer");
            }
        }
    }

    #[deprecated]
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
