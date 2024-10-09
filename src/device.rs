use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::Arc;
use tun_tap::Iface;

use crate::allowed_ip::AllowedIps;
use crate::packet::Packet;
use crate::peer::{Action, Peer, PeerName};
use crate::poll::{Poll, SockID, Token};
use socket2::{Domain, Protocol, Socket, Type};
use tracing::{debug, error, info, instrument, warn};

const BUF_SIZE: usize = 1504;

pub struct Device {
    name: PeerName,
    udp: Arc<UdpSocket>,
    iface: Iface,
    peers_by_name: HashMap<PeerName, Arc<Peer>>,
    peers_by_idx: Vec<Arc<Peer>>,
    peers_by_ip: AllowedIps<Arc<Peer>>,
    poll: Poll,
    use_connected_peer: bool,
    listen_port: u16,
}

#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddrV4>,
    pub conn: Option<Arc<UdpSocket>>,
}

pub struct DeviceConfig<'a> {
    name: PeerName,
    use_connected_peer: bool,
    listen_port: u16,
    tun_name: &'a str,
}

impl<'a> DeviceConfig<'a> {
    pub fn new(
        name: PeerName,
        tun_name: &'a str,
        listen_port: u16,
        use_connected_peer: bool,
    ) -> Self {
        Self {
            name,
            tun_name,
            listen_port,
            use_connected_peer,
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

        let udp = Arc::new(new_udp_socket(config.listen_port)?);

        Ok(Self {
            name: config.name,
            udp,
            iface,
            peers_by_name: HashMap::new(),
            peers_by_idx: Vec::new(),
            peers_by_ip: AllowedIps::new(),
            poll,
            use_connected_peer: config.use_connected_peer,
            listen_port: config.listen_port,
        })
    }

    pub fn add_peer(&mut self, name: PeerName, mut peer: Peer) {
        let local_idx = self.peers_by_idx.len();
        peer.set_local_idx(local_idx as u32);

        let peer = Arc::new(peer);

        self.peers_by_name.insert(name, Arc::clone(&peer));
        self.peers_by_ip.extend(
            peer.allowed_ips()
                .iter()
                .map(|(_, ip, cidr)| (ip, cidr, Arc::clone(&peer))),
        );
        self.peers_by_idx.push(peer);
    }

    pub fn wait(&self) {
        let mut buf = [0u8; BUF_SIZE];

        // there will be three IO resources in this loop
        //
        // 1. the tun interface
        // 2. a bind-only UdpSocket to handle the initial client handshake
        // 3. a connected peer UdpSocket to transmit subsequent data packets over
        while let Ok(token) = self.poll.wait() {
            match token {
                Token::Tun => {
                    debug!("handle Token::Tun");
                    if let Err(err) = self.handle_tun(&mut buf) {
                        error!("tun error: {:?}", err);
                    }
                }
                Token::Sock(SockID::Unconnected) => {
                    debug!("handle Token::Sock(SockID::BindOnly)");
                    if let Err(err) = self.handle_udp(&mut buf) {
                        error!("udp error: {:?}", err);
                    }
                }
                Token::Sock(SockID::Connected(i)) => {
                    debug!("handle Token::Sock(SockID::ConnectedPeer)");
                    let Some(peer) = self.peers_by_idx.get(i as usize) else {
                        continue;
                    };
                    if let Some(conn) = peer.endpoint().conn.as_deref() {
                        if let Err(err) = self.handle_connected_peer(conn, peer, &mut buf) {
                            error!("udp error: {:?}", err);
                        }
                    }
                }
            }
        }
    }

    pub fn start(&self) -> io::Result<()> {
        info!("start caetun");

        let tun = unsafe { BorrowedFd::borrow_raw(self.iface.as_raw_fd()) };

        self.poll
            .register_read(Token::Sock(SockID::Unconnected), self.udp.as_ref())?;
        self.poll.register_read::<_, SockID>(Token::Tun, &tun)?;

        let mut buf = [0u8; BUF_SIZE];
        for (_, peer) in self.peers_by_name.iter() {
            self.take_action(peer.initiate_handshake(self.name.as_ref(), &mut buf))
        }

        Ok(())
    }

    // Handle incoming data from tun interface
    #[instrument(name = "handle_tun", skip_all)]
    pub fn handle_tun(&self, buf: &mut [u8]) -> io::Result<()> {
        while let Ok(n) = self.iface.recv(buf) {
            let (_, dst) = match etherparse::Ipv4HeaderSlice::from_slice(&buf[..n]) {
                Ok(h) => {
                    let src = h.source_addr();
                    let dst = h.destination_addr();
                    info!(
                        "got Ipv4 packet of size: {n}, {src} -> {dst}, from tunnel: {}",
                        self.iface.name()
                    );
                    (src, dst)
                }
                Err(e) => {
                    warn!("not an Ipv4 packet: {:?}", e);
                    continue;
                }
            };

            // peer selection for outgoing packets: determines which peer an outgoing IP packet
            // should be routed to based on its destination address.
            let Some(peer) = self.peers_by_ip.find(dst.into()) else {
                warn!("no peer for this ip: {dst}");
                continue;
            };

            let mut dst = [0u8; BUF_SIZE];
            let action = peer.encapsulate(&buf[..n], &mut dst);
            self.take_action(action);
        }

        Ok(())
    }

    // Handle incoming data from an unconnected UdpSocket
    #[instrument(name = "handle_udp", skip_all)]
    pub fn handle_udp(&self, buf: &mut [u8]) -> io::Result<()> {
        while let Ok((n, addr)) = self.udp.recv_from(buf) {
            info!("got packet of size: {n}, from addr: {addr}");

            let SocketAddr::V4(addr) = addr else { continue };
            let Ok(packet) = Packet::parse_from(&buf[..n]) else {
                continue;
            };

            let peer = match packet {
                Packet::Empty => continue,
                Packet::HandshakeInit(ref msg) => {
                    self.peers_by_name.get(msg.sender_name.as_slice())
                }
                Packet::HandshakeResponse(ref msg) => {
                    self.peers_by_idx.get(msg.sender_idx as usize)
                }
                Packet::Data(ref msg) => self.peers_by_idx.get(msg.sender_idx as usize),
            };

            if let Some(peer) = peer {
                // handle our handshake packet

                let (endpoint_changed, conn) = peer.set_endpoint(addr);
                if let Some(conn) = conn {
                    self.poll.delete(conn.as_ref()).expect("poll delete");
                    // drop(conn);
                }

                if endpoint_changed && self.use_connected_peer {
                    // once a client peer handshakes to the server, we shall open a new UdpSocket
                    // and connect it to the client’s public ip address and port.
                    match peer.connect_endpoint(self.listen_port) {
                        Ok(conn) => {
                            self.poll
                                .register_read(
                                    Token::Sock(SockID::Connected(peer.local_idx())),
                                    &*conn,
                                )
                                .expect("poll register_read");
                        }
                        Err(err) => {
                            error!("error connecting to peer: {:?}", err);
                        }
                    }
                }

                let mut buf = [0u8; BUF_SIZE];
                let action = peer.handle_incoming_packet(packet, &mut buf);
                self.take_action(action)
            }
        }

        Ok(())
    }

    // Handle incoming data from a connected UdpSocket
    #[instrument(name = "handle_connected_peer", skip_all, fields(peer_idx = peer.local_idx()))]
    pub fn handle_connected_peer(
        &self,
        socket: &UdpSocket,
        peer: &Peer,
        buf: &mut [u8],
    ) -> io::Result<()> {
        // since this socket is "connected", so we can recv from it directly
        while let Ok(n) = socket.recv(&mut buf[..]) {
            info!("got packet of size: {n}, from a connected peer");

            let packet = match Packet::parse_from(&buf[..n]) {
                Ok(packet) => packet,
                Err(e) => {
                    error!("not a valid packet: {:?}", e);
                    continue;
                }
            };

            let mut buf = [0u8; BUF_SIZE];
            let action = peer.handle_incoming_packet(packet, &mut buf);
            self.take_action(action);
        }
        Ok(())
    }

    #[instrument(name = "take_action", skip_all)]
    fn take_action(&self, action: Action<'_>) {
        match action {
            Action::WriteToTun(peer, data, src_addr) => {
                // source address filtering for incoming packets: ensures that incoming packets
                // are from an allowed source before forwarding them to the tun interface.
                if peer.is_allowed_ip(src_addr) {
                    // send packet back to network stack
                    let n = self.iface.send(data);
                    info!("write to tun {:?} bytes", n);
                }
            }
            Action::WriteToNetwork(peer, data) => {
                let _ = self.send_over_udp(peer, data);
            }
            Action::None => (),
        }
    }

    /// send data over udp
    ///
    /// if peer is "connected", we prefer to send data over the connected UdpSocket.
    /// otherwise, we will use the main listening socket self.udp and a send_to call.
    fn send_over_udp(&self, peer: &Peer, data: &[u8]) -> io::Result<usize> {
        let endpoint = peer.endpoint();
        match (endpoint.conn.as_ref(), endpoint.addr) {
            (Some(conn), _) => conn.send(data),
            (_, Some(ref addr)) => self.udp.send_to(data, addr),
            _ => Ok(0),
        }
    }
}
