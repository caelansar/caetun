use crate::allowed_ip::AllowedIps;
use crate::device::{new_udp_socket, Endpoint};
use crate::packet::{HandshakeInit, HandshakeResponse, Packet, PacketData};
use anyhow::bail;
use parking_lot::{RwLock, RwLockReadGuard};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use tracing::{debug, info};

#[derive(Default)]
pub struct Peer {
    local_idx: u32,
    handshake_state: RwLock<HandshakeState>,
    endpoint: RwLock<Endpoint>,
    allowed_ips: AllowedIps<()>,
}

pub enum Action<'a> {
    WriteToTun(&'a [u8], Ipv4Addr),
    WriteToNetwork(&'a [u8]),
    None,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum HandshakeState {
    None,
    HandshakeSent,
    HandshakeReceived { remote_idx: u32 },
    Connected { remote_idx: u32 },
}

impl Default for HandshakeState {
    fn default() -> Self {
        Self::None
    }
}

const PEER_NAME_MAX_LEN: usize = 100;

#[derive(Debug, PartialEq, Hash, Eq)]
pub struct PeerName<T = [u8; PEER_NAME_MAX_LEN]>(T);

impl<'a> From<&'a [u8]> for PeerName<&'a [u8]> {
    fn from(slice: &'a [u8]) -> Self {
        PeerName(slice)
    }
}

impl std::borrow::Borrow<[u8]> for PeerName<[u8; PEER_NAME_MAX_LEN]> {
    fn borrow(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<'a> PeerName<&'a [u8]> {
    pub fn as_slice(&self) -> &'a [u8] {
        self.0
    }
}

impl PeerName<[u8; PEER_NAME_MAX_LEN]> {
    pub const fn max_len() -> usize {
        PEER_NAME_MAX_LEN
    }

    pub fn new(name: &str) -> anyhow::Result<Self> {
        let mut bytes = [0u8; PEER_NAME_MAX_LEN];
        let name_bytes = name.as_bytes();
        let len = name_bytes.len();

        if len > PEER_NAME_MAX_LEN {
            bail!(format!("`{name}` too long"))
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
            local_idx: 0,
            handshake_state: RwLock::new(HandshakeState::None),
            endpoint: RwLock::new(peer),
            allowed_ips: AllowedIps::new(),
        }
    }
    pub fn endpoint(&self) -> RwLockReadGuard<Endpoint> {
        self.endpoint.read()
    }

    pub fn local_idx(&self) -> u32 {
        self.local_idx
    }

    pub fn set_local_idx(&mut self, idx: u32) {
        self.local_idx = idx
    }

    pub fn allowed_ips(&self) -> &AllowedIps<()> {
        &self.allowed_ips
    }

    pub fn add_allowed_ip(&mut self, addr: Ipv4Addr, cidr: u8) {
        self.allowed_ips.insert(addr.into(), cidr, ());
    }

    pub fn is_allowed_ip(&self, addr: Ipv4Addr) -> bool {
        self.allowed_ips.find(addr.into()).is_some()
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
        info!("[peer] connect endpoint, peer: {}", self.local_idx);

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

    pub fn initiate_handshake<'a>(
        &self,
        sender_name: PeerName<&[u8]>,
        dst: &'a mut [u8],
    ) -> Action<'a> {
        let mut state = self.handshake_state.write();

        // we only send handshakes if the endpoint is set on this peer (client situation). In
        // `device.start`, we loop through all peers and call initiate_handshake with the device’s
        // name, and only those peers with known endpoints would have packets sent to them.
        let endpoint_set = self.endpoint().addr.is_some();
        if HandshakeState::None == *state && endpoint_set {
            let packet = HandshakeInit {
                sender_name,
                assigned_idx: self.local_idx(),
            };
            let n = packet.format(dst);

            *state = HandshakeState::HandshakeSent;

            debug!("sending handshake");
            Action::WriteToNetwork(&dst[..n])
        } else {
            Action::None
        }
    }

    pub fn encapsulate<'a>(&self, src: &'a [u8], dst: &'a mut [u8]) -> Action<'a> {
        let state = self.handshake_state.read();
        if let HandshakeState::Connected { remote_idx } = &*state {
            let data = PacketData {
                sender_idx: *remote_idx,
                data: src,
            };
            let n = data.format(dst);
            Action::WriteToNetwork(&dst[..n])
        } else {
            Action::None
        }
    }

    pub fn handle_incoming_packet<'a>(&self, packet: Packet<'a>, dst: &'a mut [u8]) -> Action<'a> {
        match packet {
            Packet::Empty => Action::None,
            Packet::HandshakeInit(msg) => self.handle_handshake_init(msg, dst),
            Packet::HandshakeResponse(msg) => self.handle_handshake_response(msg, dst),
            Packet::Data(msg) => self.handle_packet_data(msg, dst),
        }
    }

    fn handle_handshake_init<'a>(&self, msg: HandshakeInit<'a>, dst: &'a mut [u8]) -> Action<'a> {
        let mut state = self.handshake_state.write();

        if let HandshakeState::None | HandshakeState::Connected { .. } = &*state {
            debug!("received handshake");
            *state = HandshakeState::HandshakeReceived {
                remote_idx: msg.assigned_idx,
            };
            drop(state);

            let local_idx = self.local_idx;
            let response = HandshakeResponse {
                assigned_idx: local_idx,
                sender_idx: msg.assigned_idx,
            };
            let n = response.format(dst);
            Action::WriteToNetwork(&dst[..n])
        } else {
            Action::None
        }
    }

    fn handle_handshake_response<'a>(
        &self,
        msg: HandshakeResponse,
        dst: &'a mut [u8],
    ) -> Action<'a> {
        let mut state = self.handshake_state.write();
        if let HandshakeState::HandshakeSent = &*state {
            debug!("received handshake response");

            *state = HandshakeState::Connected {
                remote_idx: msg.assigned_idx,
            };
            drop(state);

            self.encapsulate(&[], dst)
        } else {
            Action::None
        }
    }

    fn handle_packet_data<'a>(&self, msg: PacketData<'a>, _dst: &'a mut [u8]) -> Action<'a> {
        let state = self.handshake_state.read();
        match &*state {
            HandshakeState::Connected { .. } => {
                debug!("peer is connected");
            }
            HandshakeState::HandshakeReceived { remote_idx } => {
                debug!("received a first data packet, transitioning to Connected");
                let remote_idx = *remote_idx;
                drop(state);

                let mut state = self.handshake_state.write();
                *state = HandshakeState::Connected { remote_idx };
            }
            _ => return Action::None,
        };
        match etherparse::Ipv4HeaderSlice::from_slice(msg.data) {
            Ok(iph) => {
                let src = iph.source_addr();
                Action::WriteToTun(msg.data, src)
            }
            _ => Action::None,
        }
    }
}
