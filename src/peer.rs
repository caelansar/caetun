use crate::allowed_ip::AllowedIps;
use crate::device::new_udp_socket;
use crate::packet::{HandshakeInit, HandshakeResponse, Packet, PacketData};
use anyhow::bail;
use parking_lot::{RwLock, RwLockReadGuard};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use tracing::{debug, info, instrument};

/// Peer is responsible for the state machine and identity management for a peer.
/// The handshake state machine requires asymmetric roles between two peers, if both peers act like clients
/// and initialize by sending handshakes, the situation deadlocks and neither party can make any progress.
#[derive(Default)]
pub struct Peer {
    /// The local index of the peer.
    ///
    /// On wireguard, it obfuscates the indices used in its packets by randomizing them into a 24 bit address space,
    /// hiding the total number of peers using the system. Since security is absolutely not a concern in this project,
    /// we keep it simple and do not attempt to obfuscate the indices.
    local_idx: u32,
    handshake_state: RwLock<HandshakeState>,
    endpoint: RwLock<Endpoint>,
    allowed_ips: AllowedIps<()>,
}

/// Endpoint is a struct that represents a peer's endpoint.
#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddrV4>,
    pub conn: Option<Arc<UdpSocket>>,
}

/// Action is a type that represents an action to be taken by the device.
pub enum Action<'a> {
    /// WriteToTun is an action that writes data to the tun interface.
    WriteToTun(&'a Peer, &'a [u8], Ipv4Addr),
    /// WriteToNetwork is an action that writes data to the network.
    WriteToNetwork(&'a Peer, &'a [u8]),
    /// None is an action that does nothing.
    None,
}

/// HandshakeState represents the handshake state of a peer.
///
/// for client perspective, it will go through None -> HandshakeSent -> Connected.
/// for server perspective, it will go through None -> HandshakeReceived -> Connected.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum HandshakeState {
    /// None is the initial handshake state.
    None,
    /// HandshakeSent is the handshake state when the handshake has been sent.
    HandshakeSent,
    /// HandshakeReceived is the handshake state when the handshake has been received.
    HandshakeReceived { remote_idx: u32 },
    /// Connected is the handshake state when the handshake is complete.
    Connected { remote_idx: u32 },
}

impl Default for HandshakeState {
    fn default() -> Self {
        Self::None
    }
}

const PEER_NAME_MAX_LEN: usize = 100;

/// PeerName is used to identify a peer.
/// Wireguard identifies peers by their PublicKeys, but we simply use string names here.
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
    #[allow(dead_code)]
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
    #[instrument(name = "set_endpoint", skip_all, ret)]
    pub fn set_endpoint(&self, addr: SocketAddrV4) -> (bool, Option<Arc<UdpSocket>>) {
        debug!("setting endpoint to {}", addr);

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

        let conn = new_udp_socket(Some(addr.into()), port)?;

        info!(
            message="Connected endpoint",
            port=port,
            endpoint=?endpoint.addr.unwrap()
        );

        let conn = Arc::new(conn);
        endpoint.conn = Some(conn.clone());

        Ok(conn)
    }

    /// initiate_handshake initiates a handshake with the peer.
    pub fn initiate_handshake<'a>(
        &'a self,
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
            Action::WriteToNetwork(self, &dst[..n])
        } else {
            Action::None
        }
    }

    /// encapsulate encapsulates the src data into a packet and writes it to the network
    /// if the handshake is complete.
    pub fn encapsulate<'a>(&'a self, src: &'a [u8], dst: &'a mut [u8]) -> Action<'a> {
        let state = self.handshake_state.read();
        if let HandshakeState::Connected { remote_idx } = &*state {
            let data = PacketData {
                sender_idx: *remote_idx,
                data: src,
            };
            let n = data.format(dst);
            Action::WriteToNetwork(self, &dst[..n])
        } else {
            Action::None
        }
    }

    pub fn handle_incoming_packet<'a>(
        &'a self,
        packet: Packet<'a>,
        dst: &'a mut [u8],
    ) -> Action<'a> {
        match packet {
            Packet::Empty => Action::None,
            Packet::HandshakeInit(msg) => self.handle_handshake_init(msg, dst),
            Packet::HandshakeResponse(msg) => self.handle_handshake_response(msg, dst),
            Packet::Data(msg) => self.handle_packet_data(msg, dst),
        }
    }

    fn handle_handshake_init<'a>(
        &'a self,
        msg: HandshakeInit<'a>,
        dst: &'a mut [u8],
    ) -> Action<'a> {
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
            Action::WriteToNetwork(self, &dst[..n])
        } else {
            Action::None
        }
    }

    fn handle_handshake_response<'a>(
        &'a self,
        msg: HandshakeResponse,
        dst: &'a mut [u8],
    ) -> Action<'a> {
        let mut state = self.handshake_state.write();
        if let HandshakeState::HandshakeSent = &*state {
            debug!("received handshake response, transitioning to Connected state");

            *state = HandshakeState::Connected {
                remote_idx: msg.assigned_idx,
            };
            drop(state);

            self.encapsulate(&[], dst)
        } else {
            Action::None
        }
    }

    fn handle_packet_data<'a>(&'a self, msg: PacketData<'a>, _dst: &'a mut [u8]) -> Action<'a> {
        let state = self.handshake_state.read();
        info!("handling packet data, peer handshake state: {:?}", state);

        match &*state {
            HandshakeState::Connected { .. } => {
                debug!("peer is connected");
            }
            HandshakeState::HandshakeReceived { remote_idx } => {
                debug!("received a first data packet, transitioning to Connected state");
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
                Action::WriteToTun(self, msg.data, src)
            }
            _ => Action::None,
        }
    }
}
