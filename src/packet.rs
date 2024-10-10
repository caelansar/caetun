use crate::peer::PeerName;
use thiserror::Error;

/// Packet is the type of the packets that are sent between peers.
///
/// specification:
/// the first byte is the type of the packet.
/// the following bytes are the payload of the packet.
/// for `HandshakeInit`, the payload is the assigned index and the sender's name.
/// for `HandshakeResponse`, the payload is the assigned index and the sender's index.
/// for `Data`, the payload is the sender's index and the data.
///
/// all bytes are sent in little-endian order.
#[derive(Debug, PartialEq)]
pub enum Packet<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse),
    Data(PacketData<'a>),
    Empty,
}

#[derive(Debug, PartialEq)]
pub struct HandshakeInit<'a> {
    pub sender_name: PeerName<&'a [u8]>,
    pub assigned_idx: u32,
}

#[derive(Debug, PartialEq)]
pub struct HandshakeResponse {
    pub assigned_idx: u32,
    pub sender_idx: u32,
}

#[derive(Debug, PartialEq)]
pub struct PacketData<'a> {
    pub sender_idx: u32,
    pub data: &'a [u8],
}

#[repr(u8)]
enum PacketType {
    HandshakeInit = 1,
    HandshakeResponse = 2,
    PacketData = 3,
}

impl TryFrom<u8> for PacketType {
    type Error = PackeParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PacketType::HandshakeInit),
            2 => Ok(PacketType::HandshakeResponse),
            3 => Ok(PacketType::PacketData),
            _ => Err(PackeParseError::InvalidPacketType(value)),
        }
    }
}

const HANDSHAKE_INIT_SIZE: usize = PeerName::max_len() + 5;
const HANDSHAKE_RESPONSE_SIZE: usize = 9;
const DATA_MIN_SIZE: usize = 5;

#[derive(Error, Debug, Copy, Clone)]
pub enum PackeParseError {
    #[error("invalid packet type {0}")]
    InvalidPacketType(u8),
    #[error("protocol error")]
    ProtocolErr,
}

impl<'a> Packet<'a> {
    pub fn parse_from(src: &'a [u8]) -> Result<Self, PackeParseError> {
        if src.is_empty() {
            return Ok(Packet::Empty);
        }
        match (PacketType::try_from(src[0])?, src.len()) {
            (PacketType::HandshakeInit, HANDSHAKE_INIT_SIZE) => {
                let remote_idx = u32::from_le_bytes(src[1..5].try_into().unwrap());
                let sender_name = PeerName::from(&src[5..105]);
                Ok(Packet::HandshakeInit(HandshakeInit {
                    sender_name,
                    assigned_idx: remote_idx,
                }))
            }
            (PacketType::HandshakeResponse, HANDSHAKE_RESPONSE_SIZE) => {
                let assigned_idx = u32::from_le_bytes(src[1..5].try_into().unwrap());
                let sender_idx = u32::from_le_bytes(src[5..9].try_into().unwrap());

                Ok(Packet::HandshakeResponse(HandshakeResponse {
                    assigned_idx,
                    sender_idx,
                }))
            }
            (PacketType::PacketData, n) if n >= DATA_MIN_SIZE => {
                let sender_idx = u32::from_le_bytes(src[1..5].try_into().unwrap());

                Ok(Packet::Data(PacketData {
                    sender_idx,
                    data: &src[5..],
                }))
            }
            _ => Err(PackeParseError::ProtocolErr),
        }
    }
}

impl<'a> HandshakeInit<'a> {
    pub fn format(&self, dst: &mut [u8]) -> usize {
        assert!(dst.len() >= HANDSHAKE_INIT_SIZE);

        dst[0] = PacketType::HandshakeInit as u8;
        dst[1..5].copy_from_slice(&self.assigned_idx.to_le_bytes());
        dst[5..105].copy_from_slice(self.sender_name.as_slice());

        HANDSHAKE_INIT_SIZE
    }
}

impl HandshakeResponse {
    pub fn format(&self, dst: &mut [u8]) -> usize {
        assert!(dst.len() >= HANDSHAKE_RESPONSE_SIZE);

        dst[0] = PacketType::HandshakeResponse as u8;
        dst[1..5].copy_from_slice(&self.assigned_idx.to_le_bytes());
        dst[5..9].copy_from_slice(&self.sender_idx.to_le_bytes());

        HANDSHAKE_RESPONSE_SIZE
    }
}

impl<'a> PacketData<'a> {
    pub fn format(&self, dst: &mut [u8]) -> usize {
        let n = self.data.len();
        let len = n + 5;
        assert!(dst.len() >= len);

        dst[0] = PacketType::PacketData as u8;
        dst[1..5].copy_from_slice(&self.sender_idx.to_le_bytes());
        dst[5..(5 + n)].copy_from_slice(self.data);

        len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_init() {
        let slice = [0u8; 100];

        let handshake_init = HandshakeInit {
            sender_name: PeerName::from(slice.as_slice()),
            assigned_idx: 9,
        };
        let mut dst = [0u8; 1024];
        let n = handshake_init.format(&mut dst);
        assert_eq!(HANDSHAKE_INIT_SIZE, n);

        let packet = Packet::parse_from(&dst[..n]).unwrap();
        assert_eq!(Packet::HandshakeInit(handshake_init), packet);
    }

    #[test]
    fn test_packet_data() {
        let data = PacketData {
            sender_idx: 8,
            data: &[1, 2, 3, 4],
        };

        let mut dst = [0u8; 1024];
        let n = data.format(&mut dst);
        assert_eq!(5 + 4, n);

        let packet = Packet::parse_from(&dst[..n]).unwrap();
        assert_eq!(Packet::Data(data), packet);
    }
}
