use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;
use std::os::fd::AsRawFd;

use libc::timespec;
use nix::sys::event::{EventFilter, EventFlag, FilterFlag, KEvent, Kqueue};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Token<ID = i32> {
    Tun,
    Sock(ID),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct UnknownToken(isize);

impl Display for UnknownToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown token: {}", self.0)
    }
}

impl Error for UnknownToken {}

impl<ID> From<Token<ID>> for isize
where
    ID: Into<i32>,
{
    fn from(value: Token<ID>) -> Self {
        match value {
            Token::Tun => 1 << 32,
            Token::Sock(sock_index) => 2 << 32 | (sock_index.into() as u32 as isize),
        }
    }
}

impl<ID> TryFrom<isize> for Token<ID>
where
    ID: From<i32>,
{
    type Error = UnknownToken;

    fn try_from(value: isize) -> Result<Self, Self::Error> {
        let tag = value >> 32;
        let token = match tag {
            1 => Token::Tun,
            2 => Token::Sock((value as i32).into()),
            _ => return Err(UnknownToken(value)),
        };

        Ok(token)
    }
}

pub struct Poll {
    kq: Kqueue,
}

impl Poll {
    pub fn new() -> io::Result<Self> {
        let kq = Kqueue::new()?;
        Ok(Self { kq })
    }

    pub fn register_read<F: AsRawFd, ID: From<i32> + Into<i32>>(
        &self,
        token: Token<ID>,
        fd: &F,
    ) -> io::Result<()> {
        let changes = [KEvent::new(
            fd.as_raw_fd() as usize,
            EventFilter::EVFILT_READ,
            EventFlag::EV_ADD | EventFlag::EV_CLEAR,
            FilterFlag::empty(),
            0,
            token.into(),
        )];

        self.kq.kevent(
            &changes,
            &mut [],
            Some(timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )?;

        Ok(())
    }

    pub fn delete<F: AsRawFd>(&self, fd: &F) -> io::Result<()> {
        let changes = [KEvent::new(
            fd.as_raw_fd() as usize,
            EventFilter::EVFILT_READ,
            EventFlag::EV_DELETE,
            FilterFlag::empty(),
            0,
            0,
        )];

        self.kq.kevent(
            &changes,
            &mut [],
            Some(timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )?;

        Ok(())
    }

    pub fn wait<ID: From<i32> + Into<i32>>(&self) -> io::Result<Token<ID>> {
        let mut events = [KEvent::new(
            0,
            EventFilter::EVFILT_READ,
            EventFlag::empty(),
            FilterFlag::empty(),
            0,
            0,
        )];

        let n = self.kq.kevent(&[], &mut events, None)?;
        assert_eq!(n, 1);

        let data = events[0].udata();
        let token = Token::try_from(data)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "unexpected kqueue data"))?;

        Ok(token)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SockID {
    Unconnected,
    Connected(u32),
}

impl From<i32> for SockID {
    fn from(value: i32) -> Self {
        if value == -1 {
            SockID::Unconnected
        } else {
            SockID::Connected(value as u32)
        }
    }
}

impl From<SockID> for i32 {
    fn from(value: SockID) -> Self {
        match value {
            SockID::Unconnected => -1,
            SockID::Connected(i) => i as i32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_u64_from_into() {
        for token in [
            Token::Tun,
            Token::Sock(i32::MIN),
            Token::Sock(-1),
            Token::Sock(0),
            Token::Sock(4),
            Token::Sock(i32::MAX),
        ] {
            let num: isize = token.into();
            assert_eq!(num.try_into(), Ok(token));
        }

        let num: isize = 1000;
        assert_eq!(
            <isize as TryInto<Token>>::try_into(num),
            Err(UnknownToken(1000))
        );
    }
}
