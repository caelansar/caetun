use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;
use std::os::fd::AsFd;

use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Token<ID = i32> {
    Tun,
    Sock(ID),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct UnknownToken(u64);

impl Display for UnknownToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("unknown token: {}", self.0))
    }
}

impl Error for UnknownToken {}

impl<ID> From<Token<ID>> for u64
where
    ID: Into<i32>,
{
    fn from(value: Token<ID>) -> Self {
        match value {
            Token::Tun => 1 << 32,
            Token::Sock(sock_index) => 2 << 32 | (sock_index.into() as u32 as u64),
        }
    }
}

impl<ID> TryFrom<u64> for Token<ID>
where
    ID: From<i32>,
{
    type Error = UnknownToken;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let tag = value >> 32;
        let token = match tag {
            1 => Token::Tun,
            2 => Token::Sock((value as i32).into()),
            _ => return Err(UnknownToken(value)),
        };

        Ok(token)
    }
}

// edge-triggered mode, as opposed to the default level-triggered mode. This choice significantly
// impacts how epoll behaves in a multithreaded environment:
//
// - Edge vs. Level Triggered: In level-triggered mode, epoll will continually notify about an event
//   as long as the condition persists. In contrast, edge-triggered mode only notifies once when the
//   condition changes. This behavior is crucial for avoiding redundant wake-ups in a multithreaded setup.
//
// - Spurious Wakes: With level-triggered epoll, there’s a risk of spurious wake-ups where a read event
//   could wake up multiple threads calling epoll_wait on the same epoll file descriptor (fd). This
//   scenario is less efficient and can lead to unnecessary contention among threads
const EPOLL_FLAGS: EpollFlags = EpollFlags::EPOLLIN.union(EpollFlags::EPOLLET);

pub struct Poll {
    epoll: Epoll,
}

// The Poll wrapper is designed to simplify our interactions with epoll.
impl Poll {
    pub fn new() -> io::Result<Self> {
        let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?;
        Ok(Self { epoll })
    }

    pub fn register_read<F: AsFd, ID: From<i32> + Into<i32>>(
        &self,
        token: Token<ID>,
        fd: &F,
    ) -> io::Result<()> {
        let event = EpollEvent::new(EPOLL_FLAGS, token.into());
        self.epoll.add(fd, event)?;

        Ok(())
    }

    pub fn delete<F: AsFd>(&self, fd: &F) -> io::Result<()> {
        self.epoll.delete(fd)?;

        Ok(())
    }

    // wait for one event at a time. epoll_wait sys call can return a list of ready events using
    // the out parameter pattern through the &mut events argument.
    pub fn wait<ID: From<i32> + Into<i32>>(&self) -> io::Result<Token<ID>> {
        let mut events = [EpollEvent::empty()];

        let n = self.epoll.wait(
            &mut events,
            <_ as TryInto<EpollTimeout>>::try_into(-1).unwrap(),
        )?;
        assert_eq!(n, 1);

        let data = events[0].data();
        let token = Token::try_from(data)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "unexpected epoll data"))?;

        Ok(token)
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
            let num: u64 = token.into();
            assert_eq!(num.try_into(), Ok(token));
        }

        let num: u64 = 1000;
        assert_eq!(
            <u64 as TryInto<Token>>::try_into(num),
            Err(UnknownToken(1000))
        );
    }
}
