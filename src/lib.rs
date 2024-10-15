mod allowed_ip;
pub mod conf;
pub mod device;
mod packet;
pub mod peer;

#[cfg(target_os = "linux")]
#[path = "poll_epoll.rs"]
mod poll;

#[cfg(target_os = "macos")]
#[path = "poll_kqueue.rs"]
mod poll;

#[cfg(target_os = "linux")]
#[path = "tun_linux.rs"]
mod tun;

#[cfg(target_os = "macos")]
#[path = "tun_darwin.rs"]
mod tun;
