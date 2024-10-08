use std::collections::VecDeque;
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

/// A trie of IP/cidr addresses
#[derive(Default)]
pub struct AllowedIps<D> {
    ips: IpNetworkTable<D>,
}

impl<D> AllowedIps<D> {
    pub fn new() -> Self {
        Self {
            ips: IpNetworkTable::new(),
        }
    }

    pub fn clear(&mut self) {
        self.ips = IpNetworkTable::new();
    }

    pub fn insert(&mut self, key: IpAddr, cidr: u8, data: D) -> Option<D> {
        self.ips.insert(
            IpNetwork::new_truncate(key, cidr).expect("cidr is valid length"),
            data,
        )
    }

    pub fn find(&self, key: IpAddr) -> Option<&D> {
        self.ips.longest_match(key).map(|(_net, data)| data)
    }

    pub fn remove(&mut self, predicate: impl Fn(&D) -> bool) {
        self.ips.retain(|_, v| !predicate(v));
    }

    pub fn iter(&self) -> Iter<D> {
        Iter(
            self.ips
                .iter()
                .map(|(ipa, d)| (d, ipa.network_address(), ipa.netmask()))
                .collect(),
        )
    }
}

pub struct Iter<'a, D: 'a>(VecDeque<(&'a D, IpAddr, u8)>);

impl<'a, D> Iterator for Iter<'a, D> {
    type Item = (&'a D, IpAddr, u8);
    fn next(&mut self) -> Option<Self::Item> {
        self.0.pop_front()
    }
}

impl<T> Extend<(IpAddr, u8, T)> for AllowedIps<T> {
    fn extend<I: IntoIterator<Item = (IpAddr, u8, T)>>(&mut self, iter: I) {
        for (ip, cidr, value) in iter {
            self.insert(ip, cidr, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_allowed_ips() -> AllowedIps<char> {
        let mut map: AllowedIps<char> = Default::default();
        map.insert(IpAddr::from([127, 0, 0, 1]), 32, '1');
        map.insert(IpAddr::from([45, 25, 15, 1]), 30, '6');
        map.insert(IpAddr::from([127, 0, 15, 1]), 16, '2');
        map.insert(IpAddr::from([127, 1, 15, 1]), 24, '3');
        map.insert(IpAddr::from([255, 1, 15, 1]), 24, '4');
        map.insert(IpAddr::from([60, 25, 15, 1]), 32, '5');
        map.insert(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0]), 128, '7');
        map
    }

    #[test]
    fn test_allowed_ips_insert_find() {
        let map = build_allowed_ips();
        assert_eq!(map.find(IpAddr::from([127, 0, 0, 1])), Some(&'1'));
        assert_eq!(map.find(IpAddr::from([127, 0, 255, 255])), Some(&'2'));
        assert_eq!(map.find(IpAddr::from([127, 1, 255, 255])), None);
        assert_eq!(map.find(IpAddr::from([127, 0, 255, 255])), Some(&'2'));
        assert_eq!(map.find(IpAddr::from([127, 1, 15, 255])), Some(&'3'));
        assert_eq!(map.find(IpAddr::from([127, 0, 255, 255])), Some(&'2'));
        assert_eq!(map.find(IpAddr::from([127, 1, 15, 255])), Some(&'3'));
        assert_eq!(map.find(IpAddr::from([255, 1, 15, 2])), Some(&'4'));
        assert_eq!(map.find(IpAddr::from([60, 25, 15, 1])), Some(&'5'));
        assert_eq!(map.find(IpAddr::from([20, 0, 0, 100])), None);
        assert_eq!(
            map.find(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0])),
            Some(&'7')
        );
        assert_eq!(map.find(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 1])), None);
        assert_eq!(map.find(IpAddr::from([45, 25, 15, 1])), Some(&'6'));
    }

    #[test]
    fn test_allowed_ips_remove() {
        let mut map = build_allowed_ips();
        map.remove(|c| *c == '5' || *c == '1' || *c == '7');

        let mut map_iter = map.iter();
        assert_eq!(
            map_iter.next(),
            Some((&'6', IpAddr::from([45, 25, 15, 0]), 30))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'2', IpAddr::from([127, 0, 0, 0]), 16))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'3', IpAddr::from([127, 1, 15, 0]), 24))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'4', IpAddr::from([255, 1, 15, 0]), 24))
        );
        assert_eq!(map_iter.next(), None);
    }
}
