//! How often one client may start signing in (or enrolling) on this node:
//! each start writes a row (a challenge, an OIDC flow) before anyone is
//! known, so without a limit anyone could fill the tables. A token bucket
//! per client address (per /64, for IPv6, which a client has many of),
//! kept in memory.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Instant;

/// How many a client may start at once.
const BURST: f64 = 20.0;
/// How many more a client may start per second, after that: 20 a minute.
const RATE: f64 = 20.0 / 60.0;
/// How many clients are kept track of at most. Past that, those whose
/// buckets are full again are forgotten; if none are, all are (memory
/// stays bounded, at the cost of a fresh start for clients that many).
const MAX_CLIENTS: usize = 100_000;

#[derive(Default)]
pub struct Limiter {
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

impl Limiter {
    /// Whether the client at `address` may start one now (which counts).
    pub fn allow(&self, address: IpAddr) -> bool {
        self.allow_at(address, Instant::now())
    }

    fn allow_at(&self, address: IpAddr, now: Instant) -> bool {
        let key = match address.to_canonical() {
            IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !(u64::MAX as u128))),
            v4 => v4,
        };
        let refilled = |(tokens, at): (f64, Instant)| (tokens + now.saturating_duration_since(at).as_secs_f64() * RATE).min(BURST);
        let mut buckets = self.buckets.lock().unwrap();
        if buckets.len() >= MAX_CLIENTS && !buckets.contains_key(&key) {
            buckets.retain(|_, bucket| refilled(*bucket) < BURST);
            if buckets.len() >= MAX_CLIENTS {
                buckets.clear();
            }
        }
        let bucket = buckets.entry(key).or_insert((BURST, now));
        let tokens = refilled(*bucket);
        let allowed = tokens >= 1.0;
        *bucket = (if allowed { tokens - 1.0 } else { tokens }, now);
        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_client_gets_a_burst_then_a_few_a_minute() {
        let limiter = Limiter::default();
        let start = Instant::now();
        let client: IpAddr = "192.0.2.1".parse().unwrap();
        for _ in 0..20 {
            assert!(limiter.allow_at(client, start));
        }
        assert!(!limiter.allow_at(client, start));
        // Others aren't held up by it.
        assert!(limiter.allow_at("192.0.2.2".parse().unwrap(), start));
        // One more every three seconds.
        assert!(limiter.allow_at(client, start + Duration::from_secs(3)));
        assert!(!limiter.allow_at(client, start + Duration::from_secs(4)));
        assert!(limiter.allow_at(client, start + Duration::from_secs(7)));
    }

    /// An IPv6 client is its /64: it can't get a burst per address.
    #[test]
    fn an_ipv6_client_is_its_64() {
        let limiter = Limiter::default();
        let start = Instant::now();
        for i in 0..20u16 {
            assert!(limiter.allow_at(format!("2001:db8::{i:x}").parse().unwrap(), start));
        }
        assert!(!limiter.allow_at("2001:db8::ffff:1".parse().unwrap(), start));
        assert!(limiter.allow_at("2001:db8:0:1::1".parse().unwrap(), start));
    }
}
