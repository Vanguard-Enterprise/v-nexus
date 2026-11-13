//! The client address of a request, resolved through configured trusted proxies.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use ipnet::IpNet;

use crate::router::AppState;

/// Header carrying the client chain set by reverse proxies.
const FORWARDED_FOR: &str = "x-forwarded-for";

/// The address of the client that sent the request, or `None` when the server was not
/// started with connection info (as in router tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientAddr(pub(crate) Option<IpAddr>);

impl FromRequestParts<AppState> for ClientAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip().to_canonical());
        Ok(Self(peer.map(|peer| {
            resolve(peer, &parts.headers, &state.trusted_proxies)
        })))
    }
}

/// Resolves the client address from the TCP peer and `X-Forwarded-For`.
///
/// The header is only believed when the peer is a trusted proxy. Each proxy appends the
/// address it received the request from, so the chain is read from the right: trusted
/// proxies are skipped and the first untrusted address is the client. Anything to its
/// left was supplied by the client and is ignored. An unparseable entry stops the walk at
/// the last trusted hop, because nothing beyond it can be relied on.
pub(crate) fn resolve(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> IpAddr {
    let is_trusted = |addr: &IpAddr| trusted.iter().any(|net| net.contains(addr));
    if !is_trusted(&peer) {
        return peer;
    }
    let mut client = peer;
    let values: Vec<&str> = headers
        .get_all(FORWARDED_FOR)
        .iter()
        .map(|value| value.to_str().unwrap_or(""))
        .collect();
    let entries = values
        .iter()
        .rev()
        .flat_map(|value| value.rsplit(','))
        .map(str::trim);
    for entry in entries {
        let Some(addr) = parse_entry(entry) else {
            return client;
        };
        client = addr;
        if !is_trusted(&addr) {
            return addr;
        }
    }
    client
}

/// Parses one `X-Forwarded-For` entry: an address, optionally with a port.
fn parse_entry(entry: &str) -> Option<IpAddr> {
    entry
        .parse::<IpAddr>()
        .ok()
        .or_else(|| entry.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
        .map(|addr| addr.to_canonical())
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(FORWARDED_FOR, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    fn proxies() -> Vec<IpNet> {
        vec!["10.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()]
    }

    #[test]
    fn untrusted_peer_header_is_ignored() {
        let resolved = resolve(ip("203.0.113.9"), &headers(&["198.51.100.1"]), &proxies());
        assert_eq!(resolved, ip("203.0.113.9"));
    }

    #[test]
    fn trusted_peer_yields_the_first_untrusted_hop_from_the_right() {
        let h = headers(&["1.1.1.1, 198.51.100.1, 10.0.0.5"]);
        assert_eq!(resolve(ip("10.0.0.2"), &h, &proxies()), ip("198.51.100.1"));
    }

    #[test]
    fn repeated_headers_are_one_chain() {
        let h = headers(&["198.51.100.1", "10.0.0.5"]);
        assert_eq!(resolve(ip("10.0.0.2"), &h, &proxies()), ip("198.51.100.1"));
    }

    #[test]
    fn chain_of_only_trusted_hops_yields_the_leftmost() {
        let h = headers(&["10.1.1.1, 10.0.0.5"]);
        assert_eq!(resolve(ip("10.0.0.2"), &h, &proxies()), ip("10.1.1.1"));
    }

    #[test]
    fn missing_header_yields_the_peer() {
        assert_eq!(
            resolve(ip("10.0.0.2"), &HeaderMap::new(), &proxies()),
            ip("10.0.0.2")
        );
    }

    #[test]
    fn garbage_stops_at_the_last_trusted_hop() {
        let h = headers(&["198.51.100.1, not-an-ip, 10.0.0.5"]);
        assert_eq!(resolve(ip("10.0.0.2"), &h, &proxies()), ip("10.0.0.5"));
    }

    #[test]
    fn accepts_ports_and_mapped_addresses() {
        let h = headers(&["198.51.100.1:4711"]);
        assert_eq!(resolve(ip("10.0.0.2"), &h, &proxies()), ip("198.51.100.1"));
        let h = headers(&["[2001:db8::1]:443"]);
        assert_eq!(resolve(ip("fd00::2"), &h, &proxies()), ip("2001:db8::1"));
        let h = headers(&["::ffff:198.51.100.1"]);
        assert_eq!(resolve(ip("10.0.0.2"), &h, &proxies()), ip("198.51.100.1"));
    }
}
