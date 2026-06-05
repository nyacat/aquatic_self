use std::net::IpAddr;

use anyhow::Context;
use aquatic_http_protocol::request::Request;

use crate::config::{Config, ReverseProxyPeerIpHeaderFormat};

#[derive(Debug, thiserror::Error)]
pub enum RequestParseError {
    #[error("required peer ip header missing or invalid")]
    RequiredPeerIpHeaderMissing(anyhow::Error),
    #[error("invalid request")]
    InvalidRequest(anyhow::Error),
    #[error("more data needed")]
    MoreDataNeeded,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HttpRequest {
    Tracker(Request),
    StaticIndex,
}

pub fn parse_request(
    config: &Config,
    buffer: &[u8],
) -> Result<(HttpRequest, Option<IpAddr>), RequestParseError> {
    if let Some(request) = parse_static_index_request(buffer) {
        return request;
    }

    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut http_request = httparse::Request::new(&mut headers);

    match http_request
        .parse(buffer)
        .with_context(|| "httparse")
        .map_err(RequestParseError::InvalidRequest)?
    {
        httparse::Status::Complete(_) => {
            let path = http_request
                .path
                .ok_or(anyhow::anyhow!("no http path"))
                .map_err(RequestParseError::InvalidRequest)?;
            let request = if path == "/" || path == "/index.html" {
                HttpRequest::StaticIndex
            } else {
                HttpRequest::Tracker(
                    Request::parse_http_get_path(path)
                        .map_err(RequestParseError::InvalidRequest)?,
                )
            };

            let opt_peer_ip = if config.network.runs_behind_reverse_proxy {
                let header_name = &config.network.reverse_proxy_ip_header_name;
                let header_format = config.network.reverse_proxy_ip_header_format;

                match parse_forwarded_header(header_name, header_format, http_request.headers) {
                    Ok(peer_ip) => Some(peer_ip),
                    Err(err) => {
                        return Err(RequestParseError::RequiredPeerIpHeaderMissing(err));
                    }
                }
            } else {
                None
            };

            Ok((request, opt_peer_ip))
        }
        httparse::Status::Partial => Err(RequestParseError::MoreDataNeeded),
    }
}

fn parse_static_index_request(
    buffer: &[u8],
) -> Option<Result<(HttpRequest, Option<IpAddr>), RequestParseError>> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut http_request = httparse::Request::new(&mut headers);

    match http_request.parse(buffer) {
        Ok(httparse::Status::Complete(_)) => match http_request.path {
            Some("/") | Some("/index.html") => Some(Ok((HttpRequest::StaticIndex, None))),
            _ => None,
        },
        Ok(httparse::Status::Partial) => Some(Err(RequestParseError::MoreDataNeeded)),
        Err(httparse::Error::TooManyHeaders) => Some(Err(RequestParseError::InvalidRequest(
            anyhow::anyhow!("httparse: too many headers"),
        ))),
        Err(_) => None,
    }
}

fn parse_forwarded_header(
    header_names: &str,
    header_format: ReverseProxyPeerIpHeaderFormat,
    headers: &[httparse::Header<'_>],
) -> anyhow::Result<IpAddr> {
    if let Some(header_name) = configured_single_header_name(header_names) {
        return parse_named_forwarded_header(header_name, header_format, headers)?
            .ok_or(anyhow::anyhow!("header not present"));
    }

    let mut saw_configured_header_name = false;

    for header_name in configured_header_names(header_names) {
        saw_configured_header_name = true;

        if let Some(peer_ip) = parse_named_forwarded_header(header_name, header_format, headers)? {
            return Ok(peer_ip);
        }
    }

    if saw_configured_header_name {
        Err(anyhow::anyhow!("header not present"))
    } else {
        Err(anyhow::anyhow!("no header name configured"))
    }
}

fn parse_named_forwarded_header(
    header_name: &str,
    header_format: ReverseProxyPeerIpHeaderFormat,
    headers: &[httparse::Header<'_>],
) -> anyhow::Result<Option<IpAddr>> {
    for header in headers.iter().rev() {
        if header.name.eq_ignore_ascii_case(header_name) {
            return parse_forwarded_header_value(header_name, header_format, header.value)
                .map(Some);
        }
    }

    Ok(None)
}

fn parse_forwarded_header_value(
    header_name: &str,
    header_format: ReverseProxyPeerIpHeaderFormat,
    value: &[u8],
) -> anyhow::Result<IpAddr> {
    match header_format {
        ReverseProxyPeerIpHeaderFormat::LastAddress => ::std::str::from_utf8(value)?
            .rsplit(',')
            .next()
            .ok_or(anyhow::anyhow!("no header value"))?
            .trim()
            .parse::<IpAddr>()
            .with_context(|| format!("parse {} header IP", header_name)),
    }
}

fn configured_single_header_name(header_names: &str) -> Option<&str> {
    let header_name = header_names.trim();

    if header_name.is_empty() || header_name.as_bytes().contains(&b',') {
        None
    } else {
        Some(header_name)
    }
}

fn configured_header_names(header_names: &str) -> impl Iterator<Item = &str> {
    header_names
        .split(',')
        .map(str::trim)
        .filter(|header_name| !header_name.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_START: &str = "GET /announce?info_hash=%04%0bkV%3f%5cr%14%a6%b7%98%adC%c3%c9.%40%24%00%b9&peer_id=-ABC940-5ert69muw5t8&port=12345&uploaded=1&downloaded=2&left=3&numwant=0&key=4ab4b877&compact=1&supportcrypto=1&event=started HTTP/1.1\r\nHost: example.com\r\n";

    #[test]
    fn test_parse_peer_ip_header_multiple() {
        let mut config = Config::default();

        config.network.runs_behind_reverse_proxy = true;
        config.network.reverse_proxy_ip_header_name = "X-Forwarded-For".into();
        config.network.reverse_proxy_ip_header_format = ReverseProxyPeerIpHeaderFormat::LastAddress;

        let mut request = REQUEST_START.to_string();

        request.push_str("X-Forwarded-For: 200.0.0.1\r\n");
        request.push_str("X-Forwarded-For: 1.2.3.4, 5.6.7.8,9.10.11.12\r\n");
        request.push_str("\r\n");

        let expected_ip = IpAddr::from([9, 10, 11, 12]);

        assert_eq!(
            parse_request(&config, request.as_bytes())
                .unwrap()
                .1
                .unwrap(),
            expected_ip
        )
    }

    #[test]
    fn test_parse_peer_ip_header_single() {
        let mut config = Config::default();

        config.network.runs_behind_reverse_proxy = true;
        config.network.reverse_proxy_ip_header_name = "X-Forwarded-For".into();
        config.network.reverse_proxy_ip_header_format = ReverseProxyPeerIpHeaderFormat::LastAddress;

        let mut request = REQUEST_START.to_string();

        request.push_str("X-Forwarded-For: 1.2.3.4, 5.6.7.8,9.10.11.12\r\n");
        request.push_str("X-Forwarded-For: 200.0.0.1\r\n");
        request.push_str("\r\n");

        let expected_ip = IpAddr::from([200, 0, 0, 1]);

        assert_eq!(
            parse_request(&config, request.as_bytes())
                .unwrap()
                .1
                .unwrap(),
            expected_ip
        )
    }

    #[test]
    fn test_parse_peer_ip_header_fallback_name() {
        let mut config = Config::default();

        config.network.runs_behind_reverse_proxy = true;
        config.network.reverse_proxy_ip_header_name = "X-Forwarded-For, CF-Connecting-IP".into();
        config.network.reverse_proxy_ip_header_format = ReverseProxyPeerIpHeaderFormat::LastAddress;

        let mut request = REQUEST_START.to_string();

        request.push_str("CF-Connecting-IP: 203.0.113.7\r\n");
        request.push_str("\r\n");

        let expected_ip = IpAddr::from([203, 0, 113, 7]);

        assert_eq!(
            parse_request(&config, request.as_bytes())
                .unwrap()
                .1
                .unwrap(),
            expected_ip
        )
    }

    #[test]
    fn test_parse_peer_ip_header_does_not_fallback_after_invalid_present_header() {
        let mut config = Config::default();

        config.network.runs_behind_reverse_proxy = true;
        config.network.reverse_proxy_ip_header_name = "X-Forwarded-For, CF-Connecting-IP".into();
        config.network.reverse_proxy_ip_header_format = ReverseProxyPeerIpHeaderFormat::LastAddress;

        let mut request = REQUEST_START.to_string();

        request.push_str("X-Forwarded-For: not-an-ip\r\n");
        request.push_str("CF-Connecting-IP: 203.0.113.7\r\n");
        request.push_str("\r\n");

        let res = parse_request(&config, request.as_bytes());

        assert!(matches!(
            res,
            Err(RequestParseError::RequiredPeerIpHeaderMissing(_))
        ));
    }

    #[test]
    fn test_parse_peer_ip_header_case_insensitive_name() {
        let mut config = Config::default();

        config.network.runs_behind_reverse_proxy = true;
        config.network.reverse_proxy_ip_header_name = "X-Forwarded-For".into();
        config.network.reverse_proxy_ip_header_format = ReverseProxyPeerIpHeaderFormat::LastAddress;

        let mut request = REQUEST_START.to_string();

        request.push_str("x-forwarded-for: 198.51.100.9\r\n");
        request.push_str("\r\n");

        let expected_ip = IpAddr::from([198, 51, 100, 9]);

        assert_eq!(
            parse_request(&config, request.as_bytes())
                .unwrap()
                .1
                .unwrap(),
            expected_ip
        )
    }

    #[test]
    fn test_parse_peer_ip_header_no_header() {
        let mut config = Config::default();

        config.network.runs_behind_reverse_proxy = true;

        let mut request = REQUEST_START.to_string();

        request.push_str("\r\n");

        let res = parse_request(&config, request.as_bytes());

        assert!(matches!(
            res,
            Err(RequestParseError::RequiredPeerIpHeaderMissing(_))
        ));
    }

    #[test]
    fn test_parse_invalid_complete_request() {
        let config = Config::default();
        let res = parse_request(
            &config,
            b"GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );

        assert!(matches!(res, Err(RequestParseError::InvalidRequest(_))));
    }

    #[test]
    fn test_parse_static_index_request() {
        let config = Config::default();

        for path in ["/", "/index.html"] {
            let request = format!("GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n");
            let (request, opt_peer_ip) = parse_request(&config, request.as_bytes()).unwrap();

            assert_eq!(request, HttpRequest::StaticIndex);
            assert!(opt_peer_ip.is_none());
        }

        let mut request = String::from("GET / HTTP/1.1\r\n");

        for index in 0..32 {
            request.push_str(&format!("X-Test-{index}: value\r\n"));
        }

        request.push_str("\r\n");

        let (request, opt_peer_ip) = parse_request(&config, request.as_bytes()).unwrap();

        assert_eq!(request, HttpRequest::StaticIndex);
        assert!(opt_peer_ip.is_none());
    }
}
