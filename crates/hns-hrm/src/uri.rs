//! Shared RFC 3986 syntax validation for untrusted retrieval locators.
//!
//! HRM does not assign authority to a locator or prescribe which URI schemes
//! an adapter may dereference. This module therefore validates only the
//! generic, ASCII URI syntax. Scheme and network-access policy stays with the
//! retrieval adapter.

/// Return whether `value` is an RFC 3986 URI reference with an explicit scheme.
///
/// A single fragment is accepted because it is part of the generic `URI`
/// production. Callers still authenticate the complete retrieved object by
/// hash. Empty scheme-specific parts are rejected because HRM locators must
/// identify something retrievable.
pub(crate) fn is_valid_absolute_uri(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_graphic) {
        return false;
    }

    let Some(colon) = bytes.iter().position(|byte| *byte == b':') else {
        return false;
    };
    if colon == 0
        || colon + 1 == bytes.len()
        || !bytes[0].is_ascii_alphabetic()
        || !bytes[1..colon]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return false;
    }

    let reference = &bytes[colon + 1..];
    let without_fragment = match split_once(reference, b'#') {
        Some((before, after)) => {
            if after.contains(&b'#') || !valid_query_or_fragment(after) {
                return false;
            }
            before
        }
        None => reference,
    };

    let (hier_part, query) = match split_once(without_fragment, b'?') {
        Some((before, after)) => (before, Some(after)),
        None => (without_fragment, None),
    };
    if query.is_some_and(|query| !valid_query_or_fragment(query)) {
        return false;
    }

    valid_hier_part(hier_part)
}

fn valid_hier_part(bytes: &[u8]) -> bool {
    if let Some(authority_and_path) = bytes.strip_prefix(b"//") {
        let path_start = authority_and_path
            .iter()
            .position(|byte| *byte == b'/')
            .unwrap_or(authority_and_path.len());
        let (authority, path) = authority_and_path.split_at(path_start);
        return valid_authority(authority) && valid_path_abempty(path);
    }

    if bytes.is_empty() {
        return true;
    }
    if bytes[0] == b'/' {
        return valid_path_absolute(bytes);
    }
    valid_path_rootless(bytes)
}

fn valid_authority(bytes: &[u8]) -> bool {
    let host_and_port = match rsplit_once(bytes, b'@') {
        Some((before, after)) => {
            if before.contains(&b'@') || !valid_component(before, is_userinfo_byte) {
                return false;
            }
            after
        }
        None => bytes,
    };

    if host_and_port.starts_with(b"[") {
        let Some(close) = host_and_port.iter().position(|byte| *byte == b']') else {
            return false;
        };
        let literal = &host_and_port[1..close];
        let suffix = &host_and_port[close + 1..];
        return valid_ip_literal(literal) && valid_port_suffix(suffix);
    }

    if host_and_port.contains(&b'[') || host_and_port.contains(&b']') {
        return false;
    }

    let (host, port) = match rsplit_once(host_and_port, b':') {
        Some((before, after)) => {
            if before.contains(&b':') {
                return false;
            }
            (before, Some(after))
        }
        None => (host_and_port, None),
    };

    valid_component(host, is_reg_name_byte)
        && port.is_none_or(|port| port.iter().all(u8::is_ascii_digit))
}

fn valid_port_suffix(bytes: &[u8]) -> bool {
    bytes.is_empty()
        || bytes
            .strip_prefix(b":")
            .is_some_and(|port| port.iter().all(u8::is_ascii_digit))
}

fn valid_ip_literal(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    text.parse::<std::net::Ipv6Addr>().is_ok() || valid_ipvfuture(bytes)
}

fn valid_ipvfuture(bytes: &[u8]) -> bool {
    let Some(version_and_address) = bytes
        .strip_prefix(b"v")
        .or_else(|| bytes.strip_prefix(b"V"))
    else {
        return false;
    };
    let Some((version, address)) = split_once(version_and_address, b'.') else {
        return false;
    };
    !version.is_empty()
        && version.iter().all(u8::is_ascii_hexdigit)
        && !address.is_empty()
        && address
            .iter()
            .all(|byte| is_unreserved(*byte) || is_sub_delimiter(*byte) || *byte == b':')
}

fn valid_path_abempty(bytes: &[u8]) -> bool {
    (bytes.is_empty() || bytes[0] == b'/') && valid_component(bytes, is_path_byte)
}

fn valid_path_absolute(bytes: &[u8]) -> bool {
    bytes[0] == b'/'
        && (bytes.len() == 1 || bytes[1] != b'/')
        && valid_component(bytes, is_path_byte)
}

fn valid_path_rootless(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes[0] != b'/' && valid_component(bytes, is_path_byte)
}

fn valid_query_or_fragment(bytes: &[u8]) -> bool {
    valid_component(bytes, is_query_or_fragment_byte)
}

fn valid_component(bytes: &[u8], allowed: fn(u8) -> bool) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else if allowed(bytes[index]) {
            index += 1;
        } else {
            return false;
        }
    }
    true
}

fn is_userinfo_byte(byte: u8) -> bool {
    is_unreserved(byte) || is_sub_delimiter(byte) || byte == b':'
}

fn is_reg_name_byte(byte: u8) -> bool {
    is_unreserved(byte) || is_sub_delimiter(byte)
}

fn is_path_byte(byte: u8) -> bool {
    is_pchar(byte) || byte == b'/'
}

fn is_query_or_fragment_byte(byte: u8) -> bool {
    is_pchar(byte) || matches!(byte, b'/' | b'?')
}

fn is_pchar(byte: u8) -> bool {
    is_unreserved(byte) || is_sub_delimiter(byte) || matches!(byte, b':' | b'@')
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn is_sub_delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

fn split_once(bytes: &[u8], delimiter: u8) -> Option<(&[u8], &[u8])> {
    let index = bytes.iter().position(|byte| *byte == delimiter)?;
    Some((&bytes[..index], &bytes[index + 1..]))
}

fn rsplit_once(bytes: &[u8], delimiter: u8) -> Option<(&[u8], &[u8])> {
    let index = bytes.iter().rposition(|byte| *byte == delimiter)?;
    Some((&bytes[..index], &bytes[index + 1..]))
}

#[cfg(test)]
mod tests {
    use super::is_valid_absolute_uri;

    #[test]
    fn accepts_rfc3986_absolute_uri_forms() {
        for uri in [
            "https://example.test/a/b?x=1%202#part",
            "https://user:password@example.test:443/a",
            "https://[2001:db8::1]:443/a",
            "https://[::ffff:192.0.2.128]/a",
            "scheme://[v1.fe80]:9/path",
            "ipfs:bafybeigdyrzt",
            "urn:example:animal:ferret:nose",
            "file:///var/lib/hrm/object",
            "custom:/absolute/path",
            "custom:rootless/path",
            "custom:?query",
        ] {
            assert!(is_valid_absolute_uri(uri), "rejected valid URI {uri:?}");
        }
    }

    #[test]
    fn rejects_malformed_absolute_uri_forms() {
        for uri in [
            "",
            "relative/path",
            ":missing-scheme",
            "1https://example.test/a",
            "ht*ps://example.test/a",
            "https:",
            "https://example.test/a b",
            "https://example.test/%",
            "https://example.test/%0",
            "https://example.test/%q0",
            "https://example.test/\\path",
            "https://[",
            "https://[]/a",
            "https://[2001:db8::1/a",
            "https://2001:db8::1/a",
            "https://exa[mple.test/a",
            "https://example.test:port/a",
            "https://one@example.test@evil.test/a",
            "https://example.test/a#one#two",
            "https://example.test/[path]",
            "scheme://[v.fe80]/path",
            "scheme://[v1.]/path",
            "scheme://[v1.bad%20address]/path",
        ] {
            assert!(!is_valid_absolute_uri(uri), "accepted invalid URI {uri:?}");
        }
    }
}
