//! Base64 (RFC 4648 §4, the standard alphabet, padded) - encode only.
//!
//! Two callers, both in the WebSocket handshake: `Sec-WebSocket-Key` (16
//! random bytes out) and the expected `Sec-WebSocket-Accept` (a SHA-1
//! digest out). The inbound direction never decodes base64 - the accept
//! value is compared in its encoded form - so no decoder exists to get
//! wrong.

const ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `data` with padding.
pub(crate) fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let (chunks, remainder) = data.as_chunks::<3>();
    for c in chunks {
        let n =
            (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        out.push(ALPHABET[n as usize & 63] as char);
    }
    match *remainder {
        [a] => {
            let n = u32::from(a) << 16;
            out.push(ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(ALPHABET[(n >> 12) as usize & 63] as char);
            out.push_str("==");
        }
        [a, b] => {
            let n = (u32::from(a) << 16) | (u32::from(b) << 8);
            out.push(ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(ALPHABET[(n >> 12) as usize & 63] as char);
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::encode;

    /// All seven RFC 4648 §10 vectors: every remainder length, both padded
    /// forms.
    #[test]
    fn rfc4648_vectors() {
        for (input, want) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(input), want, "encode({input:?})");
        }
    }
}
