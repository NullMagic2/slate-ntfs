//! Module: ntfs_rs::linux_names
//! Purpose: Convert Linux byte names and NTFS UTF-16 names reversibly.
//! Created: 2026-10-01
//! Architecture: Namespace adapters share generalized UTF-8 and surrogateescape conversion.
//! Valid UTF-8 becomes UTF-16; invalid bytes use DC80..DCFF escapes. Other lone
//! surrogates are retained unless they would pair, when their bytes are escaped.
//! Linux names round-trip exactly; Windows escape-range names retain lookup
//! through their decoded bytes, including when those bytes form valid UTF-8.

use super::{Error, Result};

pub const MAX_UNITS: usize = 255;
/// Longest byte form of a 255-unit name (three bytes per unit).
pub const MAX_DECODED: usize = 3 * MAX_UNITS;

#[derive(Clone, Copy)]
enum Token {
    Char(char),
    Surrogate(u16, [u8; 3]),
    Byte(u8),
}

fn next_token(bytes: &[u8]) -> (Token, usize) {
    let b0 = bytes[0];
    if b0 < 0x80 {
        return (Token::Char(char::from(b0)), 1);
    }
    let need = match b0 {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return (Token::Byte(b0), 1),
    };
    if bytes.len() < need || !bytes[1..need].iter().all(|b| b & 0xc0 == 0x80) {
        return (Token::Byte(b0), 1);
    }
    if b0 == 0xed && bytes[1] >= 0xa0 {
        let unit = 0xd000 | (u16::from(bytes[1] & 0x3f) << 6) | u16::from(bytes[2] & 0x3f);
        // Escape-range units are reserved for single invalid bytes.
        if (0xdc80..=0xdcff).contains(&unit) {
            return (Token::Byte(b0), 1);
        }
        return (Token::Surrogate(unit, [bytes[0], bytes[1], bytes[2]]), 3);
    }
    match core::str::from_utf8(&bytes[..need]) {
        Ok(text) => match text.chars().next() {
            Some(c) => (Token::Char(c), need),
            None => (Token::Byte(b0), 1),
        },
        Err(_) => (Token::Byte(b0), 1),
    }
}

fn first_unit(token: Token) -> u16 {
    match token {
        Token::Char(c) => {
            let mut units = [0u16; 2];
            c.encode_utf16(&mut units)[0]
        }
        Token::Surrogate(unit, _) => unit,
        Token::Byte(b) => 0xdc00 | u16::from(b),
    }
}

fn is_high(token: Token) -> bool {
    matches!(token, Token::Surrogate(u, _) if (0xd800..0xdc00).contains(&u))
}

/// Encode Linux name bytes as UTF-16LE into out. Returns the byte length.
/// Empty names, ./.., /, NUL and names over 255 units are refused.
/// Uses no large stack buffers: it runs inside kernel callbacks.
pub fn encode(name: &[u8], out: &mut [u8]) -> Result<usize> {
    if name.is_empty() || name == b"." || name == b".." || name.len() > 4096 {
        return Err(Error::Unsupported);
    }
    if name.iter().any(|b| *b == 0 || *b == b'/') {
        return Err(Error::Unsupported);
    }
    let mut n = 0;
    let mut push = |unit: u16, n: &mut usize| -> Result<()> {
        if *n / 2 >= MAX_UNITS || *n + 2 > out.len() {
            return Err(Error::Unsupported);
        }
        out[*n..*n + 2].copy_from_slice(&unit.to_le_bytes());
        *n += 2;
        Ok(())
    };
    let mut at = 0;
    // A run of generalized-UTF-8 high surrogates is stored as surrogates
    // unless the unit after the run is a low surrogate, which would pair
    // with the run's last unit; then the whole run is stored as escapes.
    let mut run_escaped = false;
    let mut in_run = false;
    while at < name.len() {
        let (token, used) = next_token(&name[at..]);
        if is_high(token) {
            if !in_run {
                in_run = true;
                let mut ahead = at;
                let mut following = None;
                while ahead < name.len() {
                    let (t, u) = next_token(&name[ahead..]);
                    if !is_high(t) {
                        following = Some(t);
                        break;
                    }
                    ahead += u;
                }
                run_escaped = following.is_some_and(|t| (0xdc00..0xe000).contains(&first_unit(t)));
            }
        } else {
            in_run = false;
        }
        match token {
            Token::Char(c) => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    push(*unit, &mut n)?;
                }
            }
            Token::Surrogate(unit, raw) => {
                if in_run && run_escaped {
                    for b in raw {
                        push(0xdc00 | u16::from(b), &mut n)?;
                    }
                } else {
                    push(unit, &mut n)?;
                }
            }
            Token::Byte(b) => push(0xdc00 | u16::from(b), &mut n)?,
        }
        at += used;
    }
    Ok(n)
}

/// Decode NTFS UTF-16LE name units into Linux bytes. Returns the length, or
/// Unsupported when the name contains / or NUL or does not fit out.
pub fn decode(units: impl Iterator<Item = u16>, out: &mut [u8]) -> Result<usize> {
    decode_impl(units, out, false)
}

/// Decode a path (for example a symlink target), where / separates names.
pub fn decode_path(units: impl Iterator<Item = u16>, out: &mut [u8]) -> Result<usize> {
    decode_impl(units, out, true)
}

fn decode_impl(units: impl Iterator<Item = u16>, out: &mut [u8], path: bool) -> Result<usize> {
    let mut n = 0;
    let mut put = |bytes: &[u8], n: &mut usize| -> Result<()> {
        let end = n.checked_add(bytes.len()).ok_or(Error::Overflow)?;
        out.get_mut(*n..end).ok_or(Error::Unsupported)?.copy_from_slice(bytes);
        *n = end;
        Ok(())
    };
    for decoded in core::char::decode_utf16(units) {
        match decoded {
            Ok(c) => {
                if (c == '/' && !path) || c == '\0' {
                    return Err(Error::Unsupported);
                }
                let mut buffer = [0u8; 4];
                put(c.encode_utf8(&mut buffer).as_bytes(), &mut n)?;
            }
            Err(error) => {
                let unit = error.unpaired_surrogate();
                if (0xdc80..=0xdcff).contains(&unit) {
                    put(&[(unit & 0xff) as u8], &mut n)?;
                } else {
                    put(&[0xed, 0x80 | ((unit >> 6) & 0x3f) as u8, 0x80 | (unit & 0x3f) as u8], &mut n)?;
                }
            }
        }
    }
    Ok(n)
}

/// Punctuation Win32 forbids in a name component; path separators are separate.
pub const WINDOWS_RESERVED_CHARS: [char; 8] = ['"', '*', ':', '<', '>', '?', '\\', '|'];

/// Added to a Win32-forbidden character to store it in a name. Both views do
/// this, so a program that needs such a name (Wine creates `c:`) works on an
/// ordinary mount. Windows, its checker and WSL accept the resulting private-use
/// character, and WSL shows the original character again; stored unchanged,
/// the name would be evicted from its directory by a Windows check.
pub const RESERVED_ESCAPE: u16 = 0xf000;
const ASCII_UNITS: u16 = 0x80;

/// A UTF-16 unit Win32 forbids inside a name: a control or reserved character.
fn reserved_unit(unit: u16) -> bool {
    (1..u16::from(b' ')).contains(&unit) || WINDOWS_RESERVED_CHARS.iter().any(|c| *c as u16 == unit)
}

/// The unit a mounted view shows for a stored unit.
pub fn unescaped_unit(unit: u16) -> u16 {
    let plain = unit & (ASCII_UNITS - 1);
    if unit & !(ASCII_UNITS - 1) == RESERVED_ESCAPE && reserved_unit(plain) {
        plain
    } else {
        unit
    }
}

/// `encode` for a name as either view stores it: Win32-forbidden characters
/// are escaped. Returns the byte length, which escaping does not change.
pub fn encode_linux(name: &[u8], out: &mut [u8]) -> Result<usize> {
    let n = encode(name, out)?;
    for unit in out[..n].chunks_exact_mut(2) {
        let value = u16::from_le_bytes([unit[0], unit[1]]);
        if reserved_unit(value) {
            unit.copy_from_slice(&(value | RESERVED_ESCAPE).to_le_bytes());
        }
    }
    Ok(n)
}

/// `decode` for a stored name: the inverse of `encode_linux`.
pub fn decode_linux(units: impl Iterator<Item = u16>, out: &mut [u8]) -> Result<usize> {
    decode(units.map(unescaped_unit), out)
}

/// Windows reserved device names, which Win32 cannot open as ordinary files
/// regardless of extension (CON, NUL.txt, COM1, ...).
pub fn windows_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let mut upper = [0u8; 4];
    if stem.len() > 4 || !stem.is_ascii() {
        return false;
    }
    for (i, b) in stem.bytes().enumerate() {
        upper[i] = b.to_ascii_uppercase();
    }
    let stem = &upper[..stem.len()];
    matches!(stem, b"CON" | b"PRN" | b"AUX" | b"NUL")
        || (stem.len() == 4
            && (stem.starts_with(b"COM") || stem.starts_with(b"LPT"))
            && (b'1'..=b'9').contains(&stem[3]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn round(bytes: &[u8]) -> Vec<u8> {
        let mut utf = [0u8; 1024];
        let n = encode(bytes, &mut utf).unwrap();
        let mut out = [0u8; MAX_DECODED];
        let m = decode(super::super::bytes::units(&utf[..n]), &mut out).unwrap();
        out[..m].to_vec()
    }

    #[test]
    fn byte_names_round_trip() {
        for name in [
            &b"plain.txt"[..],
            "caf\u{e9}".as_bytes(),
            "\u{1f600}x".as_bytes(),
            b"\xff\xfe",
            b"a\x80b",
            b"\xed\xa0\x80",
            b"\xed\xa0\x80\xed\xb0\x80",
            b"\xed\xa0\x80\x80",
            b"\xed\xb2\x80",
            b"\xc3",
            b"\xf0\x9f\x98",
            b"x:*?<>|\\ .",
        ] {
            assert_eq!(round(name), name, "{name:?}");
        }
        let mut all = Vec::new();
        for b in 1..=255u8 {
            if b != b'/' {
                all.push(b);
            }
        }
        for chunk in all.chunks(200) {
            assert_eq!(round(chunk), chunk);
        }
    }

    #[test]
    fn refused_names_and_reserved_devices() {
        let mut utf = [0u8; 1024];
        for bad in [&b""[..], b".", b"..", b"a/b", b"a\0b"] {
            assert!(encode(bad, &mut utf).is_err());
        }
        assert!(encode(&[b'a'; 256], &mut utf).is_err());
        assert!(encode(&[b'a'; 255], &mut utf).is_ok());
        assert!(windows_reserved("con"));
        assert!(windows_reserved("NUL.txt"));
        assert!(windows_reserved("com7.log"));
        assert!(!windows_reserved("console"));
        assert!(!windows_reserved("com0"));
    }

    #[test]
    fn linux_view_escapes_win32_forbidden_characters_reversibly() {
        let mut utf = [0u8; 510];
        let mut back = [0u8; MAX_DECODED];
        for name in [&b"c:"[..], b"a:b?<>|\"*\\.txt", b"tab\there", b"plain.txt", "caf\u{e9}".as_bytes()] {
            let n = encode_linux(name, &mut utf).unwrap();
            let units = || utf[..n].chunks_exact(2).map(|u| u16::from_le_bytes([u[0], u[1]]));
            assert!(units().all(|unit| !reserved_unit(unit)), "{name:?} keeps a forbidden unit");
            let m = decode_linux(units(), &mut back).unwrap();
            assert_eq!(&back[..m], name);
        }
        let n = encode_linux(b"c:", &mut utf).unwrap();
        assert_eq!(&utf[..n], &[b'c', 0, 0x3a, 0xf0]);
        // Private-use characters outside the escaped set are left alone.
        assert_eq!(unescaped_unit(0xf041), 0xf041);
        assert_eq!(unescaped_unit(0xf03a), u16::from(b':'));
        // A name without forbidden characters is stored unchanged.
        assert_eq!(encode_linux(b"plain", &mut utf).unwrap(), encode(b"plain", &mut back).unwrap());
    }
}
