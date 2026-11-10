//! The extractors, ports of sigrok-util's `firmware/` scripts.

pub(crate) mod hantek;
pub(crate) mod intronix;
pub(crate) mod kingst;
pub(crate) mod lecroy;
pub(crate) mod saleae;
pub(crate) mod sysclk;

use crate::error::{Error, Result};
use std::collections::BTreeMap;

/// What an extractor produced.
#[derive(Debug, Default)]
pub(crate) struct Extracted {
    /// File name to contents.
    pub files: BTreeMap<String, Vec<u8>>,
    /// Things to tell the user.
    pub warnings: Vec<String>,
}

impl Extracted {
    pub fn add(&mut self, name: impl Into<String>, data: Vec<u8>) {
        let name = name.into();
        log::debug!("Extracted {name}, {} bytes.", data.len());
        self.files.insert(name, data);
    }
}

/// `data[start..start + len]`, or a format error naming `what`.
pub(crate) fn slice<'a>(data: &'a [u8], start: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    start
        .checked_add(len)
        .and_then(|end| data.get(start..end))
        .ok_or_else(|| Error::format(what, format!("too short for {len} bytes at offset {start}")))
}

pub(crate) fn u16_le(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(at..at + 2)?.try_into().ok()?))
}

pub(crate) fn u32_le(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(at..at + 4)?.try_into().ok()?))
}

pub(crate) fn u16_be(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(d.get(at..at + 2)?.try_into().ok()?))
}

pub(crate) fn u32_be(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(at..at + 4)?.try_into().ok()?))
}

/// One Intel HEX record: its type, address and data, its checksum
/// checked.
pub(crate) struct Record<'a> {
    pub kind: u8,
    pub address: u16,
    pub data: &'a [u8],
}

/// Decodes a record's bytes (the line after `:`, from hex).
pub(crate) fn ihex_record(bytes: &[u8]) -> Result<Record<'_>> {
    let bad = |msg: &str| Error::format("Intel HEX", msg.to_owned());
    if bytes.len() < 5 {
        return Err(bad("record too short"));
    }
    if bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b)) != 0 {
        return Err(bad("checksum mismatch"));
    }
    let count = usize::from(bytes[0]);
    if bytes.len() != count + 5 {
        return Err(bad("record length mismatch"));
    }
    Ok(Record {
        kind: bytes[3],
        address: u16::from_be_bytes([bytes[1], bytes[2]]),
        data: &bytes[4..4 + count],
    })
}

/// Hex text to bytes.
pub(crate) fn unhex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(Error::format("Intel HEX", "odd number of hex digits"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| Error::format("Intel HEX", "not hex"))
        })
        .collect()
}

/// Reverses the bits of every byte.
pub(crate) fn reverse_bits(data: &[u8]) -> Vec<u8> {
    data.iter().map(|b| b.reverse_bits()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ihex_record_checks_its_checksum() {
        let bytes = unhex("0300300002337A1E").unwrap();
        let r = ihex_record(&bytes).unwrap();
        assert_eq!((r.kind, r.address, r.data), (0, 0x0030, &[0x02, 0x33, 0x7a][..]));
        assert!(ihex_record(&unhex("0300300002337A1F").unwrap()).is_err());
    }

    #[test]
    fn slice_refuses_short_data() {
        assert!(slice(b"abc", 2, 2, "x").is_err());
        assert_eq!(slice(b"abc", 1, 2, "x").unwrap(), b"bc");
    }
}
