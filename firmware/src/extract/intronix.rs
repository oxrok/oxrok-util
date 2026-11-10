// Port of oxrok-util's former firmware/intronix-logicport/sigrok-fwextract-intronix-logicport,
// GPL-3.0-or-later like it.

//! Intronix `LogicPort`: `LogicPort.ccf`, from the installer or as is.
//!
//! The installer's payload is a list of `LS\x03\x04` entries, each a
//! name and a (here Deflate64) compressed body. The `.ccf` is installed
//! unmodified; its header is checked, and each of its eight images must
//! decode to an Altera bitstream.

use super::{Extracted, u16_le, u32_le};
use crate::error::{Error, Result};
use crate::input::Input;
use crate::registry::Package;
use std::io::Read;

const OUTPUT: &str = "intronix-logicport.ccf";
const ENTRY_MAGIC: &[u8] = b"LS\x03\x04";

pub(crate) fn extract(_pkg: &Package, input: &mut Input, out: &mut Extracted) -> Result<()> {
    // `n` is lowercased by `Input`.
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    let path = input.find_one_or_given("LogicPort.ccf or logicport_*.exe", |n| {
        n == "logicport.ccf" || n == OUTPUT || (n.starts_with("logicport") && n.ends_with(".exe"))
    })?;
    let data = std::fs::read(&path)?;
    let ccf = if data.starts_with(b"MZ") { ccf_from_installer(&data)? } else { data };
    check_ccf(&ccf)?;
    out.add(OUTPUT, ccf);
    Ok(())
}

/// Finds and inflates the `.ccf` entry in the installer.
fn ccf_from_installer(exe: &[u8]) -> Result<Vec<u8>> {
    let bad = |m: &str| Error::format("LogicPort installer", m.to_owned());
    let mut i = find(exe, ENTRY_MAGIC).ok_or_else(|| bad("no LogicPort.ccf found"))?;
    while exe.get(i..i + 4) == Some(ENTRY_MAGIC) {
        let method = u16_le(exe, i + 0x08).ok_or_else(|| bad("truncated entry"))?;
        let csize = u32_le(exe, i + 0x2a).ok_or_else(|| bad("truncated entry"))? as usize;
        let usize_ = u32_le(exe, i + 0x2e).ok_or_else(|| bad("truncated entry"))? as usize;
        let namelen = u32_le(exe, i + 0x3a).ok_or_else(|| bad("truncated entry"))? as usize;
        let name = exe.get(i + 0x3e..i + 0x3e + namelen).ok_or_else(|| bad("truncated entry"))?;
        let body = i + 0x3e + namelen;
        if name.to_ascii_lowercase().ends_with(b".ccf") {
            let raw = exe.get(body..body + csize).ok_or_else(|| bad("truncated entry"))?;
            return inflate(method, raw, usize_);
        }
        i = body + csize;
    }
    Err(bad("no LogicPort.ccf found"))
}

fn inflate(method: u16, raw: &[u8], size: usize) -> Result<Vec<u8>> {
    // `size` comes from the file: reserve little up front, and read one
    // byte past it at most, so a lying header fails the size check below
    // instead of exhausting memory.
    let mut out = Vec::with_capacity(size.min(1 << 24));
    let limit = (size as u64).saturating_add(1);
    let r = match method {
        0 => {
            out.extend_from_slice(raw);
            Ok(0)
        }
        8 => flate2::read::DeflateDecoder::new(raw).take(limit).read_to_end(&mut out),
        9 => deflate64::Deflate64Decoder::new(raw).take(limit).read_to_end(&mut out),
        m => return Err(Error::format("LogicPort installer", format!("compression method {m}"))),
    };
    r.map_err(|e| Error::format("LogicPort installer", e.to_string()))?;
    if out.len() != size {
        return Err(Error::format(
            "LogicPort installer",
            "LogicPort.ccf inflates to the wrong size",
        ));
    }
    Ok(out)
}

/// The header (image sizes in 16 byte units, XOR obfuscated, and a
/// checksum), the file size, and an RBF header in every image.
fn check_ccf(data: &[u8]) -> Result<()> {
    let bad = |m: &str| Error::format("LogicPort.ccf", m.to_owned());
    let eol = find(data, b"\r\n").ok_or_else(|| bad("not a LogicPort.ccf file"))?;
    let header = std::str::from_utf8(&data[..eol]).map_err(|_| bad("not a LogicPort.ccf file"))?;
    let lens: Vec<u32> = header
        .split(',')
        .map(|x| x.trim().parse::<u32>().map(|v| v ^ 0x91_6662))
        .collect::<Result<_, _>>()
        .map_err(|_| bad("not a LogicPort.ccf file"))?;
    if lens.len() != 9 {
        return Err(bad("not a LogicPort.ccf file"));
    }
    if lens[..8].iter().fold(0, |a, v| a ^ v) != lens[8] {
        return Err(bad("header checksum mismatch"));
    }
    let total: usize = lens[..8].iter().map(|v| *v as usize * 16).sum();
    if eol + 2 + total != data.len() {
        return Err(bad("unexpected file size"));
    }
    // Each image is a bit-bang stream, two bytes per bit with the data in
    // bit 0, its first two 4 KiB blocks swapped.
    let mut off = eol + 2;
    for (i, v) in lens[..8].iter().enumerate() {
        let len = *v as usize * 16;
        let mut seg = data[off..off + len].to_vec();
        off += len;
        if seg.len() < 8192 {
            return Err(bad("image too short"));
        }
        let (a, b) = seg.split_at_mut(4096);
        a.swap_with_slice(&mut b[..4096]);
        let head: Vec<u8> = (0..17)
            .map(|byte| (0..8).fold(0u8, |acc, k| acc | ((seg[(byte * 8 + k) * 2] & 1) << k)))
            .collect();
        if head[..16] != [0xff; 16] || head[16] != 0x6a {
            return Err(bad(&format!("image {i} is not an Altera bitstream")));
        }
    }
    Ok(())
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A .ccf with eight one-segment images, each the RBF header bits.
    fn ccf() -> Vec<u8> {
        let mut image = vec![0u8; 8192 + 32];
        let header: Vec<u8> = [0xffu8; 16].into_iter().chain([0x6a]).collect();
        for (byte, v) in header.iter().enumerate() {
            for k in 0..8 {
                image[(byte * 8 + k) * 2] = (v >> k) & 1;
            }
        }
        // Stored with its first two 4 KiB blocks swapped.
        let (a, b) = image.split_at_mut(4096);
        a.swap_with_slice(&mut b[..4096]);
        let units = (image.len() / 16) as u32;
        let mut lens = vec![units; 8];
        lens.push(0);
        // Eight equal sizes XOR to 0, the checksum pushed above.
        let text: Vec<String> = lens.iter().map(|v| (v ^ 0x91_6662).to_string()).collect();
        let mut out = text.join(",").into_bytes();
        out.extend_from_slice(b"\r\n");
        for _ in 0..8 {
            out.extend_from_slice(&image);
        }
        out
    }

    #[test]
    fn accepts_a_well_formed_ccf() {
        check_ccf(&ccf()).unwrap();
    }

    #[test]
    fn refuses_a_broken_checksum_or_size() {
        let mut c = ccf();
        c.push(0);
        assert!(check_ccf(&c).is_err());
        assert!(check_ccf(b"1,2,3\r\n").is_err());
    }

    #[test]
    fn finds_the_ccf_entry_in_an_installer() {
        let body = ccf();
        let mut exe = b"MZ....".to_vec();
        // An entry before it, then the .ccf, stored.
        for (name, data) in [(&b"readme.txt"[..], &b"hello"[..]), (b"LogicPort.ccf", &body)] {
            let mut e = vec![0u8; 0x3e];
            e[..4].copy_from_slice(ENTRY_MAGIC);
            e[0x2a..0x2e].copy_from_slice(&(data.len() as u32).to_le_bytes());
            e[0x2e..0x32].copy_from_slice(&(data.len() as u32).to_le_bytes());
            e[0x3a..0x3e].copy_from_slice(&(name.len() as u32).to_le_bytes());
            exe.extend_from_slice(&e);
            exe.extend_from_slice(name);
            exe.extend_from_slice(data);
        }
        assert_eq!(ccf_from_installer(&exe).unwrap(), body);
    }
}
