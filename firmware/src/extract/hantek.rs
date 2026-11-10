// Port of sigrok-util/firmware/hantek-dso/{sigrok-fwextract-hantek-dso,parsepe.py},
// GPL-3.0-or-later like them.

//! Hantek DSO-2xxx/52xx: the FX2 firmware in the 32-bit loader driver.
//!
//! The driver (`DsoXXXXX861.sys`) keeps the firmware as the `_firmware`
//! symbol of its COFF symbol table: a list of 22 byte write records
//! (length, address, a zero flag, up to 16 bytes) that [`unsparse`]
//! lays out as the FX2's RAM image.

use super::{Extracted, u16_le, u32_le};
use crate::error::{Error, Result};
use crate::input::Input;
use crate::registry::Package;

/// The FX2's RAM; writes above it go to registers.
const RAM: usize = 0x4000;
const RECORD: usize = 22;

pub(crate) fn extract(pkg: &Package, input: &mut Input, out: &mut Extracted) -> Result<()> {
    let file = pkg.files[0];
    let model = file
        .strip_prefix("hantek-dso-")
        .and_then(|s| s.strip_suffix(".fw"))
        .ok_or_else(|| Error::format(file, "not a Hantek DSO firmware name"))?;
    let want = format!("dso{}x861.sys", model.to_lowercase());
    let path = input.find_one_or_given(&want, |n| n == want)?;
    let driver = std::fs::read(&path)?;
    let records = symbol(&driver, "_firmware")?
        .ok_or_else(|| Error::format(path.display().to_string(), "no firmware found"))?;
    out.add(file, unsparse(records)?);
    Ok(())
}

/// The data of external symbol `name` in a PE file's COFF symbol table.
///
/// As `parsepe.py`: a symbol's size runs to the next symbol's value, and
/// is known only for symbols whose section number is 2; the value is
/// used as a file offset.
fn symbol<'a>(pe: &'a [u8], name: &str) -> Result<Option<&'a [u8]>> {
    let bad = |m: &str| Error::format("PE file", m.to_owned());
    if !pe.starts_with(b"MZ") {
        return Err(bad("MZ signature not found"));
    }
    let pe_ptr = u32_le(pe, 0x3c).ok_or_else(|| bad("truncated"))? as usize;
    if pe.get(pe_ptr..pe_ptr + 4) != Some(b"PE\0\0") {
        return Err(bad("PE signature not found"));
    }
    let symtab = u32_le(pe, pe_ptr + 12).ok_or_else(|| bad("truncated"))? as usize;
    let count = u32_le(pe, pe_ptr + 16).ok_or_else(|| bad("truncated"))? as usize;
    let strtab = symtab + count * 18;

    // (name, value, size) in table order.
    let mut symbols: Vec<(String, usize, Option<usize>)> = Vec::new();
    for i in 0..count {
        let at = symtab + i * 18;
        let raw = pe.get(at..at + 18).ok_or_else(|| bad("symbol table truncated"))?;
        let value = u32_le(raw, 8).expect("in range") as usize;
        let section_lo = raw[12];
        let sym_name = if raw[..4] == [0; 4] {
            let off =
                strtab.wrapping_add(i32::from_le_bytes(raw[4..8].try_into().expect("4")) as usize);
            let s = pe.get(off..pe.len().min(off + 64)).unwrap_or(&[]);
            String::from_utf8_lossy(&s[..s.iter().position(|b| *b == 0).unwrap_or(s.len())])
                .into_owned()
        } else {
            let s = &raw[..8];
            String::from_utf8_lossy(&s[..s.iter().position(|b| *b == 0).unwrap_or(8)]).into_owned()
        };
        if let Some(last) = symbols.last_mut()
            && last.2.is_some()
            && value > last.1
        {
            last.2 = Some(value - last.1);
        }
        symbols.push((sym_name, value, (section_lo == 2).then_some(0)));
    }
    let Some((_, value, size)) = symbols.into_iter().find(|s| s.0 == name) else { return Ok(None) };
    let size = size.ok_or_else(|| bad(&format!("symbol {name} found, but has unknown size")))?;
    pe.get(value..value + size).map(Some).ok_or_else(|| bad("short file"))
}

/// Lays the write records out as the FX2's RAM, up to the highest
/// address written; register writes (above the RAM) are skipped.
fn unsparse(records: &[u8]) -> Result<Vec<u8>> {
    let mut blob = vec![0u8; RAM];
    let mut max = 0;
    let mut p = 0;
    while p + 5 <= records.len() && records[p + 4] == 0 {
        let len = usize::from(u16_le(records, p).expect("in range"));
        let address = usize::from(u16_le(records, p + 2).expect("in range"));
        let chunk = records
            .get(p + 5..p + 5 + len)
            .ok_or_else(|| Error::format("Hantek firmware", "record runs past the end"))?;
        p += RECORD;
        if address > RAM {
            continue;
        }
        if address + len > blob.len() {
            blob.resize(address + len, 0);
        }
        blob[address..address + len].copy_from_slice(chunk);
        max = max.max(address + len);
    }
    if max == 0 {
        return Err(Error::format("Hantek firmware", "no firmware records"));
    }
    blob.truncate(max);
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(address: u16, data: &[u8], flag: u8) -> Vec<u8> {
        let mut r = vec![0u8; RECORD];
        r[..2].copy_from_slice(&(data.len() as u16).to_le_bytes());
        r[2..4].copy_from_slice(&address.to_le_bytes());
        r[4] = flag;
        r[5..5 + data.len()].copy_from_slice(data);
        r
    }

    #[test]
    fn unsparse_lays_out_ram_and_skips_registers() {
        let mut recs = record(0, &[0x02, 0x00, 0x80], 0);
        recs.extend(record(0xe600, &[1], 0)); // CPUCS, a register
        recs.extend(record(0x10, &[0xaa, 0xbb], 0));
        recs.extend(record(0, &[], 1)); // the end marker
        recs.extend(record(0x20, &[0xff], 0)); // after it: ignored
        let blob = unsparse(&recs).unwrap();
        assert_eq!(blob.len(), 0x12);
        assert_eq!(&blob[..3], &[0x02, 0x00, 0x80]);
        assert_eq!(&blob[0x10..], &[0xaa, 0xbb]);
    }

    #[test]
    fn unsparse_without_an_end_marker_stops_at_the_end() {
        // The Python version raised IndexError here.
        let recs = record(0, &[1, 2], 0);
        assert_eq!(unsparse(&recs).unwrap(), vec![1, 2]);
    }

    /// A minimal PE with a COFF symbol table: `_other`, `_firmware`
    /// (section 2), and a symbol after it bounding its size.
    fn pe_with(data: &[u8]) -> Vec<u8> {
        let mut pe = vec![0u8; 0x200];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        let data_at = 0x100usize;
        pe[data_at..data_at + data.len()].copy_from_slice(data);
        let symtab = 0x180usize;
        pe[0x80 + 12..0x80 + 16].copy_from_slice(&(symtab as u32).to_le_bytes());
        pe[0x80 + 16..0x80 + 20].copy_from_slice(&3u32.to_le_bytes());
        let mut sym = |i: usize, name: &[u8], value: usize, section: u8| {
            let at = symtab + i * 18;
            pe.resize(pe.len().max(at + 18), 0);
            pe[at..at + name.len()].copy_from_slice(name);
            pe[at + 8..at + 12].copy_from_slice(&(value as u32).to_le_bytes());
            pe[at + 12] = section;
        };
        sym(0, b"_other", 0x10, 1);
        sym(1, b"_firmwar", data_at, 2); // 8 chars: inline name
        sym(2, b"_end", data_at + data.len(), 2);
        pe
    }

    #[test]
    fn finds_a_coff_symbol_and_its_size() {
        let pe = pe_with(b"records!");
        assert_eq!(symbol(&pe, "_firmwar").unwrap(), Some(&b"records!"[..]));
        assert_eq!(symbol(&pe, "_missing").unwrap(), None);
        assert!(symbol(&pe, "_other").is_err(), "a symbol of another section has no size");
    }
}
