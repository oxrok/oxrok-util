// Port of sigrok-util/firmware/saleae-logic16/sigrok-fwextract-saleae-logic16,
// GPL-3.0-or-later like it.

//! Saleae Logic16 and Logic Pro: firmware and bitstreams exported as
//! dynamic symbols of the Linux `Logic` program (1.2.x).
//!
//! The script's other path, rebuilding the FX2 firmware from the x86
//! code that fills a string table in Logic 1.1.x, is not ported: the
//! pinned 1.2.10 exports the firmware as one string.

use super::{Extracted, ihex_record, unhex};
use crate::error::{Error, Result};
use crate::input::Input;
use crate::registry::Package;
use object::{Architecture, Object, ObjectSection, ObjectSymbol};
use std::collections::{BTreeMap, HashMap};

pub(crate) fn extract(_pkg: &Package, input: &mut Input, out: &mut Extracted) -> Result<()> {
    let path = input.find_one_or_given("the Logic program", |n| n == "logic")?;
    let data = std::fs::read(&path)?;
    let elf = object::File::parse(&*data)
        .map_err(|e| Error::format("Logic", format!("not an ELF program: {e}")))?;
    if !matches!(elf.architecture(), Architecture::I386 | Architecture::X86_64) {
        return Err(Error::format("Logic", "unsupported architecture"));
    }
    let syms = Symbols::new(&elf);

    let fx2 = syms.get("Logic16FirmwareStrings").ok_or_else(|| {
        Error::format(
            "Logic",
            "no Logic16FirmwareStrings: Logic 1.1.x and 1.2.18 or later are not supported, use 1.2.10",
        )
    })??;
    out.add("saleae-logic16-fx2.fw", ihex_to_binary(&text(fx2)?.split(';').collect::<Vec<_>>())?);
    for lv in ["18", "33"] {
        let sym = format!("gLogic16Lv{lv}CompressedBitstream");
        let bits = syms.get(&sym).ok_or_else(|| Error::format("Logic", format!("no {sym}")))??;
        out.add(format!("saleae-logic16-fpga-{lv}.bitstream"), bits.to_vec());
    }
    for (sym, file) in [
        ("LogicPro16FirmwareStrings", "saleae-logicpro16-fx3.fw"),
        ("LogicPro8FirmwareStrings", "saleae-logicpro8-fx3.fw"),
    ] {
        if let Some(fw) = fx3_firmware(&syms, sym)? {
            out.add(file, fw);
        }
    }
    for (sym, file) in [
        ("gLogicPro16CompressedBitstream", "saleae-logicpro16-fpga.bitstream"),
        ("gLogicProCompressedBitstream", "saleae-logicpro8-fpga.bitstream"),
    ] {
        if let Some(bits) = syms.get(sym) {
            out.add(file, bits?.to_vec());
        }
    }
    Ok(())
}

/// Dynamic symbols by name, with the bytes they point at.
struct Symbols<'a> {
    by_name: HashMap<String, (u64, u64)>,
    /// (address, size, data) of every section with file data.
    sections: Vec<(u64, u64, &'a [u8])>,
}

impl<'a> Symbols<'a> {
    fn new(elf: &object::File<'a>) -> Self {
        let by_name = elf
            .dynamic_symbols()
            .filter_map(|s| Some((s.name().ok()?.to_owned(), (s.address(), s.size()))))
            .collect();
        let sections =
            elf.sections().filter_map(|s| Some((s.address(), s.size(), s.data().ok()?))).collect();
        Symbols { by_name, sections }
    }

    /// The bytes of symbol `name`; `None` if there is no such symbol.
    fn get(&self, name: &str) -> Option<Result<&'a [u8]>> {
        let &(address, size) = self.by_name.get(name)?;
        Some(self.load(address, size).ok_or_else(|| {
            Error::format("Logic", format!("symbol {name} is outside the file's sections"))
        }))
    }

    fn load(&self, address: u64, size: u64) -> Option<&'a [u8]> {
        let (base, _, data) =
            self.sections.iter().find(|(a, s, _)| *a <= address && address < a + s)?;
        let start = usize::try_from(address - base).ok()?;
        data.get(start..start + usize::try_from(size).ok()?)
    }
}

/// A C string's text, without its NUL.
fn text(bytes: &[u8]) -> Result<&str> {
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    std::str::from_utf8(bytes).map_err(|_| Error::format("Logic", "firmware string is not text"))
}

/// Intel HEX lines to a binary image from address 0: one data record
/// per address, no overlaps, gaps filled with zeros.
fn ihex_to_binary(lines: &[&str]) -> Result<Vec<u8>> {
    let mut chunks: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
    for line in lines.iter().filter(|l| !l.trim().is_empty()) {
        let hex = line
            .trim()
            .strip_prefix(':')
            .ok_or_else(|| Error::format("Intel HEX", "line without ':'"))?;
        let bytes = unhex(hex)?;
        let r = ihex_record(&bytes)?;
        match (r.kind, r.data.len()) {
            (1, 0) => {}
            (0, n) if n > 0 => {
                if chunks.insert(usize::from(r.address), r.data.to_vec()).is_some() {
                    return Err(Error::format(
                        "Intel HEX",
                        format!("two lines at 0x{:x}", r.address),
                    ));
                }
            }
            (kind, n) => {
                return Err(Error::format(
                    "Intel HEX",
                    format!("record type {kind} with {n} bytes"),
                ));
            }
        }
    }
    let mut blob = Vec::new();
    for (address, data) in chunks {
        if address < blob.len() {
            return Err(Error::format("Intel HEX", "overlapping lines"));
        }
        blob.resize(address, 0);
        blob.extend_from_slice(&data);
    }
    Ok(blob)
}

/// The FX3 firmware: the symbols `NAME_0`, `NAME_1`, … each hold HEX
/// lines, and the image is the lines' bytes (whole records) in order.
fn fx3_firmware(syms: &Symbols<'_>, name: &str) -> Result<Option<Vec<u8>>> {
    let mut image = Vec::new();
    for i in 0.. {
        let Some(sym) = syms.get(&format!("{name}_{i}")) else { break };
        for part in text(sym?)?.split(';').filter(|p| !p.is_empty()) {
            let hex = part
                .strip_prefix(':')
                .ok_or_else(|| Error::format("Intel HEX", "line without ':'"))?;
            image.extend(unhex(hex)?);
        }
    }
    Ok((!image.is_empty()).then_some(image))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ihex_lines_make_an_image_with_gaps_zeroed() {
        let blob = ihex_to_binary(&[":0300000002000AF1", ":01000500AA50", ":00000001FF"]).unwrap();
        assert_eq!(blob, vec![0x02, 0x00, 0x0a, 0, 0, 0xaa]);
    }

    #[test]
    fn ihex_refuses_duplicates_and_overlaps() {
        assert!(ihex_to_binary(&[":01000000AA55", ":01000000AA55"]).is_err());
        assert!(ihex_to_binary(&[":020000000102FB", ":01000100AA54"]).is_err());
    }
}
