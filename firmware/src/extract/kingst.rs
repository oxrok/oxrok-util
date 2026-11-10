// Port of sigrok-util/firmware/kingst-la/sigrok-fwextract-kingst-la2016,
// GPL-3.0-or-later like it.

//! Kingst LA series: firmware and bitstreams in `KingstVIS`'s Qt resources.
//!
//! rcc compiles resources into three static arrays: names, a tree of
//! entries, and the (often zlib compressed) data. An unstripped Linux
//! build names them in its symbol table. Stripped, macOS and Windows
//! builds do not, so each table is found by its structure instead:
//!
//! - **names**: every entry carries a hash of its name, so a long run of
//!   entries whose hashes check out is the table;
//! - **tree**: 14 byte entries starting with a name offset, the root
//!   (a directory with name offset 0) first;
//! - **data**: length prefixed blobs; the base is the one at which every
//!   file entry describes a well formed blob, every compressed one
//!   inflating to its stated size.

use super::{Extracted, u16_be, u32_be};
use crate::error::{Error, Result};
use crate::input::Input;
use crate::registry::Package;
use object::{Object, ObjectSection, ObjectSymbol};
use std::collections::{BTreeMap, HashSet};
use std::io::Read;

const COMPRESSED: u16 = 0x01;
const DIRECTORY: u16 = 0x02;
const ENTRY: usize = 14;
/// Runs shorter than these are not taken for tables: far above what
/// random bytes give, far below what `KingstVIS` ships.
const MIN_NAME_ENTRIES: usize = 8;
const MIN_STRUCT_ENTRIES: usize = 4;

pub(crate) fn extract(_pkg: &Package, input: &mut Input, out: &mut Extracted) -> Result<()> {
    let path = input
        .find_one_or_given("the KingstVIS program", |n| n == "kingstvis" || n == "kingstvis.exe")?;
    let image = std::fs::read(&path)?;
    let res = Resources::from_symbols(&image).map_or_else(|| Resources::locate(&image), Ok)?;
    let files = res.files()?;
    for (name, (flags, offset)) in &files {
        let (out_name, hex) = if let Some(rest) = name.strip_prefix("fwusb/fw") {
            (format!("kingst-la-{rest}.fw"), true)
        } else if let Some(rest) = name.strip_prefix("fwfpga/") {
            (format!("kingst-{rest}-fpga.bitstream"), false)
        } else {
            continue;
        };
        let mut data = res.data(*flags, *offset)?;
        if hex && data.first() == Some(&b':') && data.iter().all(|b| *b < 127) {
            data = intel_hex_blob(&data)?;
        }
        out.add(out_name.to_lowercase(), data);
    }
    Ok(())
}

/// Qt's `qt_hash()`, from qresource.cpp.
fn qt_hash(name: &str) -> u32 {
    let mut h: u64 = 0;
    for c in name.chars() {
        h = (h << 4) + u64::from(u32::from(c));
        h ^= (h & 0xf000_0000) >> 23;
        h &= 0x0fff_ffff;
    }
    h as u32
}

/// The three tables, each a slice starting at its base.
struct Resources<'a> {
    names: &'a [u8],
    tree: &'a [u8],
    data: &'a [u8],
}

impl<'a> Resources<'a> {
    /// The tables of an unstripped ELF build, by their symbols.
    fn from_symbols(image: &'a [u8]) -> Option<Self> {
        let elf = object::File::parse(image).ok()?;
        let sym = |name: &str| -> Option<&'a [u8]> {
            let s = elf.symbols().find(|s| s.name() == Ok(name))?;
            let section = elf.section_by_index(s.section_index()?).ok()?;
            let start = usize::try_from(s.address().checked_sub(section.address())?).ok()?;
            section.data().ok()?.get(start..start + usize::try_from(s.size()).ok()?)
        };
        Some(Resources {
            data: sym("_ZL16qt_resource_data")?,
            names: sym("_ZL16qt_resource_name")?,
            tree: sym("_ZL18qt_resource_struct")?,
        })
    }

    /// The tables of any build, by their structure.
    fn locate(image: &'a [u8]) -> Result<Self> {
        let names = find_name_table(image)?;
        let (tree, tree_len) = find_tree(image, names)?;
        let data = find_data_table(image, &image[tree..tree + tree_len])?;
        Ok(Resources {
            names: &image[names..],
            tree: &image[tree..tree + tree_len],
            data: &image[data..],
        })
    }

    fn name(&self, offset: usize) -> Result<String> {
        name_entry(self.names, offset)
            .map(|(n, _)| n)
            .ok_or_else(|| Error::format("KingstVIS", "bad resource name"))
    }

    /// Every file's full name, flags and data offset.
    fn files(&self) -> Result<BTreeMap<String, (u16, usize)>> {
        let bad = || Error::format("KingstVIS", "bad resource tree");
        let entry = |i: usize| -> Result<(usize, u16, u32, u32)> {
            let at = i * ENTRY;
            let n = u32_be(self.tree, at).ok_or_else(bad)? as usize;
            let flags = u16_be(self.tree, at + 4).ok_or_else(bad)?;
            Ok((
                n,
                flags,
                u32_be(self.tree, at + 6).ok_or_else(bad)?,
                u32_be(self.tree, at + 10).ok_or_else(bad)?,
            ))
        };
        let mut files = BTreeMap::new();
        // (entry index, path); depth bounded by the entry count.
        let mut stack = vec![(0usize, String::new())];
        let mut seen = HashSet::new();
        while let Some((i, prefix)) = stack.pop() {
            if !seen.insert(i) {
                return Err(bad());
            }
            let (_, flags, count, first) = entry(i)?;
            if flags & DIRECTORY == 0 {
                return Err(bad());
            }
            for child in first as usize..first as usize + count as usize {
                let (name_off, cflags, _, data_off) = entry(child)?;
                let path = if prefix.is_empty() {
                    self.name(name_off)?
                } else {
                    format!("{prefix}/{}", self.name(name_off)?)
                };
                if cflags & DIRECTORY != 0 {
                    stack.push((child, path));
                } else {
                    files.insert(path, (cflags, data_off as usize));
                }
            }
        }
        Ok(files)
    }

    fn data(&self, flags: u16, offset: usize) -> Result<Vec<u8>> {
        let bad = || Error::format("KingstVIS", "bad resource data");
        let len = u32_be(self.data, offset).ok_or_else(bad)? as usize;
        let blob = self.data.get(offset + 4..offset + 4 + len).ok_or_else(bad)?;
        if flags & COMPRESSED == 0 {
            return Ok(blob.to_vec());
        }
        let mut out = Vec::new();
        flate2::read::ZlibDecoder::new(blob.get(4..).ok_or_else(bad)?)
            .read_to_end(&mut out)
            .map_err(|_| bad())?;
        Ok(out)
    }
}

/// A name entry at `pos`: its name and length, if it is one.
fn name_entry(buf: &[u8], pos: usize) -> Option<(String, usize)> {
    let len = usize::from(u16_be(buf, pos)?);
    let hash = u32_be(buf, pos + 2)?;
    if len == 0 || len > 256 {
        return None;
    }
    let raw = buf.get(pos + 6..pos + 6 + 2 * len)?;
    let units: Vec<u16> =
        raw.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
    let name = String::from_utf16(&units).ok()?;
    (qt_hash(&name) == hash).then_some((name, 6 + 2 * len))
}

/// The base of the longest run of name entries.
fn find_name_table(buf: &[u8]) -> Result<usize> {
    let (mut best, mut best_count) = (0, 0);
    let mut pos = 0;
    while pos < buf.len() {
        // A length of at most 256 has a high byte of 0 or 1.
        if buf[pos] > 1 {
            pos += 1;
            continue;
        }
        let Some(mut entry) = name_entry(buf, pos) else {
            pos += 1;
            continue;
        };
        let (start, mut count) = (pos, 0);
        loop {
            pos += entry.1;
            count += 1;
            match name_entry(buf, pos) {
                Some(e) => entry = e,
                None => break,
            }
        }
        if count > best_count {
            (best, best_count) = (start, count);
        }
    }
    if best_count < MIN_NAME_ENTRIES {
        return Err(Error::format("KingstVIS", "could not locate qt_resource_name"));
    }
    Ok(best)
}

/// The base and length of the tree: the longest run of entries whose
/// name offsets point at names, starting at a root.
fn find_tree(buf: &[u8], names: usize) -> Result<(usize, usize)> {
    let root = [0, 0, 0, 0, 0, DIRECTORY as u8];
    let (mut best, mut best_count) = (0, 0);
    let mut from = 0;
    while let Some(found) = find(&buf[from..], &root) {
        let pos = from + found;
        let mut count = 0;
        while let Some(off) =
            u32_be(buf, pos + count * ENTRY).filter(|_| pos + (count + 1) * ENTRY <= buf.len())
        {
            if name_entry(buf, names + off as usize).is_none() {
                break;
            }
            count += 1;
        }
        if count > best_count {
            (best, best_count) = (pos, count);
        }
        from = pos + 1;
    }
    if best_count < MIN_STRUCT_ENTRIES {
        return Err(Error::format("KingstVIS", "could not locate qt_resource_struct"));
    }
    Ok((best, best_count * ENTRY))
}

/// The base of the data table: every zlib header proposes one, through
/// the first compressed file, and the right one fits every file.
fn find_data_table(buf: &[u8], tree: &[u8]) -> Result<usize> {
    let files: Vec<(u16, usize)> = tree
        .as_chunks::<ENTRY>()
        .0
        .iter()
        .filter_map(|e| {
            let flags = u16_be(e, 4)?;
            (flags & DIRECTORY == 0).then(|| Some((flags, u32_be(e, 10)? as usize)))?
        })
        .collect();
    let probe = files.iter().find(|f| f.0 & COMPRESSED != 0).ok_or_else(|| {
        Error::format("KingstVIS", "no compressed resource to anchor qt_resource_data")
    })?;
    let mut seen = HashSet::new();
    for magic in [[0x78, 0x01], [0x78, 0x5e], [0x78, 0x9c], [0x78, 0xda]] {
        let mut from = 0;
        while let Some(found) = find(&buf[from..], &magic) {
            let pos = from + found;
            from = pos + 1;
            let Some(base) = pos.checked_sub(8 + probe.1) else { continue };
            if seen.insert(base) && data_table_fits(buf, base, &files) {
                return Ok(base);
            }
        }
    }
    Err(Error::format("KingstVIS", "could not locate qt_resource_data"))
}

fn data_table_fits(buf: &[u8], base: usize, files: &[(u16, usize)]) -> bool {
    let blob = |offset: usize| -> Option<&[u8]> {
        let pos = base + offset;
        let len = u32_be(buf, pos)? as usize;
        if len < 4 {
            return None;
        }
        buf.get(pos + 4..pos + 4 + len)
    };
    // The cheap pass first: a wrong base fails without inflating.
    if files.iter().any(|f| blob(f.1).is_none()) {
        return false;
    }
    files.iter().filter(|f| f.0 & COMPRESSED != 0).all(|f| {
        let b = blob(f.1).expect("checked");
        let expected = u32_be(b, 0).expect("len >= 4") as usize;
        let mut out = Vec::with_capacity(expected.min(1 << 24));
        flate2::read::ZlibDecoder::new(&b[4..]).read_to_end(&mut out).is_ok()
            && out.len() == expected
    })
}

/// Intel HEX text (LF or CR LF lines) to an image from address 0.
fn intel_hex_blob(text: &[u8]) -> Result<Vec<u8>> {
    let mut records = Vec::new();
    for line in text.split(|b| *b == b'\n') {
        let line =
            std::str::from_utf8(line).map_err(|_| Error::format("Intel HEX", "not text"))?.trim();
        if line.is_empty() {
            continue;
        }
        let hex =
            line.strip_prefix(':').ok_or_else(|| Error::format("Intel HEX", "line without ':'"))?;
        let bytes = super::unhex(hex)?;
        let r = super::ihex_record(&bytes)?;
        match r.kind {
            0 => records.push((usize::from(r.address), r.data.to_vec())),
            1 => break,
            _ => {}
        }
    }
    records.sort();
    let Some((last_addr, last)) = records.last() else { return Ok(Vec::new()) };
    let mut img = vec![0u8; last_addr + last.len()];
    for (addr, data) in &records {
        let end = (addr + data.len()).min(img.len());
        img[*addr..end].copy_from_slice(&data[..end - addr]);
    }
    Ok(img)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn qt_hash_matches_qt() {
        assert_eq!(qt_hash(""), 0);
        assert_eq!(qt_hash("a"), 0x61);
        assert_eq!(qt_hash("ab"), 0x61 * 16 + 0x62);
    }

    fn name(n: &str) -> Vec<u8> {
        let mut e = (n.encode_utf16().count() as u16).to_be_bytes().to_vec();
        e.extend(qt_hash(n).to_be_bytes());
        e.extend(n.encode_utf16().flat_map(u16::to_be_bytes));
        e
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(data).unwrap();
        let mut blob = (data.len() as u32).to_be_bytes().to_vec();
        blob.extend(z.finish().unwrap());
        blob
    }

    /// An "executable" holding rcc's three tables, unnamed, among junk:
    /// root/{fwusb/fw01A2, fwfpga/LA2016, …padding dirs}.
    fn image() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let hexfw = b":0300000002000AF1\n:00000001FF\n".to_vec();
        let bitstream = vec![0x5a; 300];
        let names_list = ["fwusb", "fwfpga", "fw01A2", "LA2016", "d1", "d2", "d3", "d4", "d5"];
        let mut names = Vec::new();
        let mut name_off = Vec::new();
        for n in names_list {
            name_off.push(names.len() as u32);
            names.extend(name(n));
        }
        let mut data = Vec::new();
        let fw_off = data.len() as u32;
        data.extend((hexfw.len() as u32).to_be_bytes());
        data.extend(&hexfw);
        let bit_off = data.len() as u32;
        let z = zlib(&bitstream);
        data.extend((z.len() as u32).to_be_bytes());
        data.extend(z);
        let dir = |name: u32, count: u32, first: u32| {
            let mut e = name.to_be_bytes().to_vec();
            e.extend(DIRECTORY.to_be_bytes());
            e.extend(count.to_be_bytes());
            e.extend(first.to_be_bytes());
            e
        };
        let file = |name: u32, flags: u16, off: u32| {
            let mut e = name.to_be_bytes().to_vec();
            e.extend(flags.to_be_bytes());
            e.extend([0, 0, 0, 0]);
            e.extend(off.to_be_bytes());
            e
        };
        // 0 root -> 1 fwusb, 2 fwfpga, 3..7 d1..d5 (empty dirs)
        let mut tree = dir(0, 7, 1);
        tree.extend(dir(name_off[0], 1, 8));
        tree.extend(dir(name_off[1], 1, 9));
        for off in &name_off[4..9] {
            tree.extend(dir(*off, 0, 0));
        }
        tree.extend(file(name_off[2], 0, fw_off));
        tree.extend(file(name_off[3], COMPRESSED, bit_off));
        let mut img = b"\x7fNOT-ELF junk junk".to_vec();
        img.extend(&data);
        img.extend(b"more junk");
        img.extend(&tree);
        img.extend([0x11; 7]);
        img.extend(&names);
        img.extend(b"tail");
        (img, hexfw, bitstream)
    }

    #[test]
    fn locates_unnamed_tables_and_reads_the_files() {
        let (img, _, bitstream) = image();
        let res = Resources::locate(&img).unwrap();
        let files = res.files().unwrap();
        assert_eq!(files.keys().collect::<Vec<_>>(), vec!["fwfpga/LA2016", "fwusb/fw01A2"]);
        let (f, o) = files["fwfpga/LA2016"];
        assert_eq!(res.data(f, o).unwrap(), bitstream);
        let (f, o) = files["fwusb/fw01A2"];
        assert_eq!(intel_hex_blob(&res.data(f, o).unwrap()).unwrap(), vec![0x02, 0x00, 0x0a]);
    }
}
