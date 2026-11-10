// Port of sigrok-util/firmware/lecroy-logicstudio/sigrok-fwextract-lecroy-logicstudio
// and of the stage extraction of fritzw/cyusb-fw-extract, both GPL-3.0-or-later.

//! `LeCroy` `LogicStudio` 16: two FPGA bitstreams in `LS16Lib.dll`, and the
//! FX2LP firmware in the Cypress loader script `LogicStudio16Load.spt`.

use super::{Extracted, reverse_bits, slice, u16_le, u32_le};
use crate::error::{Error, Result};
use crate::input::Input;
use crate::registry::Package;

const BITSTREAM_SIZE: usize = 464_196;
const FX2: &str = "lecroy-logicstudio16-fx2lp.fw";

pub(crate) fn extract(_pkg: &Package, input: &mut Input, out: &mut Extracted) -> Result<()> {
    // Either file alone is still worth installing.
    let dll = input.find("LS16Lib.dll", |n| n == "ls16lib.dll");
    let spt = input.find("LogicStudio16Load.spt", |n| n == "logicstudio16load.spt");
    if let (Err(e), Err(_)) = (&dll, &spt) {
        return Err(match e {
            Error::NeedTool(a) => Error::NeedTool(a.clone()),
            _ => Error::NotFound("LS16Lib.dll or LogicStudio16Load.spt".into()),
        });
    }
    if let Ok(paths) = dll {
        let [first, second] = bitstreams(&std::fs::read(&paths[0])?)?;
        out.add("lecroy-logicstudio16-16.bitstream", first);
        out.add("lecroy-logicstudio16-8.bitstream", second);
    }
    if let Ok(paths) = spt {
        out.add(FX2, fx2_from_spt(&std::fs::read(&paths[0])?)?);
    }
    Ok(())
}

/// The two bitstreams after the UTF-16 marker `FPGA_BINS`, each with
/// its bits reversed.
fn bitstreams(dll: &[u8]) -> Result<[Vec<u8>; 2]> {
    let marker: Vec<u8> = "FPGA_BINS".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let at = dll
        .windows(marker.len())
        .position(|w| w == marker)
        .ok_or_else(|| Error::format("LS16Lib.dll", "no FPGA_BINS marker"))?
        + marker.len();
    Ok([
        reverse_bits(slice(dll, at, BITSTREAM_SIZE, "LS16Lib.dll")?),
        reverse_bits(slice(dll, at + BITSTREAM_SIZE, BITSTREAM_SIZE, "LS16Lib.dll")?),
    ])
}

/// The FX2 image of a Cypress `.spt` loader script.
///
/// The script is a list of `CSPT` chunks, each an 0xA0 (firmware load)
/// control write. Its first write sets CPUCS.0, holding the 8051 in
/// reset; each stretch of writes between setting and clearing it is a
/// stage. Stage 1 is a second-stage loader, stage 2 the firmware, laid
/// out here from its lowest to its highest address (gaps zero), as
/// `objcopy -O binary` of the extracted HEX does.
fn fx2_from_spt(spt: &[u8]) -> Result<Vec<u8>> {
    let bad = |m: &str| Error::format("LogicStudio16Load.spt", m.to_owned());
    let mut stages: Vec<Vec<(u16, &[u8])>> = Vec::new();
    let mut cpucs = None;
    let mut in_reset = false;
    let mut p = 0;
    while p < spt.len() {
        if spt.get(p..p + 4) != Some(b"CSPT") {
            return Err(bad("expected a CSPT chunk"));
        }
        let len = u32_le(spt, p + 4).ok_or_else(|| bad("truncated"))? as usize;
        let chunk = spt.get(p..p + len).filter(|_| len >= 32).ok_or_else(|| bad("truncated"))?;
        p += len;
        let request = chunk[16];
        let address = u16_le(chunk, 18).expect("in range");
        let data_len = u32_le(chunk, 28).expect("in range") as usize;
        let data = &chunk[32..];
        if data.len() != data_len {
            return Err(bad("chunk length mismatch"));
        }
        if request != 0xa0 {
            continue;
        }
        let cpucs_addr = *cpucs.get_or_insert(address);
        if address == cpucs_addr {
            let Some(&value) = data.first().filter(|_| data.len() == 1) else { continue };
            let reset = value & 1 == 1;
            if reset && !in_reset {
                stages.push(Vec::new());
            }
            in_reset = reset;
        } else if in_reset && let Some(stage) = stages.last_mut() {
            stage.push((address, data));
        }
    }
    let stage = stages.get(1).ok_or_else(|| bad("no second stage"))?;
    let lo = stage.iter().map(|(a, _)| usize::from(*a)).min().ok_or_else(|| bad("empty stage"))?;
    let hi = stage.iter().map(|(a, d)| usize::from(*a) + d.len()).max().expect("not empty");
    let mut image = vec![0u8; hi - lo];
    for (a, d) in stage {
        let at = usize::from(*a) - lo;
        image[at..at + d.len()].copy_from_slice(d);
    }
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(request: u8, address: u16, data: &[u8]) -> Vec<u8> {
        let mut c = vec![0u8; 32];
        c[..4].copy_from_slice(b"CSPT");
        c[4..8].copy_from_slice(&((32 + data.len()) as u32).to_le_bytes());
        c[16] = request;
        c[18..20].copy_from_slice(&address.to_le_bytes());
        c[28..32].copy_from_slice(&(data.len() as u32).to_le_bytes());
        c.extend_from_slice(data);
        c
    }

    #[test]
    fn takes_the_second_stage_of_an_spt() {
        const CPUCS: u16 = 0xe600;
        let spt: Vec<u8> = [
            chunk(0xa0, CPUCS, &[1]),
            chunk(0xa0, 0x0000, &[0xee]), // stage 1: a loader
            chunk(0xa0, CPUCS, &[0]),
            chunk(0xb0, 0x1234, &[9, 9]), // another request: skipped
            chunk(0xa0, CPUCS, &[1]),
            chunk(0xa0, 0x0000, &[0x02, 0x01]),
            chunk(0xa0, 0x0004, &[0xaa]),
            chunk(0xa0, CPUCS, &[0]),
        ]
        .concat();
        assert_eq!(fx2_from_spt(&spt).unwrap(), vec![0x02, 0x01, 0, 0, 0xaa]);
    }

    #[test]
    fn reverses_the_bitstreams_after_the_marker() {
        let mut dll = b"junk".to_vec();
        dll.extend("FPGA_BINS".encode_utf16().flat_map(u16::to_le_bytes));
        dll.extend(std::iter::repeat_n(0x01, BITSTREAM_SIZE));
        dll.extend(std::iter::repeat_n(0x80, BITSTREAM_SIZE));
        let [a, b] = bitstreams(&dll).unwrap();
        assert!(a.iter().all(|x| *x == 0x80) && b.iter().all(|x| *x == 0x01));
        assert!(bitstreams(&dll[..dll.len() - 1]).is_err());
    }
}
