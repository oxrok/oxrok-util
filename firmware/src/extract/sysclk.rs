// Port of sigrok-util/firmware/sysclk-lwla/sigrok-fwextract-sysclk-lwla{1016,1034},
// GPL-3.0-or-later like them.

//! Sysclk LWLA1016, LWLA1034 and SLA5032.
//!
//! The LWLA bitstreams sit at fixed offsets in known vendor binaries,
//! so those binaries are checked by hash first. The SLA5032's is a
//! plain file of the installed software, `top.bit`.

use super::{Extracted, slice};
use crate::error::{Error, Result};
use crate::input::Input;
use crate::registry::{Package, sha256_hex};

/// `(output, offset, length)` in a vendor binary.
type Cut = (&'static str, usize, usize);

const LWLA1016_DLL: &str = "lwla1016.dll";
const LWLA1016_DLL_SHA256: &str =
    "cb9db3a81606865db2fd3a5075e3c66e071c4b0b6150cc1a22ee03889b236d7f";
const LWLA1016_CUTS: &[Cut] =
    &[("sysclk-lwla1016-100.rbf", 112_300, 69_334), ("sysclk-lwla1016-100-ts.rbf", 41_708, 70_588)];

const LWLA1034_SETUP: &str = "lwla1034_en_setup.exe";
const LWLA1034_SETUP_SHA256: &str =
    "f2a9333329200ad1d939d051257f914200cf0c765ff4962b2907dcf30716f455";
const LWLA1034_CUTS: &[Cut] = &[
    ("sysclk-lwla1034-int.rbf", 34_110_342, 78_394),
    ("sysclk-lwla1034-extpos.rbf", 34_266_241, 78_243),
    ("sysclk-lwla1034-extneg.rbf", 34_344_488, 79_141),
    ("sysclk-lwla1034-off.rbf", 34_578_635, 48_521),
];

/// LWLA1016: the 100 MHz bitstreams libsigrok loads, from the installed
/// `bin/lwla1016.dll`. (The 200 and 250 MHz ones, in the other two
/// DLLs, are never loaded.)
pub(crate) fn lwla1016(_pkg: &Package, input: &mut Input, out: &mut Extracted) -> Result<()> {
    let dll = input.read_named_or_given(LWLA1016_DLL)?;
    cut(&dll, LWLA1016_DLL, LWLA1016_DLL_SHA256, LWLA1016_CUTS, out)
}

/// LWLA1034: the bitstreams in the CD's `lwla1034_EN_setup.exe`.
pub(crate) fn lwla1034(_pkg: &Package, input: &mut Input, out: &mut Extracted) -> Result<()> {
    let exe = input.read_named_or_given(LWLA1034_SETUP)?;
    cut(&exe, "lwla1034_EN_setup.exe", LWLA1034_SETUP_SHA256, LWLA1034_CUTS, out)
}

/// SLA5032: the installed `top.bit`, under the name the driver loads.
pub(crate) fn sla5032(pkg: &Package, input: &mut Input, out: &mut Extracted) -> Result<()> {
    let bit = input.read_named_or_given("top.bit")?;
    // A Xilinx .bit starts with a 9 byte field of length 9.
    if !bit.starts_with(&[0x00, 0x09, 0x0f, 0xf0]) {
        return Err(Error::format("top.bit", "not a Xilinx bitstream"));
    }
    out.add(pkg.files[0], bit);
    Ok(())
}

fn cut(data: &[u8], what: &str, sha256: &str, cuts: &[Cut], out: &mut Extracted) -> Result<()> {
    let got = sha256_hex(data);
    if got != sha256 {
        return Err(Error::Checksum {
            what: format!("{what} (only the known release has the bitstreams where oxrok looks)"),
            got,
            want: sha256.to_owned(),
        });
    }
    for (name, offset, len) in cuts {
        out.add(*name, slice(data, *offset, *len, what)?.to_vec());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_an_unknown_release() {
        let mut out = Extracted::default();
        let e = cut(b"not it", "x.dll", LWLA1016_DLL_SHA256, LWLA1016_CUTS, &mut out).unwrap_err();
        assert!(matches!(e, Error::Checksum { .. }), "{e}");
        assert!(out.files.is_empty());
    }

    #[test]
    fn cuts_at_the_offsets() {
        let data: Vec<u8> = (0..=255).collect();
        let sha = sha256_hex(&data);
        let mut out = Extracted::default();
        cut(&data, "x", &sha, &[("a", 1, 2), ("b", 254, 2)], &mut out).unwrap();
        assert_eq!(out.files["a"], vec![1, 2]);
        assert_eq!(out.files["b"], vec![254, 255]);
    }
}
