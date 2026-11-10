//! Fetching the vendor firmware oxrok's drivers need.
//!
//! Many logic analysers and oscilloscopes run firmware (FX2 code, FPGA
//! bitstreams) that their vendors never released on its own. sigrok's
//! answer was a set of extractor scripts in sigrok-util; this crate is
//! their port, plus a registry saying, for every firmware file a driver
//! looks up, where it comes from:
//!
//! - a pinned download (URL, size and SHA-256), extracted on the
//!   user's machine, as the vendor's terms usually require; or
//! - a file only the user can get (behind a vendor login, on the CD
//!   that came with the device, an installed copy of the vendor
//!   software), with [`Manual`] instructions saying where to find it.
//!
//! Nothing here touches oxrok: a front end looks a missing file up with
//! [`package_for`], then calls [`fetch`] (download, verify, extract,
//! install) or [`import`] (the same from files the user picked: an
//! installer, an archive, a folder of the installed software, or the
//! firmware files themselves). Both install into a directory the caller
//! chooses, normally [`default_install_dir`], which oxrok searches.
//!
//! No vendor firmware is part of this crate: only names, hashes and the
//! code to extract it.

mod error;
mod extract;
mod input;
mod install;
mod registry;

#[cfg(feature = "download")]
mod download;

pub use error::{Error, Result};
pub use input::{Input, unpacker};
pub use install::{
    Installed, Options, Progress, default_cache_dir, default_install_dir, fetch, import,
};
pub use registry::{Download, Manual, Package, all_files, package, package_for, packages};
