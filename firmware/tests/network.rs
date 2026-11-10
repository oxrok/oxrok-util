//! Fetches every downloadable package from the network and extracts it.
//!
//! Ignored by default: it downloads about 100 MB from vendor sites.
//! Run it with `cargo test -p oxrok-firmware-fetch --test network --
//! --ignored`; `OXROK_FIRMWARE_FETCH_CACHE` keeps the downloads between
//! runs. Every download's hash is pinned and every extracted file with a
//! known hash is checked against it, so a pass means the extractors give
//! the same bytes as sigrok-util's scripts did on the same inputs.

use oxrok_firmware_fetch::{Options, Progress, fetch, packages};
use std::path::PathBuf;

struct Log;

impl Progress for Log {
    fn message(&self, msg: &str) {
        eprintln!("{msg}");
    }
}

#[test]
#[ignore = "downloads about 100 MB from vendor sites"]
fn every_downloadable_package_fetches_and_extracts() {
    let cache = std::env::var_os("OXROK_FIRMWARE_FETCH_CACHE")
        .map_or_else(|| std::env::temp_dir().join("oxrok-firmware-fetch-test"), PathBuf::from);
    let opts = Options { cache_dir: cache, progress: &Log };
    let mut failures = Vec::new();
    for pkg in packages().iter().filter(|p| p.downloadable()) {
        let dest = tempfile::tempdir().unwrap();
        match fetch(pkg, dest.path(), &opts) {
            Ok(installed) => {
                let mut names: Vec<String> = installed
                    .files
                    .iter()
                    .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                    .collect();
                names.sort_unstable();
                let mut want: Vec<String> = pkg.files.iter().map(|f| (*f).to_owned()).collect();
                want.sort_unstable();
                if names != want {
                    failures.push(format!("{}: installed {names:?}, expected {want:?}", pkg.id));
                }
                for w in installed.warnings {
                    eprintln!("{}: warning: {w}", pkg.id);
                }
            }
            Err(oxrok_firmware_fetch::Error::NeedTool(a)) => {
                eprintln!("{}: skipped, {a} needs a tool", pkg.id);
            }
            Err(e) => failures.push(format!("{}: {e}", pkg.id)),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
