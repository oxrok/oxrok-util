//! A small front end, for trying the crate by hand:
//!
//! ```text
//! cargo run -p oxrok-firmware-fetch --example fwfetch -- list
//! cargo run -p oxrok-firmware-fetch --example fwfetch -- fetch ID|FILE DEST
//! cargo run -p oxrok-firmware-fetch --example fwfetch -- import ID|FILE DEST PATH...
//! ```

use oxrok_firmware_fetch::{
    Options, Package, Progress, fetch, import, package, package_for, packages,
};
use std::path::PathBuf;
use std::process::ExitCode;

struct Log;

impl Progress for Log {
    fn message(&self, msg: &str) {
        eprintln!("{msg}");
    }
}

fn lookup(what: &str) -> Option<&'static Package> {
    package(what).or_else(|| package_for(what))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["list"] => {
            for p in packages() {
                let how = if p.downloadable() { "download" } else { "manual" };
                println!("{:22} {how:8} {}", p.id, p.title);
            }
            Ok(())
        }
        ["fetch", what, dest] => match lookup(what) {
            Some(p) => {
                fetch(p, &PathBuf::from(dest), &Options { progress: &Log, ..Options::default() })
                    .map(report)
            }
            None => Err(oxrok_firmware_fetch::Error::UnknownFile((*what).to_owned())),
        },
        ["import", what, dest, paths @ ..] if !paths.is_empty() => match lookup(what) {
            Some(p) => {
                let paths: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
                import(p, &paths, &PathBuf::from(dest), &Log).map(report)
            }
            None => Err(oxrok_firmware_fetch::Error::UnknownFile((*what).to_owned())),
        },
        _ => {
            eprintln!("usage: fwfetch list | fetch ID|FILE DEST | import ID|FILE DEST PATH...");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::needless_pass_by_value)] // used as a `map` callback
fn report(installed: oxrok_firmware_fetch::Installed) {
    for w in &installed.warnings {
        eprintln!("warning: {w}");
    }
    println!("{} files installed", installed.files.len());
}
