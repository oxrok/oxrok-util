//! What an extractor reads: the downloads, or whatever the user gave.
//!
//! Users get vendor software in many shapes: the download itself, an
//! installer, a folder of the installed program copied from a Windows
//! machine, the CD's ISO, or the firmware files sigrok-util already
//! extracted. An [`Input`] takes any mix of these and finds files by
//! name in them, opening archives only when a plain search finds
//! nothing, and as deep as an archive in an archive in an archive.
//!
//! Zip (Deflate64 too) and tar.gz are read natively. RAR, 7z, ISO,
//! CAB, MSI and installer executables go through the first of `unar`,
//! 7-Zip or `bsdtar` that is installed; without one, a search that needs
//! them fails with [`Error::NeedTool`]. Nothing found in an input is
//! ever run.

use crate::error::{Error, Result};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// How deep archives inside archives are opened.
const MAX_DEPTH: usize = 3;

/// Files to search: downloads, or the user's files and folders.
#[derive(Debug)]
pub struct Input {
    /// Where searches start: the given paths, then each unpacked archive.
    roots: Vec<PathBuf>,
    /// Archives already unpacked (or that failed to).
    opened: HashSet<PathBuf>,
    /// Where archives are unpacked; removed with the input.
    scratch: Option<tempfile::TempDir>,
    /// The first archive that needed a missing tool, for the error.
    needs_tool: Option<String>,
    /// The first archive that failed to open, and why, for the error.
    failed: Option<(String, String)>,
}

impl Input {
    /// An input over `paths`, files or folders.
    pub fn new(paths: impl IntoIterator<Item = PathBuf>) -> Self {
        Input {
            roots: paths.into_iter().collect(),
            opened: HashSet::new(),
            scratch: None,
            needs_tool: None,
            failed: None,
        }
    }

    /// The paths given, before any archive is opened.
    pub fn given(&self) -> impl Iterator<Item = &Path> {
        self.roots.iter().map(PathBuf::as_path).filter(|p| !self.is_scratch(p))
    }

    /// Files whose lowercased base name satisfies `pred`, without
    /// opening any archive.
    pub fn find_plain(&self, pred: impl Fn(&str) -> bool) -> Vec<PathBuf> {
        let mut hits = Vec::new();
        for root in &self.roots {
            walk(root, &mut |p| {
                if base_lower(p).is_some_and(|n| pred(&n)) {
                    hits.push(p.to_owned());
                }
            });
        }
        hits
    }

    /// Files whose lowercased base name satisfies `pred`. Archives are
    /// opened a level at a time until something matches; `what` names
    /// the file in the error when nothing does.
    pub fn find(&mut self, what: &str, pred: impl Fn(&str) -> bool) -> Result<Vec<PathBuf>> {
        for _ in 0..=MAX_DEPTH {
            let hits = self.find_plain(&pred);
            if !hits.is_empty() {
                return Ok(hits);
            }
            if !self.open_next_level()? {
                break;
            }
        }
        // Why nothing was found, most likely first.
        if let Some(archive) = self.needs_tool.take() {
            return Err(Error::NeedTool(archive));
        }
        if let Some((archive, why)) = self.failed.take() {
            return Err(Error::format(
                archive,
                format!("could not open it ({why}), and {what} is not among the rest"),
            ));
        }
        Err(Error::NotFound(what.to_owned()))
    }

    /// The first file [`Input::find`] finds.
    pub fn find_one(&mut self, what: &str, pred: impl Fn(&str) -> bool) -> Result<PathBuf> {
        Ok(self.find(what, pred)?.remove(0))
    }

    /// Reads the first file named `name` (any case).
    pub fn read_named(&mut self, name: &str) -> Result<Vec<u8>> {
        let lower = name.to_lowercase();
        let path = self.find_one(name, |n| n == lower)?;
        Ok(std::fs::read(path)?)
    }

    /// As [`Input::find_one`], but when nothing has a matching name and
    /// the user gave exactly one file that is no archive, that file: a
    /// user pointing at a renamed program means it. The caller checks
    /// its contents.
    pub fn find_one_or_given(
        &mut self,
        what: &str,
        pred: impl Fn(&str) -> bool,
    ) -> Result<PathBuf> {
        match self.find_one(what, pred) {
            Err(Error::NotFound(w)) => {
                let files: Vec<&Path> = self.given().filter(|p| p.is_file()).collect();
                match files.as_slice() {
                    [one] if matches!(Kind::sniff(one), None | Some(Kind::Exe)) => {
                        Ok(one.to_path_buf())
                    }
                    _ => Err(Error::NotFound(w)),
                }
            }
            other => other,
        }
    }

    /// [`Input::find_one_or_given`]'s file, read.
    pub fn read_named_or_given(&mut self, name: &str) -> Result<Vec<u8>> {
        let lower = name.to_lowercase();
        let path = self.find_one_or_given(name, |n| n == lower)?;
        Ok(std::fs::read(path)?)
    }

    /// Unpacks every archive not opened yet; whether any was.
    fn open_next_level(&mut self) -> Result<bool> {
        let mut files = Vec::new();
        for root in &self.roots {
            walk(root, &mut |p| files.push(p.to_owned()));
        }
        let mut any = false;
        for file in files {
            if !self.opened.insert(file.clone()) {
                continue;
            }
            let Some(kind) = Kind::sniff(&file) else { continue };
            let n = self.opened.len();
            let dir = self.scratch_dir()?.join(n.to_string());
            std::fs::create_dir_all(&dir)?;
            match unpack(kind, &file, &dir) {
                Ok(()) => {
                    log::debug!("Unpacked {} ({kind:?}).", file.display());
                    self.roots.push(dir);
                    any = true;
                }
                Err(Error::NeedTool(name)) => {
                    // An executable that is no archive is common; only
                    // a real archive is worth the hint.
                    if kind != Kind::Exe && self.needs_tool.is_none() {
                        self.needs_tool = Some(name);
                    }
                }
                Err(e) => {
                    log::debug!("Not unpacking {}: {e}", file.display());
                    if kind != Kind::Exe && self.failed.is_none() {
                        self.failed = Some((file.display().to_string(), e.to_string()));
                    }
                }
            }
        }
        Ok(any)
    }

    fn scratch_dir(&mut self) -> Result<&Path> {
        if self.scratch.is_none() {
            self.scratch = Some(tempfile::Builder::new().prefix("oxrok-firmware-").tempdir()?);
        }
        Ok(self.scratch.as_ref().map(tempfile::TempDir::path).expect("just set"))
    }

    fn is_scratch(&self, p: &Path) -> bool {
        self.scratch.as_ref().is_some_and(|s| p.starts_with(s.path()))
    }
}

/// The lowercased base name.
fn base_lower(p: &Path) -> Option<String> {
    p.file_name().map(|n| n.to_string_lossy().to_lowercase())
}

/// Calls `f` on every regular file at or under `p`; symlinks are not
/// followed.
fn walk(p: &Path, f: &mut dyn FnMut(&Path)) {
    let Ok(meta) = std::fs::symlink_metadata(p) else { return };
    if meta.is_file() {
        f(p);
    } else if meta.is_dir() {
        let Ok(entries) = std::fs::read_dir(p) else { return };
        let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
        paths.sort();
        for p in paths {
            walk(&p, f);
        }
    }
}

/// Archive formats, told apart by their first bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Zip,
    Gzip,
    Rar,
    SevenZip,
    Cab,
    /// OLE compound files: MSI installers.
    Ole,
    Iso,
    /// A Windows executable, possibly a self-extracting installer.
    Exe,
}

impl Kind {
    fn sniff(path: &Path) -> Option<Kind> {
        let mut f = File::open(path).ok()?;
        let mut head = [0u8; 8];
        let n = f.read(&mut head).ok()?;
        let head = &head[..n];
        let kind = if head.starts_with(b"PK\x03\x04") {
            Kind::Zip
        } else if head.starts_with(b"\x1f\x8b") {
            Kind::Gzip
        } else if head.starts_with(b"Rar!\x1a\x07") {
            Kind::Rar
        } else if head.starts_with(b"7z\xbc\xaf\x27\x1c") {
            Kind::SevenZip
        } else if head.starts_with(b"MSCF") {
            Kind::Cab
        } else if head.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
            Kind::Ole
        } else if head.starts_with(b"MZ") {
            Kind::Exe
        } else {
            let mut cd = [0u8; 5];
            f.seek(SeekFrom::Start(0x8001)).ok()?;
            f.read_exact(&mut cd).ok()?;
            if &cd == b"CD001" {
                Kind::Iso
            } else {
                return None;
            }
        };
        Some(kind)
    }
}

fn unpack(kind: Kind, file: &Path, dir: &Path) -> Result<()> {
    let name = || file.display().to_string();
    match kind {
        Kind::Zip => {
            let mut zip = zip::ZipArchive::new(File::open(file)?)
                .map_err(|e| Error::format(name(), e.to_string()))?;
            zip.extract(dir).map_err(|e| Error::format(name(), e.to_string()))
        }
        Kind::Gzip => {
            let gz = flate2::read::GzDecoder::new(File::open(file)?);
            tar::Archive::new(gz).unpack(dir).map_err(|e| Error::format(name(), e.to_string()))
        }
        _ => unpack_with_tool(file, dir),
    }
}

/// Unpacks with the first archiver found on `PATH`.
fn unpack_with_tool(file: &Path, dir: &Path) -> Result<()> {
    type Args = fn(&Path, &Path) -> Vec<std::ffi::OsString>;
    let tools: [(&str, Args); 5] = [
        ("unar", |f, d| vec!["-q".into(), "-f".into(), "-o".into(), d.into(), f.into()]),
        ("7zz", seven_zip_args),
        ("7z", seven_zip_args),
        ("7za", seven_zip_args),
        ("bsdtar", |f, d| vec!["-x".into(), "-f".into(), f.into(), "-C".into(), d.into()]),
    ];
    let mut tried = false;
    for (tool, args) in tools {
        let Some(exe) = which(tool) else { continue };
        tried = true;
        let status = Command::new(exe)
            .args(args(file, dir))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            return Ok(());
        }
        log::debug!("{tool} could not unpack {}: {status}", file.display());
    }
    if tried {
        Err(Error::format(
            file.display().to_string(),
            "not an archive the installed unpackers read",
        ))
    } else {
        Err(Error::NeedTool(file.display().to_string()))
    }
}

fn seven_zip_args(f: &Path, d: &Path) -> Vec<std::ffi::OsString> {
    let mut out = std::ffi::OsString::from("-o");
    out.push(d);
    vec!["x".into(), "-y".into(), out, f.into()]
}

/// A program on `PATH`.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let p = dir.join(name);
        if p.is_file() {
            return Some(p);
        }
        let exe = dir.join(format!("{name}.exe"));
        exe.is_file().then_some(exe)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        let mut w = zip::ZipWriter::new(&mut buf);
        for (name, data) in entries {
            w.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap();
        buf.into_inner()
    }

    #[test]
    fn finds_plain_files_in_folders_any_case() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("bin")).unwrap();
        std::fs::write(dir.path().join("bin/LWLA1016.DLL"), b"x").unwrap();
        let mut input = Input::new([dir.path().to_owned()]);
        assert_eq!(input.read_named("lwla1016.dll").unwrap(), b"x");
    }

    #[test]
    fn opens_nested_archives_only_when_needed() {
        let inner = zip_with(&[("drv/Dso2090X861.sys", b"driver")]);
        let outer = zip_with(&[("pkg/inner.zip", &inner), ("readme.txt", b"hi")]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outer.zip");
        std::fs::write(&path, outer).unwrap();
        let mut input = Input::new([path.clone()]);
        assert_eq!(input.read_named("dso2090x861.sys").unwrap(), b"driver");
        // The given path is reported without the unpacked copies.
        assert_eq!(input.given().collect::<Vec<_>>(), vec![path.as_path()]);
    }

    #[test]
    fn reports_what_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mut input = Input::new([dir.path().to_owned()]);
        let e = input.read_named("top.bit").unwrap_err();
        assert!(matches!(e, Error::NotFound(ref n) if n == "top.bit"), "{e}");
    }

    #[test]
    fn names_a_broken_archive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken.zip");
        std::fs::write(&path, b"PK\x03\x04 not really a zip").unwrap();
        let e = Input::new([path]).read_named("top.bit").unwrap_err();
        assert!(matches!(e, Error::Format { ref name, .. } if name.ends_with("broken.zip")), "{e}");
    }

    #[test]
    fn reads_tar_gz() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.tar.gz");
        let gz = flate2::write::GzEncoder::new(
            File::create(&path).unwrap(),
            flate2::Compression::fast(),
        );
        let mut tar = tar::Builder::new(gz);
        let mut header = tar::Header::new_gnu();
        header.set_size(3);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "KingstVIS/KingstVIS", &b"elf"[..]).unwrap();
        tar.into_inner().unwrap().finish().unwrap();
        let mut input = Input::new([path]);
        assert_eq!(input.read_named("KingstVIS").unwrap(), b"elf");
    }
}
