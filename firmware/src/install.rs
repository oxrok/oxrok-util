//! Fetching, importing and installing a package's files.

use crate::error::{Error, Result};
use crate::extract::Extracted;
use crate::input::Input;
use crate::registry::{Digest, Package};
use std::path::{Path, PathBuf};

/// Hears how a fetch goes, for a progress bar or a log.
pub trait Progress {
    /// A step: "Downloading …", "Extracting …".
    fn message(&self, _msg: &str) {}
    /// Bytes of a download so far, and its size.
    fn download(&self, _name: &str, _done: u64, _total: u64) {}
}

impl Progress for () {}

/// How [`fetch`] works.
pub struct Options<'a> {
    /// Where downloads are kept between runs.
    pub cache_dir: PathBuf,
    /// Told about each step.
    pub progress: &'a dyn Progress,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Options { cache_dir: default_cache_dir().unwrap_or_else(std::env::temp_dir), progress: &() }
    }
}

/// What a fetch or an import installed.
#[derive(Debug, Default)]
pub struct Installed {
    /// The files written.
    pub files: Vec<PathBuf>,
    /// Things worth telling the user: a version with unknown hashes, a
    /// file that was not found.
    pub warnings: Vec<String>,
}

/// The per-user firmware directory oxrok searches:
/// `$XDG_DATA_HOME/oxrok-firmware`, else `~/.local/share/oxrok-firmware`.
pub fn default_install_dir() -> Option<PathBuf> {
    data_home().map(|d| d.join("oxrok-firmware"))
}

/// Where downloads are cached: `$XDG_CACHE_HOME/oxrok-firmware`, else
/// `~/.cache/oxrok-firmware` (`~/Library/Caches` on macOS,
/// `%LOCALAPPDATA%` on Windows).
pub fn default_cache_dir() -> Option<PathBuf> {
    let env = |v: &str| std::env::var_os(v).filter(|s| !s.is_empty()).map(PathBuf::from);
    let base = env("XDG_CACHE_HOME").or_else(|| {
        if cfg!(windows) {
            env("LOCALAPPDATA")
        } else if cfg!(target_os = "macos") {
            env("HOME").map(|h| h.join("Library/Caches"))
        } else {
            env("HOME").map(|h| h.join(".cache"))
        }
    })?;
    Some(base.join("oxrok-firmware"))
}

fn data_home() -> Option<PathBuf> {
    let env = |v: &str| std::env::var_os(v).filter(|s| !s.is_empty()).map(PathBuf::from);
    env("XDG_DATA_HOME")
        .or_else(|| env("HOME").or_else(|| env("USERPROFILE")).map(|h| h.join(".local/share")))
}

/// Downloads `pkg`, checks the downloads against their pinned hashes,
/// extracts the firmware and installs it into `dest`.
///
/// A package that cannot be downloaded fails with [`Error::Manual`],
/// which carries the instructions to show the user; the files they then
/// get go to [`import`].
pub fn fetch(pkg: &Package, dest: &Path, opts: &Options<'_>) -> Result<Installed> {
    if pkg.downloads.is_empty() {
        return Err(manual(pkg));
    }
    #[cfg(feature = "download")]
    {
        let mut paths = Vec::new();
        for d in pkg.downloads {
            paths.push(crate::download::get(d, &opts.cache_dir, opts.progress)?);
        }
        run(pkg, Input::new(paths), dest, opts.progress, true)
    }
    #[cfg(not(feature = "download"))]
    {
        let _ = (dest, opts);
        Err(Error::NoDownload)
    }
}

/// Extracts `pkg`'s firmware from files the user gave (installers,
/// archives, folders or the firmware files themselves) and installs it
/// into `dest`.
pub fn import(
    pkg: &Package,
    paths: &[PathBuf],
    dest: &Path,
    progress: &dyn Progress,
) -> Result<Installed> {
    run(pkg, Input::new(paths.iter().cloned()), dest, progress, false)
}

fn manual(pkg: &Package) -> Error {
    Error::Manual {
        package: pkg.title.to_owned(),
        instructions: pkg.manual.map_or_else(String::new, |m| m.instructions()),
    }
}

/// Extracts, verifies and installs. `pinned`: the input is a pinned
/// download, so every file must come out with its known hash.
fn run(
    pkg: &Package,
    mut input: Input,
    dest: &Path,
    progress: &dyn Progress,
    pinned: bool,
) -> Result<Installed> {
    progress.message(&format!("Extracting {}", pkg.title));
    let mut out = Extracted::default();
    // The firmware files themselves, e.g. a sigrok-firmware folder.
    let plain = input.find_plain(|n| pkg.files.iter().any(|f| f.eq_ignore_ascii_case(n)));
    if plain.len() >= pkg.files.len() || pkg.extract.is_none() {
        for f in pkg.files {
            match input.read_named(f) {
                Ok(data) => out.add(*f, data),
                Err(Error::NotFound(_)) if !pinned => {}
                Err(e) => return Err(e),
            }
        }
    }
    if out.files.is_empty()
        && let Some(extract) = pkg.extract
    {
        extract(pkg, &mut input, &mut out)?;
    }
    if out.files.is_empty() {
        return Err(Error::NotFound(format!("{} firmware", pkg.title)));
    }

    let mut installed = Installed { warnings: out.warnings, ..Installed::default() };
    for (name, data) in &out.files {
        if let Some(want) = pkg.known_digest(name) {
            let ok = want.matches(data);
            if !ok && pinned {
                return Err(Error::Checksum {
                    what: name.clone(),
                    got: crate::registry::sha256_hex(data),
                    want: want.to_string(),
                });
            }
            if !ok {
                installed.warnings.push(format!(
                    "{name} differs from the version oxrok knows ({want}); \
                     it may still work if your vendor software is another release"
                ));
            }
        }
    }
    let missing: Vec<&str> =
        pkg.files.iter().copied().filter(|f| !out.files.contains_key(*f)).collect();
    if !missing.is_empty() {
        installed.warnings.push(format!("not found in what was given: {}", missing.join(", ")));
    }

    std::fs::create_dir_all(dest)?;
    for (name, data) in out.files {
        let path = dest.join(&name);
        write_atomic(&path, &data)?;
        progress.message(&format!("Installed {}", path.display()));
        installed.files.push(path);
    }
    Ok(installed)
}

/// Writes through a temporary file in the same folder and a rename, so
/// a driver never reads half a file.
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(data)?;
    // A temporary file is 0600; firmware in a shared directory must be
    // readable by every user's drivers.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file().set_permissions(std::fs::Permissions::from_mode(0o644))?;
    }
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

impl Digest {
    fn matches(self, data: &[u8]) -> bool {
        match self {
            Digest::Sha256(h) => crate::registry::sha256_hex(data) == h,
            Digest::Md5(h) => {
                use md5::Digest as _;
                hex(&md5::Md5::digest(data)) == h
            }
        }
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
