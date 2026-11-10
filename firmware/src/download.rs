//! Downloading over HTTPS into the cache.
//!
//! Vendor servers are often slow and drop connections, so a download
//! tries each of its URLs in turn, and on each retries a few times,
//! resuming with a Range request where the server allows it. The whole
//! file is then checked against its pinned SHA-256 before it is kept.

use crate::error::{Error, Result};
use crate::install::Progress;
use crate::registry::{Download, sha256_hex};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Attempts per URL.
const ATTEMPTS: usize = 4;

/// Returns `d` from the cache, downloading it first if it is not there
/// or its hash is wrong. The cached file keeps `d.name` as its base
/// name, under a folder named after its hash.
pub(crate) fn get(d: &Download, cache: &Path, progress: &dyn Progress) -> Result<PathBuf> {
    let dir = cache.join(&d.sha256[..16]);
    let path = dir.join(d.name);
    if let Ok(data) = std::fs::read(&path)
        && sha256_hex(&data) == d.sha256
    {
        log::debug!("{} is cached at {}.", d.name, path.display());
        return Ok(path);
    }
    std::fs::create_dir_all(&dir)?;
    let agent = agent()?;
    let mut last = None;
    for url in d.urls {
        progress.message(&format!("Downloading {} ({}) from {url}", d.name, human(d.size)));
        match fetch_url(&agent, d, url, progress) {
            Ok(data) => {
                let got = sha256_hex(&data);
                if got != d.sha256 {
                    last = Some(Error::Checksum {
                        what: (*url).to_owned(),
                        got,
                        want: d.sha256.to_owned(),
                    });
                    continue;
                }
                crate::install::write_atomic(&path, &data)?;
                return Ok(path);
            }
            Err(e) => {
                log::warn!("{e}");
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| Error::Download { url: d.name.to_owned(), msg: "no URL".into() }))
}

/// The operating system's trusted roots (the system store on Linux and
/// the BSDs, the keychain on macOS, the certificate store on Windows).
fn system_roots() -> Result<ureq::tls::RootCerts> {
    let found = rustls_native_certs::load_native_certs();
    for e in &found.errors {
        log::debug!("Loading a system root certificate: {e}");
    }
    if found.certs.is_empty() {
        return Err(Error::Download {
            url: "(TLS setup)".into(),
            msg: "no trusted root certificates found on this system".into(),
        });
    }
    let certs: Vec<ureq::tls::Certificate<'static>> = found
        .certs
        .iter()
        .map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned())
        .collect();
    Ok(ureq::tls::RootCerts::new_with_certs(&certs))
}

fn agent() -> Result<ureq::Agent> {
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .root_certs(system_roots()?)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .build();
    Ok(ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_connect(Some(Duration::from_secs(30)))
        // Per read, not for the whole file: a slow server is fine, a
        // stalled one is retried.
        .timeout_recv_body(Some(Duration::from_secs(60)))
        .user_agent(concat!("oxrok-firmware-fetch/", env!("CARGO_PKG_VERSION")))
        .build()
        .into())
}

/// Downloads `url`, retrying and resuming; at most the pinned size.
fn fetch_url(
    agent: &ureq::Agent,
    d: &Download,
    url: &str,
    progress: &dyn Progress,
) -> Result<Vec<u8>> {
    let fail = |msg: String| Error::Download { url: url.to_owned(), msg };
    let limit = d.size;
    let mut data: Vec<u8> = Vec::with_capacity(usize::try_from(d.size).unwrap_or(0));
    let mut err = String::new();
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            log::info!("Retrying {url} at byte {} ({err}).", data.len());
            std::thread::sleep(Duration::from_secs(2 * attempt as u64));
            err.clear();
        }
        let mut req = agent.get(url);
        if !data.is_empty() {
            req = req.header("Range", &format!("bytes={}-", data.len()));
        }
        let resp = match req.call() {
            Ok(r) => r,
            Err(e) => {
                err = e.to_string();
                continue;
            }
        };
        if resp.status() != 206 {
            // Not resumed: start over.
            data.clear();
        }
        let remaining = limit.saturating_sub(data.len() as u64) + 1;
        let mut reader = resp.into_body().into_with_config().limit(remaining).reader();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    data.extend_from_slice(&buf[..n]);
                    progress.download(d.name, data.len() as u64, d.size);
                    if data.len() as u64 > limit {
                        return Err(fail(format!("larger than the pinned {} bytes", d.size)));
                    }
                }
                Err(e) => {
                    err = e.to_string();
                    break;
                }
            }
        }
        if data.len() as u64 == limit {
            return Ok(data);
        }
        if err.is_empty() {
            err = format!("ended after {} of {} bytes", data.len(), d.size);
        }
    }
    Err(fail(err))
}

fn human(bytes: u64) -> String {
    if bytes >= 1 << 20 {
        format!("{:.1} MB", bytes as f64 / f64::from(1u32 << 20))
    } else {
        format!("{} kB", bytes.div_ceil(1024))
    }
}
