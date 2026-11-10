//! The error type.

/// What can go wrong while fetching or extracting firmware.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An I/O error.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// No package provides the file.
    #[error("no known source for firmware file {0}")]
    UnknownFile(String),
    /// No package has the id.
    #[error("unknown firmware package {0}")]
    UnknownPackage(String),
    /// A download or a known file has other contents than pinned.
    #[error("{what} has SHA-256 {got}, expected {want}")]
    Checksum {
        /// The file.
        what: String,
        /// Its hash.
        got: String,
        /// The pinned hash.
        want: String,
    },
    /// A download failed.
    #[error("downloading {url} failed: {msg}")]
    Download {
        /// What was fetched.
        url: String,
        /// Why it failed.
        msg: String,
    },
    /// The package can only come from the user.
    #[error("{package} can't be downloaded, the files must come from you:\n{instructions}")]
    Manual {
        /// The package's title.
        package: String,
        /// Where to get the files.
        instructions: String,
    },
    /// Built without the `download` feature.
    #[error("this build cannot download (the `download` feature is off)")]
    NoDownload,
    /// What the extractor needs is not among the files given.
    #[error("{0} not found in the files given")]
    NotFound(String),
    /// A file is not in the expected format.
    #[error("{name}: {msg}")]
    Format {
        /// The file.
        name: String,
        /// What is wrong.
        msg: String,
    },
    /// An archive needs a tool that is not installed.
    #[error(
        "{0} needs an external unpacker: install unar, 7-Zip (7zz or 7z) or bsdtar, \
         or unpack it yourself and give the folder instead"
    )]
    NeedTool(String),
}

impl Error {
    pub(crate) fn format(name: impl Into<String>, msg: impl Into<String>) -> Self {
        Error::Format { name: name.into(), msg: msg.into() }
    }
}

/// The result type.
pub type Result<T, E = Error> = std::result::Result<T, E>;
