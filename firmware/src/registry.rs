//! Every firmware file oxrok's drivers look up, and where it comes from.
//!
//! A [`Package`] is one way to get a set of files: pinned downloads, or
//! instructions for files only the user can get, and the extractor that
//! turns either into the files drivers load. Hashes of the downloads are
//! pinned, so a vendor changing a file fails loudly instead of
//! installing something untested; hashes of the outputs, where known,
//! check the extraction and tell an import from another release apart.

use crate::error::Result;
use crate::extract::{self, Extracted};
use crate::input::Input;
use std::fmt;

/// An extractor: reads what it needs from the input, adds the files of
/// the package.
pub(crate) type Extractor = fn(&Package, &mut Input, &mut Extracted) -> Result<()>;

/// A pinned download.
#[derive(Clone, Copy, Debug)]
pub struct Download {
    /// The file's name, kept in the cache.
    pub name: &'static str,
    /// Where it is fetched from: mirrors after the first, tried in turn.
    pub urls: &'static [&'static str],
    /// Its SHA-256, lowercase hex.
    pub sha256: &'static str,
    /// Its size in bytes.
    pub size: u64,
}

/// What to tell a user who has to get the files themselves.
#[derive(Clone, Copy, Debug)]
pub struct Manual {
    /// What to give to `import`, in a phrase.
    pub what: &'static str,
    /// Where to get it.
    pub url: Option<&'static str>,
    /// Steps, one per line.
    pub steps: &'static str,
}

impl Manual {
    /// The instructions as text, for a terminal or a dialog.
    pub fn instructions(&self) -> String {
        let mut s = format!("Provide {}.", self.what);
        if let Some(url) = self.url {
            s.push_str("\nGet it from: ");
            s.push_str(url);
        }
        for line in self.steps.lines().filter(|l| !l.trim().is_empty()) {
            s.push_str("\n  - ");
            s.push_str(line.trim());
        }
        s
    }
}

/// A hash a file is known to have.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Digest {
    Sha256(&'static str),
    /// Only MD5 is published for some files (the sigrok wiki's lists).
    Md5(&'static str),
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Digest::Sha256(h) => write!(f, "SHA-256 {h}"),
            Digest::Md5(h) => write!(f, "MD5 {h}"),
        }
    }
}

/// One way to get a set of firmware files.
#[derive(Debug)]
pub struct Package {
    /// A short id, for `oxrok firmware fetch ID`.
    pub id: &'static str,
    /// What it is, for people.
    pub title: &'static str,
    /// The files it installs.
    pub files: &'static [&'static str],
    /// Files drivers accept instead of these, which it makes needless:
    /// a driver missing one of these should be offered this package.
    pub covers: &'static [&'static str],
    /// Its downloads; none when only the user can get the files.
    pub downloads: &'static [Download],
    /// How the user gets the files when they cannot be downloaded, or
    /// another way to get them (a CD, the installed software).
    pub manual: Option<Manual>,
    /// Anything else worth knowing.
    pub note: Option<&'static str>,
    pub(crate) extract: Option<Extractor>,
    pub(crate) known: &'static [(&'static str, Digest)],
}

impl Package {
    /// Whether [`crate::fetch`] can get it without the user.
    pub fn downloadable(&self) -> bool {
        !self.downloads.is_empty()
    }

    /// The bytes all its downloads take.
    pub fn download_size(&self) -> u64 {
        self.downloads.iter().map(|d| d.size).sum()
    }

    /// Every host a [`crate::fetch`] of it may contact, mirrors
    /// included, for telling the user where a download goes.
    pub fn hosts(&self) -> Vec<&'static str> {
        let mut hosts: Vec<&'static str> = Vec::new();
        let urls = self.downloads.iter().flat_map(|d| d.urls.iter());
        for host in urls.filter_map(|u| u.split('/').nth(2)) {
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
        hosts
    }

    /// Whether its downloads need an external [`crate::unpacker`]: a
    /// RAR, 7z or ISO no Rust code here reads. For a file the user picks
    /// to import, ask [`crate::file_needs_unpacker`].
    pub fn needs_unpacker(&self) -> bool {
        self.downloads.iter().any(|d| {
            let n = d.name.to_ascii_lowercase();
            [".rar", ".7z", ".iso"].iter().any(|e| n.ends_with(e))
        })
    }

    pub(crate) fn known_digest(&self, file: &str) -> Option<Digest> {
        self.known.iter().find(|(f, _)| *f == file).map(|(_, d)| *d)
    }
}

/// Every package.
pub fn packages() -> &'static [Package] {
    PACKAGES
}

/// The package with id `id`.
pub fn package(id: &str) -> Option<&'static Package> {
    PACKAGES.iter().find(|p| p.id == id)
}

/// The package that provides (or makes needless) firmware file `file`.
pub fn package_for(file: &str) -> Option<&'static Package> {
    PACKAGES
        .iter()
        .find(|p| p.files.contains(&file))
        .or_else(|| PACKAGES.iter().find(|p| p.covers.contains(&file)))
}

/// Every file some package installs.
pub fn all_files() -> impl Iterator<Item = &'static str> {
    PACKAGES.iter().flat_map(|p| p.files.iter().copied())
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest as _;
    crate::install::hex(&sha2::Sha256::digest(data))
}

/// `DSView` 0.97's resources, the set libsigrok supports.
macro_rules! dsview {
    ($path:literal) => {
        concat!(
            "https://raw.githubusercontent.com/DreamSourceLab/DSView/",
            "886b847c21c606df3138ce7ad8f8e8c363ee758b/DSView/res/",
            $path
        )
    };
}

/// oxrok-firmware: firmware whose vendor allowed redistribution.
macro_rules! oxrok_firmware {
    ($path:literal) => {
        concat!(
            "https://raw.githubusercontent.com/oxrok/oxrok-firmware/",
            "11eed913a9c535b87b5d5b5b92d2622cf34cee8b/",
            $path
        )
    };
}

macro_rules! gdrive {
    ($id:literal) => {
        concat!("https://drive.usercontent.google.com/download?export=download&confirm=t&id=", $id)
    };
}

/// A download whose cache name is the firmware file it installs.
macro_rules! file {
    ($name:literal, $url:expr, $sha:literal, $size:literal) => {
        Download { name: $name, urls: &[$url], sha256: $sha, size: $size }
    };
}

/// One Hantek DSO model: its driver package, the 32-bit loader driver
/// holds the firmware.
macro_rules! hantek {
    ($id:literal, $title:literal, $file:literal, $dl:expr, $sha:literal) => {
        Package {
            id: $id,
            title: $title,
            files: &[$file],
            covers: &[],
            downloads: &[$dl],
            manual: Some(Manual {
                what: "the model's Windows driver package from Hantek, or its DsoXXXXX861.sys",
                url: Some("https://www.hantek.com/download"),
                steps: "",
            }),
            note: None,
            extract: Some(extract::hantek::extract),
            known: sha!($file => $sha),
        }
    };
}

macro_rules! sha {
    ($($f:literal => $h:literal),* $(,)?) => { &[$(($f, Digest::Sha256($h))),*] };
}

static PACKAGES: &[Package] = &[
    Package {
        id: "dreamsourcelab-dslogic",
        title: "DreamSourceLab DSLogic and DSCope (DSView 0.97 set)",
        files: &[
            "dreamsourcelab-dslogic-fpga-5v.fw",
            "dreamsourcelab-dslogic-fpga-3v3.fw",
            "dreamsourcelab-dslogic-fx2.fw",
            "dreamsourcelab-dscope-fpga.fw",
            "dreamsourcelab-dscope-fx2.fw",
            "dreamsourcelab-dslogic-pro-fpga.fw",
            "dreamsourcelab-dslogic-pro-fx2.fw",
            "dreamsourcelab-dslogic-plus-fpga.fw",
            "dreamsourcelab-dslogic-plus-fx2.fw",
            "dreamsourcelab-dslogic-basic-fpga.fw",
            "dreamsourcelab-dslogic-basic-fx2.fw",
        ],
        covers: &[],
        downloads: &[
            Download { name: "dreamsourcelab-dslogic-fpga-5v.fw", urls: &[dsview!("DSLogic50.bin")], sha256: "094d62dc40731c8491532d171d6dc16297e17438d229c12b77335ab15599228a", size: 341_160 },
            Download { name: "dreamsourcelab-dslogic-fpga-3v3.fw", urls: &[dsview!("DSLogic33.bin")], sha256: "cc1e464b4521aaf6073a91a6310ed56d399a3c29ab6f0b08788f7fb35c815047", size: 341_160 },
            Download { name: "dreamsourcelab-dslogic-fx2.fw", urls: &[dsview!("DSLogic.fw")], sha256: "b354d7ff9a1d5c01f88b17ba92a0978055190428d9bf9e256efbeb0c25ae8513", size: 8120 },
            Download { name: "dreamsourcelab-dscope-fpga.fw", urls: &[dsview!("DSCope.bin")], sha256: "f9193dd20754c8cc717c90047cefa751826ab3ea3ee9a071ad3b030388c49611", size: 341_436 },
            Download { name: "dreamsourcelab-dscope-fx2.fw", urls: &[dsview!("DSCope.fw")], sha256: "4f024d250bdbb9a2f65d176bb8b533bc5a5f4409a34074e16d2c7d473d80ec68", size: 8120 },
            Download { name: "dreamsourcelab-dslogic-pro-fpga.fw", urls: &[dsview!("DSLogicPro.bin")], sha256: "dcac2a3eab0319930cfff1bafbc7871f1d9394c36877d08a6ffd0be34024f340", size: 341_436 },
            Download { name: "dreamsourcelab-dslogic-pro-fx2.fw", urls: &[dsview!("DSLogicPro.fw")], sha256: "a8999f5b2b0f09581b3619e29bea1c1cfae9924ac555d9f7399d491dfb91fa3a", size: 8120 },
            Download { name: "dreamsourcelab-dslogic-plus-fpga.fw", urls: &[dsview!("DSLogicPlus.bin")], sha256: "e16c70e4af9181044e3ec3a363e4bb109f1d731b4f9f046f8bc1d1015a7842a7", size: 341_160 },
            Download { name: "dreamsourcelab-dslogic-plus-fx2.fw", urls: &[dsview!("DSLogicPlus.fw")], sha256: "9197e08dd33a9cda61cc8cd3de559cbae9b049b2dfa827c089ffe0528f5dcc5e", size: 8120 },
            Download { name: "dreamsourcelab-dslogic-basic-fpga.fw", urls: &[dsview!("DSLogicBasic.bin")], sha256: "2b1597dc4e6cc365f9e34e03203274d179960a00c2c0537b6a5a73c51cd3d7fe", size: 341_160 },
            Download { name: "dreamsourcelab-dslogic-basic-fx2.fw", urls: &[dsview!("DSLogicBasic.fw")], sha256: "a157a7810c885842e54de14dd1bfb99566227513cb9a62539c1659a36138f002", size: 8120 },
        ],
        manual: None,
        note: Some("The firmware set libsigrok supports since 2017-06."),
        extract: None,
        known: &[],
    },
    Package {
        id: "fx2lafw",
        title: "fx2lafw open firmware 0.1.7 (sigrok)",
        files: &[
            "fx2lafw-braintechnology-usb-lps.fw",
            "fx2lafw-cwav-usbeeax.fw",
            "fx2lafw-cwav-usbeedx.fw",
            "fx2lafw-cwav-usbeesx.fw",
            "fx2lafw-cwav-usbeezx.fw",
            "fx2lafw-cypress-fx2.fw",
            "fx2lafw-hantek-6022be.fw",
            "fx2lafw-hantek-6022bl.fw",
            "fx2lafw-sainsmart-dds120.fw",
            "fx2lafw-saleae-logic.fw",
            "fx2lafw-sigrok-fx2-16ch.fw",
            "fx2lafw-sigrok-fx2-8ch.fw",
            "fx2lafw-yixingdianzi-mdso.fw",
        ],
        covers: &[],
        downloads: &[Download {
            name: "sigrok-firmware-fx2lafw-bin-0.1.7.tar.gz",
            urls: &["https://sigrok.org/download/binary/sigrok-firmware-fx2lafw/sigrok-firmware-fx2lafw-bin-0.1.7.tar.gz"],
            sha256: "c876fd075549e7783a6d5bfc8d99a695cfc583ddbcea0217d8e3f9351d1723af",
            size: 54_529,
        }],
        manual: None,
        note: Some("Free software (GPL-2.0-or-later), built by sigrok."),
        extract: None,
        known: &[],
    },
    Package {
        id: "fx2lafw-git",
        title: "fx2lafw open firmware, newer than 0.1.7",
        files: &["fx2lafw-instrustar-isds205b.fw", "fx2lafw-usb-c-grok.fw"],
        covers: &[],
        downloads: &[],
        manual: Some(Manual {
            what: "the fx2lafw-*.fw files built from fx2lafw's git (or a distribution package newer than 0.1.7)",
            url: Some("https://github.com/sigrokproject/sigrok-firmware-fx2lafw"),
            steps: "No release ships these yet; build them from source:
                git clone https://github.com/sigrokproject/sigrok-firmware-fx2lafw && cd sigrok-firmware-fx2lafw
                ./autogen.sh && ./configure && make   (needs sdcc)
                then import the folder, or the .fw files",
        }),
        note: None,
        extract: None,
        known: &[],
    },
    Package {
        id: "asix-sigma",
        title: "ASIX SIGMA/SIGMA2 FPGA netlists (oxrok-firmware)",
        files: &["asix-sigma-50.fw", "asix-sigma-50sync.fw", "asix-sigma-100.fw", "asix-sigma-200.fw"],
        covers: &[],
        downloads: &[
            file!("asix-sigma-50.fw", oxrok_firmware!("asix-sigma/asix-sigma-50.fw"), "5a1548b3090aac532de10a13359f971638aadfb1daf3a0719a632ae16f2f6422", 45_432),
            file!("asix-sigma-50sync.fw", oxrok_firmware!("asix-sigma/asix-sigma-50sync.fw"), "b619b34901dbc00aed842927901d8334c2aea82a9707375dbf163ec6801362f2", 45_360),
            file!("asix-sigma-100.fw", oxrok_firmware!("asix-sigma/asix-sigma-100.fw"), "5b3890a309966ba1e6e698937aa86354cd81559254edf786ffcb87693b2c8c2b", 45_140),
            file!("asix-sigma-200.fw", oxrok_firmware!("asix-sigma/asix-sigma-200.fw"), "d39fd8daabb9613d45447400eb4c26d8c0e2d0ce5ca6ba596afa2daefcd68535", 45_396),
        ],
        manual: None,
        note: Some("Redistributed with ASIX's permission, see LICENSE.Sigma in oxrok-firmware."),
        extract: None,
        known: &[],
    },
    Package {
        id: "kingst-la",
        title: "Kingst LA series (KingstVIS 3.6.6)",
        files: &[
            "kingst-la-01a1.fw", "kingst-la-01a2.fw", "kingst-la-01a3.fw", "kingst-la-01a4.fw", "kingst-la-03a1.fw",
            "kingst-la1010a0-fpga.bitstream", "kingst-la1010a1-fpga.bitstream", "kingst-la1010a2-fpga.bitstream",
            "kingst-la1016-fpga.bitstream", "kingst-la1016a1-fpga.bitstream",
            "kingst-la2016-fpga.bitstream", "kingst-la2016a1-fpga.bitstream", "kingst-la2016a2-fpga.bitstream",
            "kingst-la5016-fpga.bitstream", "kingst-la5016a1-fpga.bitstream", "kingst-la5016a2-fpga.bitstream",
            "kingst-la5032a0-fpga.bitstream", "kingst-ms6218-fpga.bitstream",
        ],
        covers: &[],
        downloads: &[Download {
            name: "KingstVIS_v3.6.6.tar.gz",
            urls: &[
                "https://res.kingst.site/kfs/KingstVIS_v3.6.6.tar.gz",
                "https://www.qdkingst.com/kfs/KingstVIS_v3.6.6.tar.gz",
            ],
            sha256: "3fefb1416998b3b2f8c7c6c519deb04b9c26585bbb9f5d5ecded1e385838fb70",
            size: 29_160_040,
        }],
        manual: Some(Manual {
            what: "the KingstVIS program (Linux, macOS or Windows build), or its download",
            url: Some("https://www.qdkingst.com/en/download"),
            steps: "Any build works: KingstVIS (Linux), KingstVIS.app/Contents/MacOS/KingstVIS, or KingstVIS.exe",
        }),
        note: None,
        extract: Some(extract::kingst::extract),
        known: sha!(
            "kingst-la-01a1.fw" => "b25d34a22fae5bae5aa60454b99d7916384d88681884060086f555676579a18e",
            "kingst-la-01a2.fw" => "87a8bbc96bed5e179069717f971e05b3a3d1703d4ef096f2b276d454f129bd22",
            "kingst-la-01a3.fw" => "d23f1140636d92929663175f0bc6a592060d75a35f064c0c03d6d766057a3843",
            "kingst-la-01a4.fw" => "bdfd098400bd21c6875fc8e19ba2bd93c0415c1a62f1e36a8713c6b830096b0c",
            "kingst-la-03a1.fw" => "022099f258523e4b7a06e044726243319b19c99230b179a50134861bd2b91e5c",
            "kingst-la1010a0-fpga.bitstream" => "e362de3925ffcaece2286aff2538ece507baeeda4327f19babc5b0a352a383e7",
            "kingst-la1010a1-fpga.bitstream" => "c7afe03315237ff46d456ae3036e9c3d2ca41bd128889f703bdeed995462a499",
            "kingst-la1010a2-fpga.bitstream" => "125a128f515a36e3e3e3aef78e0627b5a008e38f7283d02c22fd595978b857f6",
            "kingst-la1016-fpga.bitstream" => "386fa5cd95847c9385706377d6cb574438399496fb3066930aba20867dea0f07",
            "kingst-la1016a1-fpga.bitstream" => "f88a5c6ed43978496b488fa2c72c16bebba82a078ccc3fc2d2a49eb53d148da3",
            "kingst-la2016-fpga.bitstream" => "59957732878ba67022e3245a4532fb55da983b716742e79dd059a19af9b69219",
            "kingst-la2016a1-fpga.bitstream" => "9110d239f8f117d3333574f5493d477873feef73db82ee8025d68c73a381a159",
            "kingst-la2016a2-fpga.bitstream" => "bb2ba076533cb8d653d2f75dd3bcaa3d3b054fdeb926e71a63b0d4176c0734ac",
            "kingst-la5016-fpga.bitstream" => "8bc62e11fad368c352180ced4621b84a397e3591d6fa8b24a201976d59972de8",
            "kingst-la5016a1-fpga.bitstream" => "d2aa87d6e89be5530fda09fcfbe1cb73ff37cac0f1d69e144c53b0ac4cf2f675",
            "kingst-la5016a2-fpga.bitstream" => "ce9e24b3e2a898d26b0df17a82d0e46dc14e2eb50da5d34e276d83b7ca0ed28d",
            "kingst-la5032a0-fpga.bitstream" => "9225d7ca802a75a0e7fd5cb79b9640b972ea64e3556b9611c217e6f95c378c00",
            "kingst-ms6218-fpga.bitstream" => "69b85d66c14e178293b754f5f0b162f824b3b008acb115f4bc4bc2967afca37c",
        ),
    },
    Package {
        id: "saleae-logic",
        title: "Saleae Logic16, Logic Pro 8 and Logic Pro 16 (Logic 1.2.10)",
        files: &[
            "saleae-logic16-fx2.fw",
            "saleae-logic16-fpga-18.bitstream",
            "saleae-logic16-fpga-33.bitstream",
            "saleae-logicpro16-fx3.fw",
            "saleae-logicpro8-fx3.fw",
            "saleae-logicpro16-fpga.bitstream",
            "saleae-logicpro8-fpga.bitstream",
        ],
        covers: &[],
        downloads: &[Download {
            name: "Logic 1.2.10 (64-bit).zip",
            urls: &["https://downloads.saleae.com/logic/1.2.10/Logic%201.2.10%20(64-bit).zip"],
            sha256: "07121e7833a14cae929b5d84e0faa56e77f1e659381976b4f6f7b068dd157dea",
            size: 12_397_923,
        }],
        manual: Some(Manual {
            what: "the Linux \"Logic\" program of Saleae Logic 1.2.x, or its zip",
            url: Some("https://support.saleae.com/logic-software/legacy-software/older-software-releases"),
            steps: "Logic 1.2.18 and Logic 2 no longer contain the firmware; 1.2.10 does",
        }),
        note: None,
        extract: Some(extract::saleae::extract),
        known: sha!(
            "saleae-logic16-fx2.fw" => "e3c87262a4a79ccb1cf5bd7848ce7183235d2914a9fc1774bd8f960ba411fdbc",
            "saleae-logic16-fpga-18.bitstream" => "ad86c11965ee55f6705ad7ac6a5d7b57bad3a2a5d815633f5ded2e2fa553000f",
            "saleae-logic16-fpga-33.bitstream" => "0748da041cf56d2dba1165e1a2718f46f0525428c118f100f50905c9e0c9d7ac",
            "saleae-logicpro16-fx3.fw" => "c5c5da48317497b81343cb0ed7c815bf1e388a3977b8518e4b1cbed4580e03d3",
            "saleae-logicpro8-fx3.fw" => "ee091c4e0e20947f4068625a247fc75fe87f6b384e70a65ebf3c83184cff5242",
            "saleae-logicpro16-fpga.bitstream" => "e36720e59e0dea1dc4bd4a860e2b5b163dec09248af10882144960cad92db9a4",
            "saleae-logicpro8-fpga.bitstream" => "abe49cd4a3171f8344f789b3eb538b52bf8298c3df7525a9a3ec5124567f4b07",
        ),
    },
    Package {
        id: "intronix-logicport",
        title: "Intronix LogicPort LA1034 (LogicPort build 2371)",
        files: &["intronix-logicport.ccf"],
        covers: &[
            "intronix-logicport-state-after.rbf",
            "intronix-logicport-state-before-clk1-rise.rbf",
            "intronix-logicport-state-before-clk2-rise.rbf",
            "intronix-logicport-state-before-clk1-fall.rbf",
            "intronix-logicport-state-before-clk2-fall.rbf",
            "intronix-logicport-state-on.rbf",
            "intronix-logicport-timing-ddr.rbf",
            "intronix-logicport-timing-sdr.rbf",
        ],
        downloads: &[Download {
            name: "logicport_2371.exe",
            urls: &["https://www.pctestinstruments.com/downloads/logicport_2371.exe"],
            sha256: "4943568f001a481250dd73ce9d841de73b274c0f93d0897f3c7adc222f811d0c",
            size: 4_877_000,
        }],
        manual: Some(Manual {
            what: "the LogicPort installer (logicport_*.exe) or LogicPort.ccf from an installed copy",
            url: Some("https://www.pctestinstruments.com/"),
            steps: "",
        }),
        note: None,
        extract: Some(extract::intronix::extract),
        known: sha!("intronix-logicport.ccf" => "9298a5eacb3cf1a791b8ce48460a19e031eb81baffa378bab3f94f2d78483f9c"),
    },
    hantek!("hantek-dso-2090", "Hantek DSO-2090", "hantek-dso-2090.fw", Download {
        name: "DSO2090.zip",
        urls: &["https://hantek.com/uploadpic/hantek/files/20251127/DSO2090.zip"],
        sha256: "586e67dfb19f61618e5252032e72dba127aed82d1e6a0732bd07ebe83eb53c97",
        size: 199_409,
    }, "42ff7f7c883acc1cfeeb3e0980102156929ff206c525f01809ea2b9ebd2ef8eb"),
    hantek!("hantek-dso-2150", "Hantek DSO-2150", "hantek-dso-2150.fw", Download {
        name: "DSO2150_Software.zip",
        urls: &["https://www.hantek.com/Product/DSO2000/DSO2150_Software.zip"],
        sha256: "8b85450b0b341c53edb6b1f14b9c334451167867c64398fb76f734fea826c349",
        size: 16_492_878,
    }, "dd967b4bf2277c239ef2b7cb9ec5c1be5d5c89b21f77f9ffb448fa131a22bd7c"),
    hantek!("hantek-dso-2250", "Hantek DSO-2250", "hantek-dso-2250.fw", Download {
        name: "DSO2250.zip",
        urls: &["https://hantek.com/uploadpic/hantek/files/20251125/DSO2250.zip"],
        sha256: "ec7a7abced09ede99b662023f7db7be166753ef7df44dc162ea1e226f4248351",
        size: 395_142,
    }, "1d9b3a902caa8a9b92e8f1ba718060113ea7578f6a19dcea88656c51e1455c1b"),
    hantek!("hantek-dso-5200", "Hantek DSO-5200", "hantek-dso-5200.fw", Download {
        name: "DSO5200_Software.zip",
        urls: &["https://www.hantek.com/Product/DSO2000/DSO5200_Software.zip"],
        sha256: "eb36b4b29359616e8e0b6daf719e905f77455dd9fc943f61cdd4ba56bc5d18cc",
        size: 12_117_631,
    }, "e5be3cfed4ca31665d273f9c3c72ae098bc6f9bb12b3994f47bb8b01cff14f9b"),
    hantek!("hantek-dso-5200a", "Hantek DSO-5200A", "hantek-dso-5200A.fw", Download {
        name: "DSO5200A-Win11.rar",
        urls: &["https://hantek.com/uploadpic/hantek/files/20251125/DSO5200A-Win11.rar"],
        sha256: "34701d7aab3d69b941a4fdc79754e6c641d1244dda0d424b3b6d47c5db91c3e7",
        size: 188_888,
    }, "d9293ef89ed96ef58946ff203fe043ef9ab6659e5860515f93412e5e0579ce0f"),
    Package {
        id: "lecroy-logicstudio",
        title: "LeCroy LogicStudio 16",
        files: &[
            "lecroy-logicstudio16-fx2lp.fw",
            "lecroy-logicstudio16-8.bitstream",
            "lecroy-logicstudio16-16.bitstream",
        ],
        covers: &[],
        downloads: &[],
        manual: Some(Manual {
            what: "the LogicStudio installer zip (1.2.5.0), or LS16Lib.dll and LogicStudio16Load.spt from an installed copy",
            url: Some("https://www.teledynelecroy.com/support/softwaredownload/logicstudio.aspx"),
            steps: "Teledyne LeCroy needs a free account (its approval can take a day or two)
                Download \"LogicStudio Installer\" (32 or 64 bit, version 1.2.5.0)
                Give oxrok the downloaded zip as it is; nothing has to be installed",
        }),
        note: None,
        extract: Some(extract::lecroy::extract),
        known: &[
            ("lecroy-logicstudio16-fx2lp.fw", Digest::Md5("1638e2a5ef211c10f48405c1c16a057f")),
            ("lecroy-logicstudio16-16.bitstream", Digest::Md5("1ab904704def72f18543d9d7aa929002")),
            ("lecroy-logicstudio16-8.bitstream", Digest::Md5("5763c67cb762c85c8b1d09dc1f239acb")),
        ],
    },
    Package {
        id: "sysclk-lwla1034",
        title: "Sysclk LWLA1034 (oxrok-firmware)",
        files: &[
            "sysclk-lwla1034-int.rbf",
            "sysclk-lwla1034-extpos.rbf",
            "sysclk-lwla1034-extneg.rbf",
            "sysclk-lwla1034-off.rbf",
        ],
        covers: &[],
        downloads: &[
            file!("sysclk-lwla1034-int.rbf", oxrok_firmware!("sysclk-lwla/sysclk-lwla1034-int.rbf"), "84a10ceafe9303a8c05d743269ab23d3169977ab4ec5e7b364c340e05a458e0a", 81_460),
            file!("sysclk-lwla1034-extpos.rbf", oxrok_firmware!("sysclk-lwla/sysclk-lwla1034-extpos.rbf"), "f0170f9751f69b2a6209fd563c48e09076d592f9d946c92f23af2c61867b1a87", 81_808),
            file!("sysclk-lwla1034-extneg.rbf", oxrok_firmware!("sysclk-lwla/sysclk-lwla1034-extneg.rbf"), "e1476bd162387bdcd5ff9834da4441a3f918acf43e2adf7502b8066c61a7dcf3", 81_808),
            file!("sysclk-lwla1034-off.rbf", oxrok_firmware!("sysclk-lwla/sysclk-lwla1034-off.rbf"), "58af5e5f136ecaf35607792c24a611796ccd6395cc1a43dd0e23978cf88869b5", 48_521),
        ],
        manual: Some(Manual {
            what: "lwla1034_EN_setup.exe from the CD-ROM that came with the device",
            url: None,
            steps: "Only the 2012-07-12 CD release is known; other releases are refused",
        }),
        note: Some("Redistributed with SysCLK's permission, see LICENSE.LWLA in oxrok-firmware."),
        extract: Some(extract::sysclk::lwla1034),
        known: &[],
    },
    Package {
        id: "sysclk-lwla1016",
        title: "Sysclk LWLA1016 (100 MHz bitstreams)",
        files: &["sysclk-lwla1016-100.rbf", "sysclk-lwla1016-100-ts.rbf"],
        covers: &[],
        downloads: &[
            file!("sysclk-lwla1016-100.rbf", gdrive!("1HkzTxHRyJ3iTfvgbtxhnLnzJLCsgVucb"), "3384da818a849057f07ae307a66071d933546234299c89bd7b8ac8cc6592c2df", 69_334),
            file!("sysclk-lwla1016-100-ts.rbf", gdrive!("1TreRxRevBGVn9zcbCQGX-5gTL37ZZkHM"), "3409ea50563252c80fac991547b71399ed5ce83fe6b7b33de0e4810ffd2ba7c0", 70_588),
        ],
        manual: Some(Manual {
            what: "the folder of an installed LWLA1016 vendor software (it holds bin/lwla1016.dll)",
            url: Some("https://sigrok.org/wiki/Sysclk_LWLA1016"),
            steps: "Install the vendor software on Windows (a virtual machine will do) and copy its folder",
        }),
        note: Some(
            "The downloads are a user's extraction shared from blog.danman.eu, checked against the \
             sigrok wiki's hashes; SysCLK's redistributable LWLA1016 files are buggy (sigrok bug 760).",
        ),
        extract: Some(extract::sysclk::lwla1016),
        known: sha!(
            "sysclk-lwla1016-100.rbf" => "3384da818a849057f07ae307a66071d933546234299c89bd7b8ac8cc6592c2df",
            "sysclk-lwla1016-100-ts.rbf" => "3409ea50563252c80fac991547b71399ed5ce83fe6b7b33de0e4810ffd2ba7c0",
        ),
    },
    Package {
        id: "sysclk-sla5032",
        title: "Sysclk SLA5032",
        files: &["sysclk-sla5032.bit"],
        covers: &[],
        downloads: &[],
        manual: Some(Manual {
            what: "the SLA5032 vendor CD or its ISO (sla5032_2015_1_24.iso), or top.bit from an installed copy",
            url: Some("https://sigrok.org/wiki/Sysclk_SLA5032"),
            steps: "An installed copy keeps it as C:\\Program Files (x86)\\SLA5032\\bin\\top.bit
                Opening an ISO needs unar, 7-Zip or bsdtar",
        }),
        note: None,
        extract: Some(extract::sysclk::sla5032),
        known: &[],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_unpackers() {
        let kingst = package("kingst-la").unwrap();
        // The mirror too: a fetch may contact it.
        assert_eq!(kingst.hosts(), vec!["res.kingst.site", "www.qdkingst.com"]);
        assert!(!kingst.needs_unpacker());
        assert!(package("hantek-dso-5200a").unwrap().needs_unpacker());
        assert_eq!(
            package("dreamsourcelab-dslogic").unwrap().hosts(),
            vec!["raw.githubusercontent.com"]
        );
        assert_eq!(package("lecroy-logicstudio").unwrap().hosts(), Vec::<&str>::new());
    }
}
