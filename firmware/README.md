# oxrok-firmware-fetch

Many logic analysers and oscilloscopes run firmware (FX2 code, FPGA
bitstreams) that their vendors never released on its own, and whose terms
do not allow redistributing it. This crate gets that firmware onto the
user's machine the way sigrok-util's `sigrok-fwextract-*` scripts did, which
it replaces:

- a **registry** of every firmware file oxrok's drivers load, grouped in
  packages, each with pinned downloads (URLs, size, SHA-256) or, when only
  the user can get the files (a vendor login, the device's CD, an installed
  copy), instructions saying where to find them;
- **extractors**, Rust ports of the scripts, that read the vendor software
  the downloads or the user's files contain;
- `fetch` (download, verify, extract, install) and `import` (the same from
  installers, archives, folders or the firmware files the user has).

No firmware is in this repository: only names, hashes and code.

| Package | Source | Extractor |
|---|---|---|
| `dreamsourcelab-dslogic` | DSView 0.97 resources on GitHub | none (the files as they are) |
| `fx2lafw` | sigrok's fx2lafw 0.1.7 binary release | none |
| `fx2lafw-git` | build fx2lafw from git (no release ships these) | none |
| `asix-sigma`, `sysclk-lwla1034` | oxrok-firmware (redistributable) | LWLA1034 also from the CD's installer |
| `kingst-la` | KingstVIS 3.6.6 | Qt resources, by symbol or by structure (stripped, macOS, Windows builds) |
| `saleae-logic` | Saleae Logic 1.2.10 for Linux | ELF dynamic symbols |
| `intronix-logicport` | LogicPort installer, build 2371 | Deflate64 entry of the installer |
| `hantek-dso-*` | Hantek's driver packages (DSO-2090, 2150, 2250, 5200, 5200A) | COFF symbol of the 32-bit loader driver |
| `lecroy-logicstudio` | the user (Teledyne LeCroy account) | `LS16Lib.dll`, Cypress `.spt` loader script |
| `sysclk-lwla1016` | 100 MHz bitstreams shared by a user, checked against the sigrok wiki | installed `lwla1016.dll` |
| `sysclk-sla5032` | the user (vendor CD or ISO) | `top.bit` |

Zip (Deflate64 too) and tar.gz are read natively. RAR, 7z, ISO, CAB, MSI
and installer executables go through `unar`, 7-Zip or `bsdtar` when one is
installed. Nothing found in an input is ever run.

## Use

The front end is oxrok's `oxrok firmware list|fetch|import|info`. To try
the crate on its own:

```text
cargo run --example fwfetch -- list
cargo run --example fwfetch -- fetch kingst-la /tmp/fw
cargo run --example fwfetch -- import lecroy-logicstudio /tmp/fw LogicStudio_x64.zip
```

Without the default `download` feature the registry, the extractors and
`import` still work, with no HTTP or TLS code.

## Tests

`cargo test` runs the unit tests on synthetic input. The network test
fetches every downloadable package (about 100 MB) and checks every
extracted file against the hashes the original scripts produced:

```text
OXROK_FIRMWARE_FETCH_CACHE=~/.cache/oxrok-firmware cargo test --test network -- --ignored
```

## License

GPL-3.0-or-later, as the scripts it ports.
