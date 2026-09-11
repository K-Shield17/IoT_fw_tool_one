# IoT_fw_tool — slim integrated build

IoT firmware static-analysis pipeline built by **selecting only the required functionality from the three supplied upstream tools**, rather than vendoring each complete project.

## Pipeline

`Firmware -> Binwalk-lite temporary extraction -> RootFS -> targeted Firmwalker-lite + selected ELF Checksec-lite -> normalized findings -> risk correlation -> JSON/HTML report -> delete extracted/raw working data`

## Selected upstream functionality

### Binwalk 3.1.0 (Rust)
Kept only the signature/extraction path needed for common embedded Linux firmware: gzip/xz/tar/squashfs/lzma/bzip2/uImage/cpio/Linux kernel/zstd/zip/JFFS2/ROMFS/UBI/YAFFS/CRAMFS/ext/FAT/MBR/TP-Link/TRX/SEAMA/Realtek/zlib. The original parser/extractor/structure source files for these formats are copied unchanged. Removed entropy graphing, stdin, carve-only mode, generic listing/display CLI, unrelated signatures and extractors. The small `main.rs` only performs scan + extraction + recursive extraction.

### Firmwalker (Bash)
The scanner is now intentionally **targeted rather than exhaustive**. It searches high-value configuration, credential, key/certificate, web/API, service-startup, firmware-update and state/data paths such as `/etc`, `/var`, `/root`, `/home`, `/www`, `/htdocs`, `/cgi-bin`, plus executable paths such as `/bin`, `/sbin`, `/usr/bin` and `/usr/sbin`. It collects evidence useful for OWASP IoT Top 10 mapping while still retaining additional preventive indicators such as component/version hints, URLs/IPs, crypto use and binary/service presence. Large library trees and unrelated extracted files are not repeatedly scanned.

### Checksec 3.2.0 (Go)
Static ELF analysis keeps RELRO, Canary, NX, PIE, RPATH, RUNPATH and FORTIFY and adds **Separate Code**, **CFI** and **Stack Clash Protection** indicators. Checksec is no longer run against every file in the root filesystem; it is limited to executable-heavy and externally exposed paths (`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`, and CGI directories). CFI is a conservative marker-based observation. Stack Clash protection has no universal ELF metadata bit, so the scanner reports a positive result only when an explicit probe marker is visible and otherwise returns `Unknown` rather than claiming the protection is absent.

## Build

Requirements: Rust/Cargo, Go 1.25+, `jq`, `file`, plus system utilities required by the retained Binwalk extractors (for example `unsquashfs`, `7z`, `tsk_recover` (Sleuth Kit), `ubireader_extract_files`, depending on firmware format).

```bash
chmod +x build.sh run.sh setup/*.sh tools/firmwalker-lite/firmwalker-lite.sh
./build.sh
```

### MBR/FAT recursive extraction

The retained Binwalk path now includes the upstream MBR and FAT signature/parser chain. MBR partitions are carved with the upstream internal MBR extractor, then recursively rescanned. FAT/ext filesystems are recovered with the retained `tsk_recover` extractor. This restores the extraction path needed for disk-style firmware images such as `MBR -> FAT32 partition -> boot files` while preserving the existing SquashFS extraction path.

## Run

```bash
./run.sh scan firmware.bin -o results
```

For an already extracted filesystem:

```bash
./run.sh analyze-rootfs ./rootfs -o results
```

`-o` is the **parent output directory**. Each input gets its own result directory, so later analyses do not overwrite earlier ones.

Example: analyzing `firmware.bin` with `-o results` creates `results/firmware/`. If that name already exists, the next run is saved as `results/firmware_2/`, then `results/firmware_3/`, and so on.

Final outputs are stored under the per-input directory: `results/firmware/report.json` and `results/firmware/report.html`. Binwalk extraction directories and raw/intermediate analyzer files are temporary working data and are removed automatically when the run exits.

## Automatic dependency setup

`run.sh` now performs a preflight before analysis. On Ubuntu/AttifyOS it:

- checks required OS tools and installs missing `apt` packages;
- installs Rust + Cargo with `rustup` only when they are absent;
- installs Go when absent and enables Go toolchain auto-selection;
- creates a project-local Python virtual environment **only for upstream Binwalk extractor utilities** (`jefferson`, `ubi-reader`, `vmlinux-to-elf`); the IoT_fw_tool analysis/report code itself is not Python;
- provides a project-local `sasquatch` compatibility command backed by modern `unsquashfs`, avoiding the common legacy-sasquatch GCC build failure for standard SquashFS images;
- resolves firmware paths to absolute paths before Binwalk starts;
- automatically builds Binwalk-lite/Checksec-lite when binaries are missing.

Normal use on a fresh Ubuntu/AttifyOS machine is therefore simply:

```bash
chmod +x build.sh run.sh setup/*.sh tools/firmwalker-lite/firmwalker-lite.sh
./run.sh scan /absolute/or/relative/path/to/firmware.bin -o results
```

The first run may ask for the `sudo` password while installing missing Ubuntu packages. Later runs reuse everything already installed.

To inspect the current environment without starting an analysis:

```bash
./setup/check_environment.sh
```

### SquashFS note

Binwalk 3.1.0's upstream SquashFS extractor invokes `sasquatch`. The legacy sasquatch source frequently fails to compile with modern GCC. This package therefore installs a local compatibility wrapper that invokes the distribution's maintained `unsquashfs` for standard SquashFS. Vendor-modified SquashFS images that genuinely require patched sasquatch may still require a dedicated extractor; this is reported as an extraction limitation rather than a missing-command crash.

## Analyst-oriented report engine

The current report engine separates raw tool observations from security conclusions:

```text
Binwalk / Firmwalker / Checksec
        ↓
Raw evidence
        ↓
Asset context
        ↓
Evidence correlation
        ↓
Security cases
        ↓
Analyst-oriented HTML/JSON report
```

A missing Canary, disabled PIE, or Partial RELRO is no longer reported as a standalone confirmed vulnerability. The report prioritizes correlated cases such as network-service exposure plus multiple hardening weaknesses, weak password hashes, or broadly readable key material. Kernel modules and ordinary shared-library hardening observations remain available in the evidence appendix without flooding the main findings.

During analysis, intermediate evidence is generated under `results/<target>/raw/` and Binwalk extraction data under `results/<target>/extracted/`. These are working artifacts only and are deleted automatically after report generation (and also on early exit).

The persistent final outputs are:

- `results/<target>/report.json`
- `results/<target>/report.html`
