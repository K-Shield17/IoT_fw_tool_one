# Source selection map

This file records what was retained from the three user-supplied source archives.

## Binwalk 3.1.0

Unchanged core files: `src/binwalk.rs`, `src/common.rs`, `src/lib.rs`. Selected signature, extractor and structure implementation files are copied byte-for-byte from the uploaded Binwalk 3.1.0 archive. `magic.rs`, `signatures.rs`, `extractors.rs`, `structures.rs` are reduced registries containing only retained formats. `main.rs` is new integration CLI code because the upstream CLI exposes many options that this project intentionally removes.

Retained formats: gzip, xz, tarball, squashfs, lzma, bzip2, uImage, cpio, Linux kernel/boot image, zstd, zip, JFFS2, ROMFS, UBI, YAFFS, CRAMFS, ext, **MBR, FAT**, TP-Link, TRX, SEAMA, Realtek, zlib. MBR uses the upstream internal partition-carving extractor; FAT uses the retained upstream TSK extractor (`tsk_recover`) and is recursively rescanned by the project CLI.

## Firmwalker

`firmwalker.original.sh` is the supplied source unchanged. `firmwalker-lite.sh` keeps the original `find`/`grep`-based search approach but only executes project-relevant categories. All retained rule lists come directly from the supplied `data/*.txt`. Shodan was removed because this project is an offline static firmware analyzer. Email enumeration and generic shell/bin inventories were removed as low-value report noise.

## Checksec 3.2.0

The following files are copied unchanged from the supplied source: `canary.go`, `nx.go`, `pie.go`, `relro.go`, `rpath.go`, `runpath.go`, `fortify.go`, `symbols.go`, `result.go`, and `pkg/output/output.go`. A new minimal `main.go` invokes only those checks on a single ELF file and emits JSON. Process/kernel/seccomp/system checks and the Cobra CLI are not included.

## New project-specific code

`run.sh`, `setup/find_rootfs.sh`, `setup/run_checksec.sh`, and `setup/build_report.sh` connect the retained engines, normalize findings, correlate multiple missing mitigations, and generate reports.

## Checksec-lite output cleanup

- `pkg/output/output.go` removed: terminal banner/color helpers were not needed by the integrated JSON/report pipeline.
- Warning calls used by symbol/Fortify parsing now write directly to stderr.
