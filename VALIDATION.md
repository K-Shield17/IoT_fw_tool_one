# Validation notes

## Source reduction

- Binwalk 3.1.0: upstream `src/` contained 186 Rust files; this build contains 69 Rust source files, including the new minimal CLI/registries. Retained parser/extractor/structure implementation files were compared byte-for-byte against the uploaded archive.
- Checksec 3.2.0: upstream archive contained 81 Go files; this build contains 11 Go files. The 9 selected `pkg/checksec` implementation files and `pkg/output/output.go` were compared byte-for-byte against the uploaded archive.
- Firmwalker: the uploaded original script is preserved as `firmwalker.original.sh`; `firmwalker-lite.sh` keeps only the project-relevant search sections and uses the uploaded rule files.

## Runtime validation performed here

- All Bash scripts pass `bash -n`.
- Firmwalker-lite was executed against a synthetic RootFS and detected password/shadow material, private keys, sensitive credential patterns, web-server binaries, IPs, and URLs.
- Report normalization/correlation was executed with synthetic Firmwalker findings and a Checksec-compatible JSON result; `report.json` and `report.html` were generated successfully.

## Build limitation of this environment

This execution environment does not provide Rust/Cargo, so the reduced Binwalk Rust crate could not be compiled here. The available Go compiler is 1.23.2 while the supplied Checksec 3.2.0 source declares Go 1.25.0, so the final Checksec-lite binary also could not be built here. The project intentionally retains that upstream Go requirement rather than rewriting the original Checksec implementation to satisfy an older compiler.
