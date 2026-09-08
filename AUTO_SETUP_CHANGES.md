# Automatic setup / reliability changes

This revision adds a preflight/bootstrap layer without replacing the selected upstream analysis logic.

## Added

- `scripts/bootstrap.sh`
  - installs missing Ubuntu packages with `apt`;
  - installs Rust/Cargo with rustup only when absent;
  - installs Go when absent;
  - creates `.deps/venv` for upstream Binwalk Python-based extractors only;
  - installs Jefferson, ubi-reader and vmlinux-to-elf in that isolated environment;
  - exposes extractor commands through project-local `tools/bin`;
  - creates a `sasquatch` compatibility wrapper backed by `unsquashfs` when real sasquatch is absent;
  - validates essential commands after setup.

- `scripts/check_environment.sh`
  - displays which compiler/extractor commands are currently available and their resolved paths.

## Changed

- `run.sh`
  - resolves input/output paths before running;
  - runs automatic dependency setup;
  - builds analyzers automatically if binaries are missing;
  - safely clears only prior generated files under the selected output directory;
  - captures Binwalk stderr separately;
  - attempts to continue if Binwalk reports a partial extractor failure but a usable RootFS was produced.

- `build.sh`
  - performs dependency bootstrap automatically;
  - runs `go mod tidy` before Checksec-lite compilation;
  - enables Go toolchain auto-selection.

- Binwalk-lite `main.rs`
  - corrected error formatting for the retained Binwalk error type (`{:?}`), matching the compile fix verified during integration testing.

## Why the sasquatch compatibility wrapper exists

The selected Binwalk 3.1.0 SquashFS extractor calls `sasquatch`, but the old sasquatch fork commonly fails on modern GCC because its legacy source treats newer compiler diagnostics as errors. For standard SquashFS, modern `unsquashfs` is sufficient and much more reliable. The wrapper preserves the command name expected by upstream Binwalk while delegating extraction to `unsquashfs`.

This does not guarantee extraction of every vendor-modified SquashFS variant. Such firmware may still need a patched vendor-specific sasquatch build.
