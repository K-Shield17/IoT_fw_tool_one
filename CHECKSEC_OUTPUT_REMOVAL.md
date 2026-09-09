# Checksec-lite output package removal

The upstream-derived `pkg/output/output.go` file was removed because the integrated tool does not use Checksec's terminal logo or color formatting.

Changes:
- Removed `tools/checksec-lite/pkg/output/output.go` and the `pkg/output` package.
- Replaced `output.Warnf(...)` calls in `symbols.go` and `fortify.go` with direct `fmt.Fprintf(os.Stderr, ...)` warnings.
- Removed the direct `github.com/fatih/color` dependency from `go.mod` and its color-only checksum entries from `go.sum`.
- Updated the stale `output.ColorPrinter` comment in `result.go`.

The security checks themselves (Canary, NX, PIE, RELRO, Fortify, RPATH, RUNPATH) are unchanged.
