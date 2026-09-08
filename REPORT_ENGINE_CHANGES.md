# Analyst-oriented report engine changes

The Binwalk, Firmwalker-lite, and Checksec-lite analysis engines are unchanged by this revision. Only the reporting/correlation layer was replaced.

## New pipeline

1. `normalize_evidence.sh` — converts raw Firmwalker/Checksec output into neutral evidence. Checksec flags are stored as one hardening profile per ELF and are not promoted directly to vulnerabilities.
2. `build_asset_context.sh` — classifies assets (web server, SSH server, PPP service, library, kernel module, etc.), captures file mode/ownership, and looks for static startup/config references.
3. `correlate_cases.sh` — creates security cases only when evidence combinations satisfy explicit rules. It also generates systemic and informational findings.
4. `render_report.sh` — creates an analyst-oriented report ordered by priority with Why this matters, Attack scenario, Potential impact, Evidence chain, Confidence, and Recommended remediation.

## Important behavior changes

- `No Canary`, `PIE Disabled`, and `Partial RELRO` alone are evidence, not vulnerabilities.
- Network-service role + multiple hardening weaknesses can create a security case.
- `.ko` hardening results are informational and do not flood the main findings.
- Shared libraries do not independently generate ordinary hardening cases.
- Repeated hardening patterns across userspace binaries are summarized as a firmware-wide build-policy finding.
- Unix-MD5 password hashes produce a high-confidence credential-storage case.
- Sensitive key material is escalated only when filesystem permissions are broadly readable.
- Command/exec strings in web content are reported only as low-confidence review cases unless stronger source-to-sink evidence exists.
