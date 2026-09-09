# Output isolation and build-warning cleanup

## 1. Binwalk-lite build warning
The project-local Binwalk-lite inherits an enum that contains an internal function pointer. Rust can emit `unpredictable_function_pointer_comparisons` from the derived comparison traits. The project does not use that function-pointer comparison as a security decision, so the lint is suppressed only on `ExtractorType` instead of globally suppressing compiler warnings.

## 2. Per-target result directories
`run.sh` now treats `-o` as a parent output directory. Each analyzed target receives its own subdirectory based on the input filename. Existing results are never deleted or overwritten.

Examples:
- `firmware.bin` -> `results/firmware/`
- another target `router_v2.ins` -> `results/router_v2/`
- re-running `firmware.bin` -> `results/firmware_2/` (then `firmware_3/`, `firmware_4/`, ...)

Each target directory contains its own `extracted/`, `raw/`, `report.json`, and `report.html`.
