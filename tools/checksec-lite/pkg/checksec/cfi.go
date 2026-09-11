package checksec

import (
	"debug/elf"
	"strings"
)

var cfiMarkers = []string{
	"__cfi_check",
	"__cfi_slowpath",
	"__cfi_slowpath_diag",
	"__cfi_check_fail",
	"__ubsan_handle_cfi_check_fail",
}

func isCFIMarker(name string) bool {
	for _, marker := range cfiMarkers {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

// CFI performs a conservative symbol-based check for Clang/LLVM CFI markers.
// ELF has no universal CFI bit, so absence is reported as Not Detected rather
// than as a confirmed vulnerability.
func CFI(file *elf.File) *Result {
	if file == nil {
		return &Result{Value: "Unknown", Status: StatusNA}
	}

	if symbols, err := file.Symbols(); err == nil {
		for _, s := range symbols {
			if isCFIMarker(s.Name) {
				return &Result{Value: "CFI Detected", Status: StatusGood}
			}
		}
	}
	if symbols, err := file.DynamicSymbols(); err == nil {
		for _, s := range symbols {
			if isCFIMarker(s.Name) {
				return &Result{Value: "CFI Detected", Status: StatusGood}
			}
		}
	}

	return &Result{Value: "CFI Not Detected", Status: StatusInfo}
}
