package checksec

import (
	"debug/elf"
	"strings"
)

// There is no standard ELF metadata bit for GCC/Clang stack-clash protection.
// These symbols are only strong hints that explicit stack probing/checking is
// present. Most GCC -fstack-clash-protection builds use inline probe sequences,
// which cannot be reliably identified from ELF metadata alone.
var stackProbeMarkers = []string{
	"__probe_stack",
	"__stack_probe",
	"__chkstk",
	"___chkstk_ms",
	"__alloca_probe",
}

func hasStackProbeMarker(name string) bool {
	for _, marker := range stackProbeMarkers {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

// StackClash returns Detected only when an explicit stack-probe marker is
// visible. Otherwise it reports Unknown instead of claiming the protection is
// absent, because reliable detection requires architecture-specific
// disassembly of compiler-generated probe sequences.
func StackClash(file *elf.File) *Result {
	if file == nil {
		return &Result{Value: "Unknown", Status: StatusNA}
	}

	if symbols, err := file.Symbols(); err == nil {
		for _, s := range symbols {
			if hasStackProbeMarker(s.Name) {
				return &Result{Value: "Stack Clash Protection Detected", Status: StatusGood}
			}
		}
	}
	if symbols, err := file.DynamicSymbols(); err == nil {
		for _, s := range symbols {
			if hasStackProbeMarker(s.Name) {
				return &Result{Value: "Stack Clash Protection Detected", Status: StatusGood}
			}
		}
	}

	return &Result{Value: "Unknown (no ELF marker)", Status: StatusInfo}
}
