package checksec

import "debug/elf"

// SeparateCode checks whether executable and writable PT_LOAD segments are
// separated and whether any loadable segment is simultaneously writable and
// executable (W+X). This is a lightweight ELF-level approximation of the
// "separate-code" hardening property used by checksec-style tools.
func SeparateCode(file *elf.File) *Result {
	if file == nil {
		return &Result{Value: "Unknown", Status: StatusNA}
	}
	if len(file.Progs) == 0 {
		return &Result{Value: "N/A", Status: StatusNA}
	}

	hasExec := false
	hasWrite := false
	for _, p := range file.Progs {
		if p == nil || p.Type != elf.PT_LOAD {
			continue
		}
		exec := p.Flags&elf.PF_X != 0
		write := p.Flags&elf.PF_W != 0
		if exec {
			hasExec = true
		}
		if write {
			hasWrite = true
		}
		if exec && write {
			return &Result{Value: "Not Separate (W+X LOAD)", Status: StatusBad}
		}
	}

	if hasExec && hasWrite {
		return &Result{Value: "Separate Code", Status: StatusGood}
	}
	return &Result{Value: "Unknown", Status: StatusNA}
}
