package main

import (
	"debug/elf"
	"encoding/json"
	"fmt"
	"github.com/slimm609/checksec/v3/pkg/checksec"
	"os"
)

type output struct {
	File         string            `json:"file"`
	RELRO        *checksec.Result  `json:"relro"`
	Canary       *checksec.Result  `json:"canary"`
	NX           *checksec.Result  `json:"nx"`
	PIE          *checksec.Result  `json:"pie"`
	RPATH        *checksec.Result  `json:"rpath"`
	RUNPATH      *checksec.Result  `json:"runpath"`
	Fortify      map[string]string `json:"fortify"`
	SeparateCode *checksec.Result  `json:"separate_code"`
	StackClash   *checksec.Result  `json:"stack_clash"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: checksec-lite <ELF>")
		os.Exit(2)
	}
	name := os.Args[1]
	raw, err := os.Open(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer raw.Close()
	ef, err := elf.NewFile(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	f := map[string]string{"output": "N/A", "fortified": "0", "fortifiable": "0", "libc_support": "N/A"}
	if fr, ferr := checksec.Fortify(name, ef, ""); ferr == nil {
		f["output"] = fr.Output
		f["fortified"] = fr.Fortified
		f["fortifiable"] = fr.Fortifiable
		f["libc_support"] = fr.LibcSupport
	}
	r := output{
		File:         name,
		RELRO:        checksec.RELRO(ef),
		Canary:       checksec.Canary(ef, raw),
		NX:           checksec.NX(ef),
		PIE:          checksec.PIE(ef),
		RPATH:        checksec.RPATH(ef),
		RUNPATH:      checksec.RUNPATH(ef),
		Fortify:      f,
		SeparateCode: checksec.SeparateCode(ef),
		StackClash:   checksec.StackClash(ef),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		os.Exit(1)
	}
}
