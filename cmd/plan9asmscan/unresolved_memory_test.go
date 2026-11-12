package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestScanPackagesRetainsUnresolvedX86MemoryAndLaterInstructions(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			dir := t.TempDir()
			source := "TEXT one(SB),4,$0-0\nMOVL g_stackguard0(BP),BX\nMOVL g(CX),CX\n" +
				"CMPB internal∕cpu·X86+const_offsetX86HasERMS(SB),$1\nADDL $7,BX\nRET\n"
			if err := os.WriteFile(filepath.Join(dir, "one.s"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			ops, forms, parseErrs, packages, files, err := scanPackages([]pkgJSON{{
				ImportPath: "example.invalid/source", Dir: dir, SFiles: []string{"one.s"},
			}}, plan9asm.ArchAMD64, arch, runtime.GOROOT())
			if err != nil || len(parseErrs) != 0 || packages != 1 || files != 1 {
				t.Fatalf("source was lost: err=%v parse=%v packages=%d files=%d", err, parseErrs, packages, files)
			}
			if ops["MOVL"] == nil || ops["MOVL"].Count != 2 || ops["ADDL"] == nil || ops["RET"] == nil {
				t.Fatal("unresolved memory suppressed later instruction inventory")
			}
			var contextual int
			for _, form := range forms {
				if form.Descriptor.Opcode != "MOVL" && form.Descriptor.Opcode != "CMPB" {
					continue
				}
				contextual += form.ContextCount
				if form.SupportedCount != 0 || form.UnsupportedCount != 0 {
					t.Fatalf("unresolved memory was not exclusively contextual: %#v", form)
				}
			}
			if contextual != 3 {
				t.Fatalf("retained %d contextual probes, want all three exact source operands", contextual)
			}
		})
	}
}
