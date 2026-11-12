package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestScanPackagesRetainsUnresolvedFPSymbolOffsetsAndLaterInstructions(t *testing.T) {
	for _, target := range []struct {
		arch   plan9asm.Arch
		goarch string
		ops    []string
	}{
		{plan9asm.ArchARM, "arm", []string{"MOVF", "MOVD"}},
		{plan9asm.ArchARM64, "arm64", []string{"FMOVS", "FMOVD", "FMOVQ"}},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			var rows []string
			for _, op := range target.ops {
				rows = append(rows, op+" ·memory+OFFSET(SB),F0", op+" F0,·memory+OFFSET(SB)")
			}
			source := "TEXT probe(SB),$0-0\n" + strings.Join(rows, "\n") + "\nADD $7,R2\nRET\n"
			directory := t.TempDir()
			if err := os.WriteFile(filepath.Join(directory, "probe.s"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			ops, forms, parseErrors, packages, files, err := scanPackages([]pkgJSON{{
				ImportPath: "example.invalid/fplayout", Dir: directory, SFiles: []string{"probe.s"},
			}}, target.arch, target.goarch, runtime.GOROOT())
			if err != nil || len(parseErrors) != 0 || packages != 1 || files != 1 {
				t.Fatalf("FP source inventory was lost: error=%v parse=%v packages=%d files=%d", err, parseErrors, packages, files)
			}
			if ops["ADD"] == nil || ops["RET"] == nil {
				t.Fatal("an unresolved FP symbol suppressed later inventory")
			}
			contexts := 0
			for _, op := range target.ops {
				if ops[op] == nil || ops[op].Count != 2 {
					t.Errorf("FP load/store rows were not retained: %s", op)
				}
				for _, form := range forms {
					if form.Descriptor.Opcode != op {
						continue
					}
					contexts += form.ContextCount
					if form.SupportedCount != 0 || form.UnsupportedCount != 0 || len(form.Errors) != 0 {
						t.Errorf("FP generated offset was guessed or rejected as unsupported: %+v", form)
					}
				}
			}
			if contexts != len(rows) {
				t.Errorf("retained %d contextual operands; want %d", contexts, len(rows))
			}
		})
	}
}
