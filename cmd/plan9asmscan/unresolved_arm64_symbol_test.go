package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestScanPackagesRetainsUnresolvedARM64SymbolAddendsAndLaterInstructions(t *testing.T) {
	var rows []string
	for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
		rows = append(rows, op+" ·memory+OFFSET(SB),R2", op+" R2,·memory-OFFSET(SB)")
	}
	rows = append(rows, "MOVD $·memory+(OFFSET+4)(SB),R2",
		"MOVWU $·memory-OFFSET(SB),R2",
		"MOVBU internal∕cpu·ARM64+const_offsetARM64HasATOMICS(SB),R4")
	source := "TEXT one(SB),$0-0\n" + strings.Join(rows, "\n") + "\nADD $7,R2\nRET\n"
	directory := t.TempDir()
	input := filepath.Join(directory, "one.s")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ops, forms, parseErrors, packages, files, err := scanPackages([]pkgJSON{{
		ImportPath: "example.invalid/layout", Dir: directory, SFiles: []string{"one.s"},
	}}, plan9asm.ArchARM64, "arm64", runtime.GOROOT())
	if err != nil || len(parseErrors) != 0 || packages != 1 || files != 1 {
		t.Fatalf("source inventory was lost: error=%v parse=%v packages=%d files=%d", err, parseErrors, packages, files)
	}
	if ops["ADD"] == nil || ops["ADD"].Count != 1 || ops["RET"] == nil || ops["RET"].Count != 1 {
		t.Fatal("an unresolved symbol addend suppressed later instructions")
	}
	contexts := 0
	for _, form := range forms {
		if !strings.HasPrefix(form.Descriptor.Opcode, "MOV") {
			continue
		}
		contexts += form.ContextCount
		if form.SupportedCount != 0 || form.UnsupportedCount != 0 || len(form.Errors) != 0 {
			t.Errorf("unresolved symbol was invented as supported or rejected as an instruction: %+v", form)
		}
	}
	if contexts != len(rows) {
		t.Errorf("retained %d contexts; want every one of %d original operands", contexts, len(rows))
	}
	retained, err := os.ReadFile(input)
	if err != nil || string(retained) != source {
		t.Fatal("scanning changed the original generated-constant source", err)
	}
}
