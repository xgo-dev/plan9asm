package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

// ABIInternal requires the hidden g value in R14; ABI0 does not. This checks
// byte-definedness only: it grants no native register entry, g, memory or
// caller continuation permission, and every GP entry mask remains empty.
func TestX86ABI0ResultInitializationR14ActualSourceRoles(t *testing.T) {
	for _, row := range []struct{ typ, move, register string }{
		{"uint8", "MOVB", "R14B"}, {"uint16", "MOVW", "R14"},
		{"uint32", "MOVL", "R14"}, {"uint64", "MOVQ", "R14"},
	} {
		t.Run(row.move, func(t *testing.T) {
			body := fmt.Sprintf("MOVQ $0x1122334455667788,R14\n%s %s,AX\n%s AX,ret0+0(FP)\nRET", row.move, row.register, row.move)
			_, file, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value() "+row.typ, body)
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64"); err != nil {
				t.Fatalf("source-defined ABI0 scratch byte rejected as hidden g: %v", err)
			}
			unknown := fmt.Sprintf("%s %s,AX\n%s AX,ret0+0(FP)\nRET", row.move, row.register, row.move)
			_, emptyFile, emptySig, emptySource := x86ResultInitializationFixture(t, "amd64", "func Value() "+row.typ, unknown)
			goAssemblerOracleOutput(t, "amd64", emptySource, "", true)
			if err := CheckX86ABI0ResultInitialization(emptyFile.Funcs[0], emptySig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("undefined ABI0 R14 acquired an entry value")
			}
			internal := file.Funcs[0]
			internal.Sym += "<ABIInternal>"
			if err := CheckX86ABI0ResultInitialization(internal, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("ABIInternal was treated as ordinary numeric ABI0")
			}
		})
	}
}
