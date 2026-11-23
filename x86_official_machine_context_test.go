package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86OfficialMachineContextObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	const encoder, extra = "amd64enc.s", "amd64enc_extra.s"
	const address = "MOVQ address+0(FP),BX\nMOVQ address+0(FP),R11\n"
	const value = "MOVQ value+0(FP),DX\nMOVQ value+0(FP),DI\nMOVQ value+0(FP),R11\n"
	for _, family := range []struct {
		name, file, pattern string
		args, declaration   string
		prefix, result      string
		count               int
	}{
		{"descriptors", encoder, `(?:LGDT \(R11\)|(?:LIDT|SGDT|SIDT) \((?:BX|R11)\))`,
			"8", "(address *[10]byte)", address, "", 7},
		{"cache-flush", encoder, `CLFLUSH(?:OPT)? \((?:BX|R11)\)`,
			"8", "(address *[10]byte)", address, "", 4},
		{"cache-writeback", extra, `CLWB \(BX\)`,
			"8", "(address *[10]byte)", address, "", 1},
		{"control-debug", encoder, `MOVQ (?:DX|R11),\s*(?:CR[23]|DR[23])`,
			"8", "(value uint64)", value, "", 8},
		{"control-extra", extra, `MOVQ (?:DX,\s*CR0|DI,\s*CR4)`,
			"8", "(value uint64)", value, "", 2},
		{"wait", extra, `(?:TPAUSE|UMWAIT) BX`,
			"0", "()", "XORL AX,AX\nXORL DX,DX\nXORL BX,BX\n", "", 2},
		{"x87-round", encoder, `FRNDINT`,
			"16", "(input float64) float64", "FINIT\nFMOVD input+0(FP),F0\n", "FMOVDP F0,ret+8(FP)\n", 1},
	} {
		t.Run(family.name, func(t *testing.T) {
			rows := x86OfficialAMD64EncodingRows(t, family.file, family.pattern)
			if len(rows) != family.count {
				t.Fatalf("found %d original rows, want %d", len(rows), family.count)
			}
			var source, declarations strings.Builder
			var witnesses []x86OfficialPackedCase
			line := 0
			for index, row := range rows {
				symbol := fmt.Sprintf("Machine%d", index)
				prefix := fmt.Sprintf("TEXT ·%s(SB),4,$0-%s\n%s", symbol, family.args, family.prefix)
				body := prefix + row.instruction + "\n" + family.result + "RET\n"
				source.WriteString(body)
				fmt.Fprintf(&declarations, "func %s%s\n", symbol, family.declaration)
				witnesses = append(witnesses, x86OfficialPackedCase{
					row: row.location, symbol: symbol, line: line + strings.Count(prefix, "\n") + 1,
					witness: goasmrules.X86PackedBinaryWitness{Instruction: row.instruction, Encoding: row.code},
				})
				line += strings.Count(body, "\n")
			}
			// Privileged instruction rows are assembled and lowered into objects.
			requireX86OfficialAMD64Objects(t, llc, source.String(), declarations.String(), witnesses)
		})
	}
}
