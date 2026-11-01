package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Initialize the actual index, merge/data and mask inputs independently of the
// row-byte generator. Every active address is within the caller's data array:
// the indices are zero and the mask is nonzero. Scatter uses the output array.
func x86OfficialVSIBAssembly(cases []x86OfficialPackedCase) (string, string) {
	var source, declarations strings.Builder
	for index := range cases {
		fixture := &cases[index]
		w := fixture.witness
		fixture.symbol = fmt.Sprint("VSIBRow", index)
		prefetch := strings.Contains(w.Instruction, "PF")
		scatter := strings.Contains(w.Instruction, "SCATTER") && !prefetch
		fmt.Fprintf(&declarations, "func %s(out *[80]byte,data,seed *[64]byte)\n", fixture.symbol)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-24\nMOVQ out+0(FP),DX\n", fixture.symbol)
		if !scatter {
			source.WriteString("MOVQ data+8(FP),AX\n")
		}
		source.WriteString("MOVQ seed+16(FP),BX\n")
		if w.Generation == "vex" {
			fmt.Fprintf(&source, "VPXOR Y%s,Y%s,Y%s\n", w.Second[1:], w.Second[1:], w.Second[1:])
			source.WriteString("VPXOR Y1,Y1,Y1\nVPCMPEQD Y1,Y1,Y1\n")
			fmt.Fprintf(&source, "VMOVUPS (BX),Y%s\n", w.Destination[1:])
		} else {
			fmt.Fprintf(&source, "VPXORD Z%s,Z%s,Z%s\n", w.Second[1:], w.Second[1:], w.Second[1:])
			source.WriteString("MOVQ $1,R9\nKMOVQ R9,K1\n")
			if !prefetch {
				fmt.Fprintf(&source, "VMOVUPS (BX),Z%s\n", w.Destination[1:])
			}
		}
		if scatter {
			source.WriteString("MOVQ DX,AX\n")
		}
		fixture.line = strings.Count(source.String(), "\n") + 1
		fmt.Fprintln(&source, w.Instruction)
		if !prefetch && !scatter {
			carrier := "Z"
			if w.Generation == "vex" {
				carrier = "Y"
			}
			fmt.Fprintf(&source, "VMOVUPS %s%s,(DX)\n", carrier, w.Destination[1:])
		}
		if w.Generation == "evex" {
			source.WriteString("KMOVQ K1,64(DX)\n")
		} else {
			source.WriteString("VMOVUPS Y1,32(DX)\n")
		}
		source.WriteString("RET\n")
	}
	return source.String(), declarations.String()
}

func TestX86OfficialVSIBRowsInitializedThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	x86OfficialPackedRowsObjectsInspect(t, goasmrules.X86IndexedMemoryRows, 80, 320, 0,
		x86OfficialVSIBAssembly, func(t *testing.T, ir string, _ []x86OfficialPackedCase) {
			x86PackedStringCompileObject(t, llc, "x86_64-unknown-linux-gnu", ir, "-O2")
		})
}

func TestX86VSIBInitializedSourceRequiresActualInputs(t *testing.T) {
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86IndexedMemoryRows(goasmrules.X86LegacyCatalog{}, avx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Opcode != "VGATHERDPS" && row.Opcode != "VPSCATTERDD" {
			continue
		}
		// One complete representative per VEX/EVEX and gather/scatter role.
		if !strings.HasSuffix(row.ID, "/0") && !strings.HasSuffix(row.ID, "/2") {
			continue
		}
		w := row.Witnesses[0]
		cases := []x86OfficialPackedCase{{row: row.ID, witness: w}}
		source, declarations := x86OfficialVSIBAssembly(cases)
		inputs := []string{"MOVQ data+8(FP),AX\n"}
		if row.Opcode == "VPSCATTERDD" {
			inputs = []string{"MOVQ DX,AX\n"}
		}
		if w.Generation == "vex" {
			inputs = append(inputs, "VPXOR Y0,Y0,Y0\n", "VPXOR Y1,Y1,Y1\nVPCMPEQD Y1,Y1,Y1\n")
		} else {
			inputs = append(inputs, "VPXORD Z16,Z16,Z16\n", "KMOVQ R9,K1\n", "VMOVUPS (BX),Z18\n")
		}
		t.Run(row.ID, func(t *testing.T) {
			for _, api := range []string{"text", "module", "Go"} {
				if _, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
					t.Fatal("complete initialized source must precede input mutation", api, err)
				}
				for _, removed := range inputs {
					if strings.Count(source, removed) != 1 {
						t.Fatal("input mutation does not own one exact initializer", removed)
					}
					changed := strings.Replace(source, removed, "", 1)
					if _, err := x86ScalarFPBitViewAPI(t, changed, declarations, "amd64", "x86_64-unknown-linux-gnu", api); err == nil {
						t.Fatal("missing actual indexed-memory input was accepted", api, removed)
					}
				}
			}
		})
	}
}
