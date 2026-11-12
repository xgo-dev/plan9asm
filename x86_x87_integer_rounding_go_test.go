package plan9asm

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestX86X87IntegerRoundingCompleteGoRowsAndBytes(t *testing.T) {
	table, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		"var yfmvf = []ytab{\n\t{Zm_o, 2, argList{Ym, Yf0}},\n\t{Zo_m, 2, argList{Yf0, Ym}},\n}",
		"var yfmvx = []ytab{\n\t{Zm_o, 2, argList{Ym, Yf0}},\n}",
		"var yfmvp = []ytab{\n\t{Zo_m, 2, argList{Yf0, Ym}},\n}",
		"var ynone = []ytab{\n\t{Zlit, 1, argList{}},\n}",
		"{AFMOVW, yfmvf, Px, opBytes{0xdf, 00, 0xdf, 02}}",
		"{AFMOVWP, yfmvp, Px, opBytes{0xdf, 03}}",
		"{AFMOVL, yfmvf, Px, opBytes{0xdb, 00, 0xdb, 02}}",
		"{AFMOVLP, yfmvp, Px, opBytes{0xdb, 03}}",
		"{AFMOVV, yfmvx, Px, opBytes{0xdf, 05}}",
		"{AFMOVVP, yfmvp, Px, opBytes{0xdf, 07}}",
		"{AFRNDINT, ynone, Px, opBytes{0xd9, 0xfc}}",
	} {
		if !strings.Contains(string(table), row) {
			t.Fatal("actual selected complete integer-rounding Go row changed", row)
		}
	}
	// Nine actual rows, not a generated view of a future effect descriptor.
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			op         string
			first, ext byte
			load       bool
		}{
			{"FMOVW", 0xdf, 0, true}, {"FMOVW", 0xdf, 2, false},
			{"FMOVWP", 0xdf, 3, false},
			{"FMOVL", 0xdb, 0, true}, {"FMOVL", 0xdb, 2, false},
			{"FMOVLP", 0xdb, 3, false},
			{"FMOVV", 0xdf, 5, true}, {"FMOVVP", 0xdf, 7, false},
		} {
			instruction := func(memory string) string {
				if row.load {
					return row.op + " " + memory + ",F0"
				}
				return row.op + " F0," + memory
			}
			for _, memory := range []string{"(AX)", "-7(BX)(CX*4)"} {
				text := instruction(memory)
				t.Run(arch+"/bytes/"+text, func(t *testing.T) {
					want := []byte{row.first, row.ext << 3, 0xc3}
					if memory != "(AX)" {
						want = []byte{row.first, 0x44 | row.ext<<3, 0x8b, 0xf9, 0xc3}
					}
					got := x86OrderingHintGoBytes(t, arch, "TEXT probe(SB),4,$0-0\n"+text+"\nRET\n")
					if !bytes.Equal(got, want) {
						t.Fatalf("actual Go integer row=%x, independent expected=%x", got, want)
					}
				})
			}
			for _, memory := range []string{"value+0(FP)", "value-8(SP)"} {
				text := instruction(memory)
				t.Run(arch+"/pseudo-memory/"+text, func(t *testing.T) {
					// This original object validates Go format only, not native
					// storage ownership or a callable/initialized x87 entry.
					goAssemblerOracleOutput(t, arch, "TEXT probe(SB),4,$16-32\n"+text+"\nRET\n", "", true)
				})
			}
		}
		t.Run(arch+"/bytes/FRNDINT", func(t *testing.T) {
			got := x86OrderingHintGoBytes(t, arch, "TEXT probe(SB),4,$0-0\nFRNDINT\nRET\n")
			if !bytes.Equal(got, []byte{0xd9, 0xfc, 0xc3}) {
				t.Fatalf("actual Go no-operand rounding=%x", got)
			}
		})
		for _, source := range []string{
			"FMOVW (AX),F1", "FMOVW F1,(AX)", "FMOVW F0,F1",
			"FMOVL (AX),F1", "FMOVL F1,(AX)", "FMOVL F0,F1",
			"FMOVV F0,(AX)", "FMOVVP (AX),F0", "FMOVWP (AX),F0", "FMOVLP (AX),F0",
			"FMOVW $1,F0", "FMOVV AX,F0", "FRNDINT F0", "FMOVWP", "FMOVV.Z (AX),F0",
		} {
			t.Run(fmt.Sprintf("%s/Go-rejects/%s", arch, source), func(t *testing.T) {
				goAssemblerOracleOutput(t, arch, "TEXT probe(SB),4,$0-0\n"+source+"\nRET\n", "", false)
			})
		}
	}
}
