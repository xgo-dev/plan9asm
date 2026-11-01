package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Each complete original VEX row has register and memory counterparts.
// This is bounded numerical availability/object evidence, not native FP,
// MXCSR, fault execution or a certificate for the input pointee's extent.
func TestX86AlternatingRoundInitializedOfficialRowsThreeAPIObjects(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"},
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			word, move, output := 8, "MOVQ", "VMOVUPS Z2,(DX)"
			if target.arch == "386" {
				word, move, output = 4, "MOVL", "VMOVUPS Y2,(DX)"
			}
			var source, declarations, refusedSource, refusedDeclarations strings.Builder
			rows, functions, refusedRows, refusedFunctions := 0, 0, 0, 0
			for _, row := range rules {
				if row.Opcode != "VADDSUBPS" && row.Opcode != "VADDSUBPD" && row.Opcode != "VROUNDPS" && row.Opcode != "VROUNDPD" && row.Opcode != "VROUNDSS" && row.Opcode != "VROUNDSD" {
					continue
				}
				rows++
				goRefused := target.arch == "386" && (row.Opcode == "VROUNDSS" || row.Opcode == "VROUNDSD")
				if goRefused {
					refusedRows++
				}
				bank := map[string]string{"Yxr": "X", "Yyr": "Y"}[row.Classes[len(row.Classes)-1]]
				if bank == "" {
					t.Fatal("original row lost its VEX carrier", row)
				}
				immediate := "$7"
				if row.Classes[0] == "Yi8" {
					immediate = "$-1"
				}
				for _, memory := range []bool{false, true} {
					name := fmt.Sprint("AlternatingRound", functions)
					functions++
					var function strings.Builder
					declaration := fmt.Sprintf("func %s(out *[64]byte,a,b *[32]byte)\n", name)
					fmt.Fprintf(&function, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DX\n%s a+%d(FP),AX\n", name, 3*word, move, move, word)
					first := bank + "0"
					if memory {
						first = "(AX)"
					} else {
						function.WriteString("VMOVUPS (AX),Y0\n")
					}
					if strings.HasPrefix(row.Opcode, "VADDSUB") || strings.HasSuffix(row.Opcode, "SS") || strings.HasSuffix(row.Opcode, "SD") {
						fmt.Fprintf(&function, "%s b+%d(FP),BX\nVMOVUPS (BX),Y1\n", move, 2*word)
					}
					switch {
					case strings.HasPrefix(row.Opcode, "VADDSUB"):
						fmt.Fprintf(&function, "%s %s,%s1,%s2\n", row.Opcode, first, bank, bank)
					case strings.HasSuffix(row.Opcode, "SS") || strings.HasSuffix(row.Opcode, "SD"):
						fmt.Fprintf(&function, "%s %s,%s,X1,X2\n", row.Opcode, immediate, first)
					default:
						fmt.Fprintf(&function, "%s %s,%s,%s2\n", row.Opcode, immediate, first, bank)
					}
					function.WriteString(output + "\nRET\n")
					if goRefused {
						refusedFunctions++
						refusedSource.WriteString(function.String())
						refusedDeclarations.WriteString(declaration)
					} else {
						source.WriteString(function.String())
						declarations.WriteString(declaration)
					}
				}
			}
			if rows != 14 || functions != 28 {
				t.Fatal("complete original row/source union changed", rows, functions)
			}
			if target.arch == "386" {
				if refusedRows != 2 || refusedFunctions != 4 || rows-refusedRows != 12 || functions-refusedFunctions != 24 {
					t.Fatal("mode32 ordinary/refused source union changed", rows, functions, refusedRows, refusedFunctions)
				}
				x86RoundRejectedGoSource(t, refusedSource.String(), refusedDeclarations.String(), target.arch, target.triple)
			} else if refusedRows != 0 || refusedFunctions != 0 {
				t.Fatal("AMD64 lost an original canonical row")
			}
			t.Logf("original rows=%d functions=%d selected rows=%d functions=%d refused rows=%d functions=%d", rows, functions, rows-refusedRows, functions-refusedFunctions, refusedRows, refusedFunctions)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("complete independently initialized alternating/round rows rejected", err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, ir, level)
					}
				})
			}
		})
	}

}
