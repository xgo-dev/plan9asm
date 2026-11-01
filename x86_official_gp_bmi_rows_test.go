package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// The source producer follows scalar operand roles. MULX independently reads
// DX and stores both results; ordinary ternary operations read CX instead.
// This is initialized object evidence, not a numerical or FLAGS oracle.
func x86OfficialGPBMIAssembly(cases []x86OfficialPackedCase, arch string) (string, string) {
	word, move := 8, "Q"
	if arch == "386" {
		word, move = 4, "L"
	}
	var source, declarations strings.Builder
	for index := range cases {
		fixture := &cases[index]
		w := fixture.witness
		mulx := strings.HasPrefix(w.Instruction, "MULX")
		fixture.symbol = fmt.Sprint("GPBMI", index)
		results, size := "(result uintptr)", word*5
		if mulx {
			results, size = "(low,high uintptr)", word*6
		}
		fmt.Fprintf(&declarations, "func %s(memory *[8]byte,a,control,multiplier uintptr) %s\n", fixture.symbol, results)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n", fixture.symbol, size)
		if w.Memory {
			fmt.Fprintf(&source, "MOV%s memory+0(FP),AX\n", move)
		} else {
			fmt.Fprintf(&source, "MOV%s a+%d(FP),AX\n", move, word)
		}
		if mulx {
			fmt.Fprintf(&source, "MOV%s multiplier+%d(FP),DX\n", move, word*3)
		} else if w.Second != "" {
			fmt.Fprintf(&source, "MOV%s control+%d(FP),CX\n", move, word*2)
		}
		fixture.line = strings.Count(source.String(), "\n") + 1
		fmt.Fprintln(&source, w.Instruction)
		if mulx {
			fmt.Fprintf(&source, "MOV%s CX,low+%d(FP)\nMOV%s BX,high+%d(FP)\n", move, word*4, move, word*5)
		} else {
			fmt.Fprintf(&source, "MOV%s %s,result+%d(FP)\n", move, w.Destination, word*4)
		}
		source.WriteString("RET\n")
	}
	return source.String(), declarations.String()
}

func TestX86OfficialGPBMIRowsSelectedGoBytesThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, mode := range []struct {
		arch, triple    string
		rows, witnesses int
	}{
		{"amd64", "x86_64-unknown-linux-gnu", 28, 56},
		{"386", "i386-unknown-linux-gnu", 27, 54},
	} {
		t.Run(mode.arch, func(t *testing.T) {
			selected := func(legacy goasmrules.X86LegacyCatalog, avx []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error) {
				rows, err := goasmrules.X86GPBMIRows(legacy, avx)
				if err != nil || len(rows) != 28 {
					return nil, fmt.Errorf("complete original GP table has %d rows: %v", len(rows), err)
				}
				var ordinary []goasmrules.X86PackedBinaryRow
				for _, row := range rows {
					if mode.arch == "386" && row.Opcode == "MULXQ" {
						continue // Existing physical-WIG Context is owned separately below.
					}
					ordinary = append(ordinary, row)
				}
				return ordinary, nil
			}
			x86OfficialPackedRowsObjectsForTarget(t, mode.arch, mode.triple, selected, mode.rows, mode.witnesses, 0,
				func(cases []x86OfficialPackedCase) (string, string) {
					return x86OfficialGPBMIAssembly(cases, mode.arch)
				},
				func(t *testing.T, ir string, _ []x86OfficialPackedCase) {
					x86PackedStringCompileObject(t, llc, mode.triple, ir, "-O2")
				})
		})
	}
}

func TestX86OfficialGPBMIMode32MULXQKeepsPhysicalContext(t *testing.T) {
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86GPBMIRows(goasmrules.X86LegacyCatalog{}, avx)
	if err != nil {
		t.Fatal(err)
	}
	observed := 0
	for _, row := range rows {
		if row.Opcode != "MULXQ" {
			continue
		}
		for _, w := range row.Witnesses {
			observed++
			t.Run(fmt.Sprint(w.Memory), func(t *testing.T) {
				cases := []x86OfficialPackedCase{{row: row.ID, witness: w}}
				source, declarations := x86OfficialGPBMIAssembly(cases, "386")
				listing, err := x86ScalarLiteralGoListing(t, "386", source)
				if err != nil {
					t.Fatal("original named mode32 W1 source must be observed", err)
				}
				if err := x86OfficialPackedVerifyListing(listing, cases); err != nil {
					t.Fatal("mode32 retained the physical VEX.W payload", err)
				}
				for _, api := range []string{"text", "module", "Go"} {
					if _, err := x86ScalarFPBitViewAPI(t, source, declarations, "386", "i386-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("named source must retain its existing physical mode32 Context, not an object/runtime pass", api, err)
					}
				}
			})
		}
	}
	if observed != 2 {
		t.Fatal("complete mode32 MULXQ original-source alternatives changed", observed)
	}
}

func TestX86GPBMIInitializedProducerKeepsActualInputRoles(t *testing.T) {
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86GPBMIRows(goasmrules.X86LegacyCatalog{}, avx)
	if err != nil {
		t.Fatal(err)
	}
	for _, probe := range []struct{ opcode, removed string }{
		{"ANDNQ", "MOVQ control+16(FP),CX\n"},
		{"BEXTRQ", "MOVQ control+16(FP),CX\n"},
		{"BLSIQ", "MOVQ a+8(FP),AX\n"},
		{"MULXQ", "MOVQ multiplier+24(FP),DX\n"},
		{"RORXQ", "MOVQ a+8(FP),AX\n"},
	} {
		t.Run(probe.opcode, func(t *testing.T) {
			var cases []x86OfficialPackedCase
			for _, row := range rows {
				if row.Opcode == probe.opcode {
					cases = append(cases, x86OfficialPackedCase{row: row.ID, witness: row.Witnesses[0]})
					break
				}
			}
			if len(cases) != 1 {
				t.Fatal("independent input-role member missing")
			}
			source, declarations := x86OfficialGPBMIAssembly(cases, "amd64")
			if strings.Count(source, probe.removed) != 1 {
				t.Fatal("input mutation does not own one actual source initializer", source)
			}
			for _, api := range []string{"text", "module", "Go"} {
				if _, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
					t.Fatal("complete initialized source must precede missing-input rejection", api, err)
				}
				changed := strings.Replace(source, probe.removed, "", 1)
				if _, err := x86ScalarFPBitViewAPI(t, changed, declarations, "amd64", "x86_64-unknown-linux-gnu", api); err == nil {
					t.Fatal("missing actual scalar/implicit input was accepted", api, probe.opcode)
				}
			}
		})
	}
}
