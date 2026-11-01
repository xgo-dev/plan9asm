package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// The signed scalar memory spellings are selected by the earlier VEX row.
// Their EVEX rows remain selectable through high-register/rounding inputs.
func x86ConversionEarlierMemoryRow(row goasmrules.X86PackedBinaryRow, w goasmrules.X86PackedBinaryWitness) bool {
	return strings.Contains(row.ID, "/_yvcvtsd2si/1") && w.Memory
}

func x86ConversionRowsForObjects(terminal bool) func(goasmrules.X86LegacyCatalog, []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error) {
	return func(legacy goasmrules.X86LegacyCatalog, avx []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error) {
		rows, err := goasmrules.X86PrecisionHalfScalarConversionRows(legacy, avx)
		if err != nil {
			return nil, err
		}
		var selected []goasmrules.X86PackedBinaryRow
		for _, row := range rows {
			original := row.Witnesses
			row.Witnesses = nil
			for _, w := range original {
				fault := row.Opcode == "VCVTPS2PH" && w.Zeroing && w.Destination == "(AX)"
				if fault == terminal && !x86ConversionEarlierMemoryRow(row, w) {
					row.Witnesses = append(row.Witnesses, w)
				}
			}
			if len(row.Witnesses) != 0 {
				selected = append(selected, row)
			}
		}
		return selected, nil
	}
}

func TestX86OfficialPrecisionHalfScalarConversionRowsThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	// This existing direction/kind producer initializes only actual vector,
	// GP, upper-copy and masked-merge inputs, and stores the real result.
	x86OfficialPackedRowsObjectsInspect(t, x86ConversionRowsForObjects(false), 76, 287, 0,
		x86OfficialInsertExtractAssembly, func(t *testing.T, ir string, _ []x86OfficialPackedCase) {
			x86PackedStringCompileObject(t, llc, "x86_64-unknown-linux-gnu", ir, "-O2")
		})
}

func TestX86OfficialPrecisionHalfConversionTerminalRowsThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	assembly := func(cases []x86OfficialPackedCase) (string, string) {
		var source, declarations strings.Builder
		for index := range cases {
			fixture := &cases[index]
			fixture.symbol = fmt.Sprint("ConversionFault", index)
			fmt.Fprintf(&declarations, "func %s()\n", fixture.symbol)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-0\n", fixture.symbol)
			fixture.line = strings.Count(source.String(), "\n") + 1
			fmt.Fprintln(&source, fixture.witness.Instruction)
			source.WriteString("RET\n")
		}
		return source.String(), declarations.String()
	}
	x86OfficialPackedRowsObjectsInspect(t, x86ConversionRowsForObjects(true), 3, 3, 0, assembly,
		func(t *testing.T, ir string, cases []x86OfficialPackedCase) {
			for _, fixture := range cases {
				if _, err := x86OfficialMoveFaultBody(ir, fixture.symbol); err != nil {
					t.Fatal("half terminal read unavailable inputs or retained a continuation", err)
				}
			}
			x86PackedStringCompileObject(t, llc, "x86_64-unknown-linux-gnu", ir, "-O2")
		})
}

func TestX86OfficialScalarConversionEarlierMemorySelection(t *testing.T) {
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86PrecisionHalfScalarConversionRows(goasmrules.X86LegacyCatalog{}, avx)
	if err != nil {
		t.Fatal(err)
	}
	var earlier []x86OfficialPackedCase
	for _, row := range rows {
		for _, w := range row.Witnesses {
			if !x86ConversionEarlierMemoryRow(row, w) {
				continue
			}
			var selected *goasmrules.X86PackedBinaryWitness
			for _, candidate := range rows {
				if candidate.Opcode != row.Opcode || !strings.Contains(candidate.ID, "/_yvcvtsd2si/0") {
					continue
				}
				for _, physical := range candidate.Witnesses {
					if physical.Instruction == w.Instruction {
						copy := physical
						selected = &copy
					}
				}
			}
			if selected == nil || selected.Generation != "vex" || string(selected.Encoding) == string(w.Encoding) {
				t.Fatal("late EVEX memory alternative lost its independent earlier row", row.ID, w)
			}
			earlier = append(earlier, x86OfficialPackedCase{row: row.ID, witness: *selected})
		}
	}
	if len(earlier) != 8 {
		t.Fatal("signed scalar partial-shadow observations changed", len(earlier))
	}
	source, _ := x86OfficialInsertExtractAssembly(earlier)
	listing, err := x86ScalarLiteralGoListing(t, "amd64", source)
	if err != nil {
		t.Fatal(err)
	}
	if err := x86OfficialPackedVerifyListing(listing, earlier); err != nil {
		t.Fatal("stock Go selected a different row than the independent earlier payload", err)
	}
}
