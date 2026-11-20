//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

const (
	x86PackedConversionNativeOwners = 8
	x86PackedConversionValueCapture = 64
	x86PackedConversionFaultCapture = 16
)

// The full994-row object matrix owns spelling/address axes. Native execution
// keeps every independent semantic shape, rather than duplicating that syntax
// Cartesian product:38 existing families plus signed4, aliases, dead results,
// all signed masks/broadcasts/rounding and the two physical low-bank EVEX forms.
func x86PackedConversionCompleteRuntimeRows() []x86PackedConversionRuntimeRow {
	rows := x86PackedConversionRuntimeRows(true)
	for _, row := range x86SignedPackedValueRows() {
		input := row.input
		if strings.Contains(input, "(") {
			input = "(SI)"
		}
		rows = append(rows, x86PackedConversionRuntimeRow{
			instruction: row.op + " " + input + "," + row.mask + row.bank + "1",
			wide:        true, inputBits: 32, mask: row.mask != "", sae: strings.Contains(row.op, "SAE"),
		})
	}
	for _, op := range []string{"CVTPL2PS", "CVTPL2PD", "VCVTDQ2PS", "VCVTDQ2PD"} {
		banks := []string{"X"}
		if strings.HasPrefix(op, "V") {
			banks = []string{"X", "Y", "Z"}
		}
		for _, bank := range banks {
			input := bank
			if op == "VCVTDQ2PD" {
				input = "X"
				if bank == "Z" {
					input = "Y"
				}
			}
			rows = append(rows,
				x86PackedConversionRuntimeRow{instruction: op + " " + input + "1," + bank + "1", wide: true, inputBits: 32},
				x86PackedConversionRuntimeRow{instruction: op + " " + input + "0," + bank + "1", wide: true, dead: true, inputBits: 32})
		}
	}
	for _, physical := range []struct {
		instruction string
		code        []byte
	}{
		{"VCVTDQ2PS X0,X1", []byte{0x62, 0xf1, 0x7c, 0x08, 0x5b, 0xc8}},
		{"VCVTDQ2PD X0,X1", []byte{0x62, 0xf1, 0x7e, 0x08, 0xe6, 0xc8}},
	} {
		rows = append(rows, x86PackedConversionRuntimeRow{
			instruction: physical.instruction, rawOverride: strings.TrimSuffix(x86RawDisplacementDirectives(physical.code), "\n"),
			wide: true, inputBits: 32,
		})
	}
	return rows
}

func x86PackedConversionCompleteFaultRows() []x86PackedConversionFaultRow {
	rows := x86PackedConversionFaultRows(true)
	for _, member := range []struct {
		name              string
		width, lanes      int
		legacy, precision bool
	}{
		{"CVTPL2PS", 16, 4, true, true},
		{"CVTPL2PD", 8, 2, true, false},
		{"VCVTDQ2PS", 16, 4, false, true},
		{"VCVTDQ2PS", 32, 8, false, true},
		{"VCVTDQ2PS", 64, 16, false, true},
		{"VCVTDQ2PD", 8, 2, false, false},
		{"VCVTDQ2PD", 16, 4, false, false},
		{"VCVTDQ2PD", 32, 8, false, false},
	} {
		outputBytes := member.lanes * 4
		if strings.HasSuffix(member.name, "PD") {
			outputBytes *= 2
		}
		destination := map[int]string{16: "X1", 32: "Y1", 64: "Z1"}[outputBytes]
		row := x86PackedConversionFaultRow{
			name: member.name, width: member.width, laneBytes: 4, lanes: member.lanes,
			precision: member.precision,
			// SSE CVTDQ2PD reads only m64 and has no m128 alignment
			// requirement. It must not inherit the other legacy forms'.
			aligned:    member.legacy && member.width == 16,
			conversion: member.name + " (DI)," + destination,
		}
		rows = append(rows, row)
		if !member.legacy {
			row.name, row.masked = member.name+".Z", true
			row.conversion = row.name + " (DI),K1," + destination
			rows = append(rows, row)
			row.name, row.width = member.name+".BCST.Z", 4
			row.conversion = row.name + " (DI),K1," + destination
			rows = append(rows, row)
		}
	}
	return rows
}

func x86PackedConversionCompleteNativeFaults(t *testing.T, owner int) {
	t.Helper()
	if owner < 0 || owner >= x86PackedConversionNativeOwners {
		t.Fatal("invalid native conversion fault owner", owner)
	}
	execution := x86PackedConversionNativeTools(t)
	rows := x86PackedConversionCompleteFaultRows()
	if len(rows) != 222 {
		t.Fatal("complete42 fault denominator changed", len(rows))
	}
	x86PackedConversionRunFaultRows(t, execution, rows, x86PackedConversionFaultCapture, owner, x86PackedConversionNativeOwners, true, true)
}

func x86PackedConversionCompleteNativeValues(t *testing.T, owner int) {
	t.Helper()
	if owner < 0 || owner >= x86PackedConversionNativeOwners {
		t.Fatal("invalid native conversion owner", owner)
	}
	execution := x86PackedConversionNativeTools(t)
	rows := x86PackedConversionCompleteRuntimeRows()
	if len(rows) != 692 {
		t.Fatal("complete42 native semantic denominator changed", len(rows))
	}
	consumed := 0
	for batch, start := 0, 0; start < len(rows); batch, start = batch+1, start+x86PackedConversionValueCapture {
		if batch%x86PackedConversionNativeOwners != owner {
			continue
		}
		end := start + x86PackedConversionValueCapture
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("batch-%04d", start), func(t *testing.T) {
			current := rows[start:end]
			assembly, declarations, main, driver := x86PackedConversionRuntimeFixture(current)
			var want []byte
			t.Run("original_go_named", func(t *testing.T) {
				want = x86ScalarFloatIntegerOriginalOutput(t, execution, assembly, main)
				if strings.Count(string(want), "\n") != len(current) {
					t.Fatal("incomplete original Go named runtime receipts")
				}
			})
			var instructions []string
			for _, row := range current {
				instructions = append(instructions, row.instruction)
			}
			raw := x86PackedConversionContinuationRawRows(t, "amd64", instructions)
			rawRows := append([]x86PackedConversionRuntimeRow(nil), current...)
			for index := range rawRows {
				rawRows[index].instruction = raw[index]
				if current[index].rawOverride != "" {
					rawRows[index].instruction = current[index].rawOverride
				}
			}
			rawAssembly, _, rawMain, _ := x86PackedConversionRuntimeFixture(rawRows)
			t.Run("original_go_raw", func(t *testing.T) {
				got := x86ScalarFloatIntegerOriginalOutput(t, execution, rawAssembly, rawMain)
				if string(got) != string(want) || len(want) == 0 {
					t.Fatal("original named/raw Go runtime diverged or lost receipts")
				}
			})
			if len(want) == 0 {
				t.Fatal("missing original native Go execution")
			}
			for _, spelling := range []struct{ name, source string }{{"named", assembly}, {"raw", rawAssembly}} {
				t.Run(spelling.name, func(t *testing.T) {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, spelling.source, declarations, "amd64", execution.triple, api)
							if err != nil {
								t.Fatal("initialized complete native conversion source rejected", err)
							}
							x86PackedConversionNativePipelines(t, execution, ir, driver, want)
						})
					}
				})
			}
			consumed += len(current)
		})
	}
	if consumed == 0 {
		t.Fatal("empty native value owner")
	}
	t.Logf("%d/692 native kernels: actual named/raw Go,3APIs,3LLVM paths; full MXCSR, masks, aliases and dead results", consumed)
}
