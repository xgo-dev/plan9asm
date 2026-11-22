package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalFourSourceAssembly(t *testing.T, name string, row x86FourSourceOracleRow, memory string, omit Reg) string {
	t.Helper()
	var setup strings.Builder
	// The encoded source starts at the aligned group, which can include
	// registers that are absent from the textual range.
	base := row.first &^ 3
	for register := base; register < base+4; register++ {
		reg := Reg(fmt.Sprintf("Z%d", register))
		if reg != "Z0" && reg != omit {
			fmt.Fprintf(&setup, "VMOVUPS Z0,%s\n", reg)
		}
	}
	operation := strings.Replace(row.instruction(), "(BX)", memory, 1)
	return fixedLocalVectorStackAssembly(t, name, operation, setup.String(), omit)
}

func TestGoAMD64FixedLocalFourSourceObjects(t *testing.T) {
	rows := x86FourSourceOracleRows("amd64")
	var source, declarations strings.Builder
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		memory := "17(SP)"
		if row.first != 0 {
			memory = "17(SP)(BP*2)"
		}
		source.WriteString(fixedLocalFourSourceAssembly(t, name, row, memory, ""))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	fixedLocalCompleteVectorObjects(t, source.String(), declarations.String(), len(rows))
}

func TestX86FourSourceNativeBoundaryRejectsMalformedBytes(t *testing.T) {
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", "V4FMADDPS 128(BX), [Z0-Z3], Z6\nRET")
	instruction := code[:pcs[1]]
	for _, test := range []struct {
		name   string
		offset int
		mask   byte
	}{
		{"missing-fixed-bit", 2, 0x04},
		{"reserved-width", 2, 0x80},
		{"wrong-vector-length", 3, 0x40},
		{"reserved-broadcast", 3, 0x10},
		{"zero-without-mask", 3, 0x80},
		{"register-instead-of-memory", 5, 0x80},
	} {
		t.Run(test.name, func(t *testing.T) {
			malformed := append([]byte(nil), instruction...)
			malformed[test.offset] ^= test.mask
			if _, err := x86NumericalVectorBoundary(malformed, 64); err == nil {
				t.Fatalf("accepted malformed four-source bytes %x", malformed)
			}
		})
	}
	if _, err := x86NumericalVectorBoundary(instruction[:len(instruction)-1], 64); err == nil {
		t.Fatal("accepted a truncated four-source displacement")
	}
}

func TestGoAMD64FixedLocalFourSourceChecksAllInputs(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, member := range x86FourSourceOracle {
		row := x86FourSourceOracleRow{op: member.op, scalar: member.scalar, dot: member.dot, first: 2, dest: 6, mode: "zero"}
		t.Run(row.op, func(t *testing.T) {
			for _, test := range []struct {
				name, memory string
				omit         Reg
			}{
				{"exact-m128", "112(SP)", ""},
				{"missing-last-memory-byte", "113(SP)", ""},
				{"out-of-frame", "248(SP)", ""},
				{"missing-effective-register", "112(SP)", "Z1"},
				{"missing-mask", "112(SP)", "K1"},
				{"missing-accumulator-even-with-zeroing", "112(SP)", "Z6"},
			} {
				t.Run(test.name, func(t *testing.T) {
					source := fixedLocalFourSourceAssembly(t, "Value", row, test.memory, test.omit)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					proven, err := proveX86FixedLocal(file.Funcs[0], sig)
					if test.name != "exact-m128" {
						if !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("incomplete source acquired a proof: %v", err)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					for _, ins := range proven.Instrs {
						if ins.Op == Op(row.op+".Z") {
							access := ins.x86FixedLocalMemory[0]
							if access.owner != proven.x86FixedLocal || access.width != 16 || access.write || access.nativeInput {
								t.Fatalf("expected the exact private m128 read: %+v", access)
							}
							return
						}
					}
					t.Fatal("the original four-source instruction disappeared")
				})
			}
		})
	}
}
