package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type fixedLocalVEXZeroCase struct {
	instruction         string
	bank                string
	source, destination int
}

func fixedLocalVEXZeroCases() []fixedLocalVEXZeroCase {
	var cases []fixedLocalVEXZeroCase
	for _, name := range x86LegacyLogicalMemoryNames {
		if !fixedLocalLogicalZeroName(name) {
			continue
		}
		for _, bank := range []string{"X", "Y"} {
			for source := 0; source < 16; source++ {
				for _, destination := range []int{source, (source + 1) % 16} {
					instruction := fmt.Sprintf("V%s %s%d,%s%d,%s%d", name, bank, source, bank, source, bank, destination)
					cases = append(cases, fixedLocalVEXZeroCase{instruction, bank, source, destination})
				}
			}
		}
	}
	return cases
}

func fixedLocalVEXZeroBody(row fixedLocalVEXZeroCase) string {
	// Read the complete Y alias even after an X-width zero, then consume all
	// four qwords and the separately initialized input canary at 0(SP).
	// OR prevents incorrect nonzero lanes from cancelling one another.
	return row.instruction + fmt.Sprintf("\nVMOVDQU Y%d,16(SP)\n", row.destination) +
		"MOVQ 16(SP),AX\nORQ 24(SP),AX\nORQ 32(SP),AX\nORQ 40(SP),AX\nADDQ 0(SP),AX"
}

func TestGoAMD64FixedLocalVEXLogicalZeroOfficialRows(t *testing.T) {
	witnesses := fixedLocalVEXFamilyWitnesses(t,
		`^V(ANDN?P[DS]|ORP[DS]|XORP[DS]|PANDN?|POR|PXOR)$`, 24, 72)
	fixedLocalCheckVEXEncodings(t, witnesses)
	fixedLocalCheckVEXPhysicalBoundaries(t, witnesses)
}

func TestGoAMD64FixedLocalVEXLogicalZeroComplete(t *testing.T) {
	cases := fixedLocalVEXZeroCases()
	if len(cases) != 384 {
		t.Fatal("six zero identities by two widths, 16 sources and two destination aliases changed", len(cases))
	}
	var original strings.Builder
	for index, row := range cases {
		_, _, source := fixedLocalGPFixture(t, fixedLocalVEXZeroBody(row))
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
	for _, row := range cases {
		t.Run(row.instruction, func(t *testing.T) {
			fn, sig, _ := fixedLocalGPFixture(t, fixedLocalVEXZeroBody(row))
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("same-input logical zero acquired an undefined-input obligation", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalVEXLogicalZeroConsumers(t *testing.T) {
	for _, name := range x86LegacyLogicalMemoryNames {
		for _, bank := range []string{"X", "Y"} {
			for _, first := range []int{0, 1} {
				for _, destination := range []int{0, 2} {
					instruction := fmt.Sprintf("V%s %s%d,%s0,%s%d", name, bank, first, bank, bank, destination)
					zero := first == 0 && fixedLocalLogicalZeroName(name)
					t.Run(instruction, func(t *testing.T) {
						ins := x86ScalarLaneInstruction(t, instruction)
						_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value() uint64",
							instruction+fmt.Sprintf("\nMOVQ X%d,AX\nMOVQ AX,ret0+0(FP)\nRET", destination))
						resultErr := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, "amd64")
						if zero && resultErr != nil || !zero && !errors.Is(resultErr, ErrProbeNeedsContext) {
							t.Fatal("ordinary result consumer changed its logical dependency", resultErr)
						}
						effect, known, err := x86UnmaskedVEXByteEffect(ins.Op, ins, "amd64")
						if !known || err != nil || len(effect.operands) != 3 {
							t.Fatal("complete VEX logical source lacks its typed effect", known, err)
						}
						for _, operand := range effect.operands {
							if operand.read && zero {
								t.Fatal("a logical zero still reads undefined register bytes", operand)
							}
						}
						state := x86FixedLocalState{vectors: map[Reg]uint64{"Z0": 0, "Z1": 0, "Z2": 0, "Z16": 0xa55a}, flags: x86ByteFlagsAll}
						before := cloneFixedLocalState(state)
						err = fixedLocalVectorStep(&ins, &state, nil, 0)
						if !zero {
							if !errors.Is(err, ErrProbeNeedsContext) || !reflect.DeepEqual(state.vectors, before.vectors) || state.flags != before.flags {
								t.Fatal("nonzero logical input was invented or partially published", err, state)
							}
							return
						}
						before.vectors[Reg(fmt.Sprintf("Z%d", destination))] = ^uint64(0)
						if err != nil || !reflect.DeepEqual(state.vectors, before.vectors) || state.flags != before.flags {
							t.Fatal("logical zero changed a source alias, upper bytes or FLAGS", err, state)
						}
					})
				}
			}
		}
	}
}

func TestGoAMD64FixedLocalVEXLogicalZeroKeepsMemoryAndEncodingRoles(t *testing.T) {
	for _, row := range []string{
		"VPXOR 16(SP),Y0,Y0", "VANDNPS 16(SP),Y0,Y0",
		"VXORPS X16,X16,X16", "VXORPS Y16,Y16,Y16", "VXORPS Z0,Z0,Z0",
		"KMOVQ AX,K1\nVXORPS X0,X0,K1,X1", "KMOVQ AX,K1\nVXORPS.Z X0,X0,K1,X1",
	} {
		t.Run(row, func(t *testing.T) {
			fn, sig, source := fixedLocalGPFixture(t, row+"\nMOVQ $0,AX")
			requireX86GoAssemblerResult(t, "amd64", source, true)
			if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("logical zero granted memory, mask or high-bank authority", err)
			}
		})
	}
}

func fixedLocalVEXZeroProgram(t *testing.T) (string, string, int) {
	t.Helper()
	var assembly, declarations strings.Builder
	count := 0
	for _, row := range fixedLocalVEXZeroCases() {
		if row.source != 15 {
			continue
		}
		_, _, source := fixedLocalGPFixture(t, fixedLocalVEXZeroBody(row))
		name := fmt.Sprintf("Value%d", count)
		assembly.WriteString(strings.Replace(source, "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
		count++
	}
	if count != 24 {
		t.Fatal("six zero identities by two widths and two destination aliases changed", count)
	}
	return assembly.String(), declarations.String(), count
}

func TestGoAMD64FixedLocalVEXLogicalZeroObjects(t *testing.T) {
	assembly, declarations, count := fixedLocalVEXZeroProgram(t)
	fixedLocalCompleteVectorObjects(t, assembly, declarations, count)
}
