package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalBlockWitnesses(t *testing.T) []fixedLocalVEXWitness {
	t.Helper()
	// Original Go has one unsigned insertion row and two overlapping
	// signed/unsigned extraction rows for each of the F/I spellings.
	return fixedLocalVEXFamilyWitnesses(t, `^V(INSERT|EXTRACT)[FI]128$`, 6, 18)
}

func TestGoAMD64FixedLocalBlockTransferCompleteFamilies(t *testing.T) {
	witnesses := fixedLocalBlockWitnesses(t)
	fixedLocalCheckVEXEncodings(t, witnesses)
	fixedLocalCheckVEXPhysicalBoundaries(t, witnesses)
	fixedLocalCheckVEXFamilies(t, witnesses)
}

func TestGoAMD64FixedLocalBlockTransferSelectedBytes(t *testing.T) {
	for _, name := range []string{"VINSERTF128", "VINSERTI128", "VEXTRACTF128", "VEXTRACTI128"} {
		insert := strings.HasPrefix(name, "VINSERT")
		for _, alias := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/alias=%t", name, alias), func(t *testing.T) {
				minimum := -128
				if insert {
					minimum = 0
				}
				for selector := minimum; selector <= 255; selector++ {
					selected := uint64(0xffff) << (uint(selector&1) * 16)
					input, destination := selected, "X2"
					args := "Y1," + destination
					if alias {
						destination, args = "X1", "Y1,X1"
					}
					if insert {
						input, destination = uint64(0xffffffff)&^selected, "Y2"
						if alias {
							destination = "Y1"
						}
						args = "X0,Y1," + destination
					}
					ins := x86YMMReadSource(t, fmt.Sprintf("%s $%d,%s", name, selector, args))
					state := x86FixedLocalState{vectors: map[Reg]uint64{
						"Z0": 0xffff, "Z1": input, "Z2": 0, "Z7": 123,
					}, flags: x86ByteFlagsAll}
					if err := fixedLocalVectorStep(&ins, &state, nil, 0); err != nil {
						t.Fatal("unselected source bytes must not be inputs", selector, err)
					}
					if state.vectors[x86CallerVectorRoot(Reg(destination))] != ^uint64(0) ||
						!alias && state.vectors["Z1"] != input || state.vectors["Z7"] != 123 || state.flags != x86ByteFlagsAll {
						t.Fatal("block transfer lost an alias, upper zero or unrelated state", selector, state)
					}
					for bit := uint(0); bit < 32; bit++ {
						if input&(1<<bit) == 0 {
							continue
						}
						state.vectors["Z1"] = input &^ (1 << bit)
						if err := fixedLocalVectorStep(&ins, &state, nil, 0); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("missing selected/retained byte accepted", selector, bit, err)
						}
					}
				}
			})
		}
	}
	for _, name := range []string{"VINSERTF128", "VINSERTI128"} {
		t.Run(name+"/all operands alias", func(t *testing.T) {
			for selector := 0; selector <= 255; selector++ {
				input := uint64(0xffffffff)
				if selector&1 != 0 {
					input = 0xffff // The low chunk supplies both halves.
				}
				ins := x86YMMReadSource(t, fmt.Sprintf("%s $%d,X0,Y0,Y0", name, selector))
				for missing := -1; missing < 32; missing++ {
					known := input
					if missing >= 0 {
						known &^= 1 << uint(missing)
					}
					state := x86FixedLocalState{vectors: map[Reg]uint64{"Z0": known}}
					err := fixedLocalVectorStep(&ins, &state, nil, 0)
					if known == input {
						if err != nil || state.vectors["Z0"] != ^uint64(0) {
							t.Fatal("aliased inputs lost their common selected bytes", selector, missing, err)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("insertion invented a source/retained byte", selector, missing, err)
					}
				}
			}
		})
	}
}

func TestGoAMD64FixedLocalBlockTransferMemoryBounds(t *testing.T) {
	for _, name := range []string{"VINSERTF128", "VINSERTI128", "VEXTRACTF128", "VEXTRACTI128"} {
		for _, offset := range []int{0, 65, 176, 177, 256} {
			t.Run(fmt.Sprintf("%s/%d", name, offset), func(t *testing.T) {
				args := fmt.Sprintf("$1,Y1,%d(BP)", offset)
				if strings.HasPrefix(name, "VINSERT") {
					args = fmt.Sprintf("$1,%d(BP),Y1,Y2", offset)
				}
				fn, sig, _ := fixedLocalVEXFixture(t, name+" "+args)
				_, err := proveX86FixedLocal(fn, sig)
				// The fixture initializes the private read extent through 191.
				// Writes may initialize a new in-frame span, but never escape it.
				want := offset >= 64 && offset <= 176 || !strings.HasPrefix(name, "VINSERT") && offset == 0
				if (err == nil) != want {
					t.Fatal("complete unaligned m128 access has wrong bounds", want, err)
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalBlockTransferObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	witnesses := fixedLocalBlockWitnesses(t)
	for index, row := range witnesses {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(fixedLocalVEXAssembly(row.source), "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(p *uint64,a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(witnesses))
}

func TestGoAMD64FixedLocalBlockTransferEVEXOriginalObjects(t *testing.T) {
	operations := []string{
		"VEXTRACTF32X8 $0, Z12, K4, (BP)",
		"VEXTRACTF32X8 $0, Z13, K4, (BP)",
		"VEXTRACTF64X2 $1, Y3, K4, -17(BP)(SI*8)",
		"VEXTRACTF64X2 $1, Y19, K4, -17(BP)(SI*8)",
		"VEXTRACTF64X2 $1, Y23, K4, -17(BP)(SI*8)",
		"VEXTRACTI32X4 $1, Z27, K3, (SP)",
		"VEXTRACTI32X4 $1, Z25, K3, (SP)",
		"VINSERTF32X8.Z $1,32(SP),Z12,K4,Z13",
		"VINSERTI64X2 $2,17(SP)(SI*2),Z20,K3,Z23",
		"VEXTRACTI64X4.Z $1,Z13,K2,Y12",
	}
	var assembly, declarations strings.Builder
	for index, operation := range operations {
		name := fmt.Sprintf("Value%d", index)
		setup := "LEAQ 48(SP),BP\nMOVQ $1,SI\n"
		assembly.WriteString(fixedLocalVectorStackAssembly(t, name, operation, setup, ""))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(operations))
}

func TestGoAMD64FixedLocalBlockTransferOfficialMemoryRows(t *testing.T) {
	var source strings.Builder
	var operations []string
	seen := make(map[string]bool)
	members := make(map[string]bool)
	rowCount := 0
	for _, row := range x86OfficialInsertExtractBoundaryRows(t) {
		name := row.Opcode
		isBlock := (strings.HasPrefix(name, "VINSERT") || strings.HasPrefix(name, "VEXTRACT")) &&
			name != "VINSERTPS" && name != "VEXTRACTPS"
		if !isBlock {
			continue
		}
		members[name] = true
		rowCount++
		for _, witness := range row.Witnesses {
			if !witness.Memory {
				continue
			}
			operation := strings.Replace(witness.Instruction, "(AX)", "17(SP)(BP*2)", 1)
			if operation == witness.Instruction {
				t.Fatalf("row %s lacks its memory operand: %s", row.ID, witness.Instruction)
			}
			if !seen[operation] {
				source.WriteString(fixedLocalVectorStackAssembly(t, fmt.Sprintf("Value%d", len(operations)), operation, "", ""))
				operations = append(operations, operation)
				seen[operation] = true
			}
		}
	}
	t.Logf("%d block mnemonics, %d original rows, %d distinct memory spellings", len(members), rowCount, len(operations))
	if len(members) != 20 || rowCount != 54 || len(operations) != 38 {
		t.Fatal("incomplete block transfer inventory")
	}
	requireX86GoAssemblerResult(t, "amd64", "TEXT Forms(SB),4,$0-0\n"+strings.Join(operations, "\n")+"\nRET\n", true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != len(operations) {
		t.Fatal("missing parsed block transfer functions", len(file.Funcs))
	}
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for index, operation := range operations {
		if _, err := proveX86FixedLocal(file.Funcs[index], sig); err != nil {
			t.Fatalf("%s: initialized frame rejected: %v", operation, err)
		}
	}
}

func TestGoAMD64FixedLocalBlockTransferMaskedBytes(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		operation string
		omit      Reg
		read      string
		valid     bool
	}{
		{"VEXTRACTI64X2 $1,Z1,K1,120(SP)", "", "", true},
		{"VEXTRACTI64X2 $1,Z1,K1,120(SP)", "", "MOVB 128(SP),AL", false},
		{"VEXTRACTI64X2 $1,Z1,120(SP)", "", "MOVB 128(SP),AL", true},
		{"VEXTRACTI64X2 $1,Z1,K1,120(SP)", "K1", "", false},
		{"VEXTRACTI64X2.Z $1,Z1,K1,120(SP)", "", "", false},
		{"VEXTRACTF64X4 $1,Z1,K1,240(SP)", "", "", false},
		{"VINSERTF32X8.Z $1,96(SP),Z2,K1,Z3", "Z3", "", true},
		{"VINSERTF32X8 $1,96(SP),Z2,K1,Z3", "Z3", "", false},
		{"VINSERTF32X8.Z $1,97(SP),Z2,K1,Z3", "Z3", "", false},
		{"VEXTRACTF64X2.Z $1,Z1,K1,X3", "Z3", "", true},
		{"VEXTRACTF64X2 $1,Z1,K1,X3", "Z3", "", false},
	} {
		t.Run(fmt.Sprintf("%s/omit=%s/read=%s", row.operation, row.omit, row.read), func(t *testing.T) {
			source := fixedLocalVectorStackAssembly(t, "Value", row.operation, "", row.omit)
			if row.read != "" {
				const originalRead = "MOVB 120(SP),AL"
				if !strings.Contains(source, originalRead) {
					t.Fatal("missing store readback in fixture")
				}
				source = strings.Replace(source, originalRead, row.read, 1)
			}
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.valid && err != nil || !row.valid && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("valid=%t: %v", row.valid, err)
			}
		})
	}
}
