package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalCLMULCases() []string {
	var operations []string
	for _, selector := range []int{0, 1, 16, 17} {
		for _, source := range []string{"X1", "X2", "64(BP)", "(SI)"} {
			operations = append(operations, fmt.Sprintf("PCLMULQDQ $%d,%s,X2", selector, source))
		}
		for _, bank := range []string{"X", "Y"} {
			for _, source := range []string{bank + "1", "64(BP)", "(SI)", "65(BP)", "1(SI)"} {
				operations = append(operations, fmt.Sprintf("VPCLMULQDQ $%d,%s,%s2,%s3", selector, source, bank, bank))
			}
			for _, destination := range []string{bank + "1", bank + "2"} {
				operations = append(operations, fmt.Sprintf("VPCLMULQDQ $%d,%s1,%s2,%s", selector, bank, bank, destination))
			}
		}
	}
	return operations
}

func TestGoAMD64FixedLocalCLMULOfficialVEXBytes(t *testing.T) {
	// The existing complete CLMUL audit owns all six original rows. These
	// two VEX rows supply source witnesses, not exact encoder-row selection.
	witnesses := fixedLocalVEXFamilyWitnesses(t, `^VPCLMULQDQ$`, 2, 6)
	fixedLocalCheckVEXEncodings(t, witnesses)
	fixedLocalCheckVEXPhysicalBoundaries(t, witnesses)
}

func TestGoAMD64FixedLocalCLMULCompleteFamilies(t *testing.T) {
	operations := fixedLocalCLMULCases()
	if len(operations) != 72 {
		t.Fatal("CLMUL selector/width/alias/memory inventory changed", len(operations))
	}
	var assembly strings.Builder
	for index, operation := range operations {
		assembly.WriteString(strings.Replace(fixedLocalVEXAssembly(operation), "·Value", fmt.Sprintf("·Value%d", index), 1))
	}
	requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
	for _, operation := range operations {
		t.Run(operation, func(t *testing.T) {
			fn, sig, _ := fixedLocalVEXFixture(t, operation)
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("original Go accepts complete carryless-multiply source but private-frame effect is missing", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalCLMULSelectedBytesAndAliases(t *testing.T) {
	for _, shape := range []struct {
		name, bank string
		width      int
	}{
		{"PCLMULQDQ", "X", 16}, {"VPCLMULQDQ", "X", 16}, {"VPCLMULQDQ", "Y", 32},
	} {
		for _, destination := range []int{1, 2, 3} {
			if shape.name == "PCLMULQDQ" && destination == 3 {
				continue
			}
			t.Run(fmt.Sprintf("%s/%s/destination%d", shape.name, shape.bank, destination), func(t *testing.T) {
				for immediate := 0; immediate < 256; immediate++ {
					second := 2
					operation := fmt.Sprintf("VPCLMULQDQ $%d,%s1,%s2,%s%d", immediate, shape.bank, shape.bank, shape.bank, destination)
					if shape.name == "PCLMULQDQ" {
						second = destination
						operation = fmt.Sprintf("PCLMULQDQ $%d,X1,X%d", immediate, destination)
					}
					ins := x86YMMReadSource(t, operation)
					secondRoot := Reg(fmt.Sprintf("Z%d", second))
					output := Reg(fmt.Sprintf("Z%d", destination))
					// Independent byte positions: bit 4 selects the first source;
					// bit 0 selects the second (old destination for legacy).
					needed := map[Reg]uint64{}
					for lane := 0; lane < shape.width; lane += 16 {
						for byteIndex := 0; byteIndex < 8; byteIndex++ {
							needed["Z1"] |= uint64(1) << uint(lane+(immediate>>4&1)*8+byteIndex)
							needed[secondRoot] |= uint64(1) << uint(lane+(immediate&1)*8+byteIndex)
						}
					}
					for missing := -1; missing < shape.width; missing++ {
						for _, input := range []Reg{"Z1", secondRoot} {
							state := x86FixedLocalState{
								vectors: map[Reg]uint64{"Z1": needed["Z1"], "Z2": needed["Z2"], "Z3": 0, "Z7": 0x1234},
								flags:   x86ByteFlagsAll,
							}
							state.vectors[output] |= uint64(1) << 60
							if missing >= 0 {
								state.vectors[input] &^= uint64(1) << uint(missing)
							}
							beforeOutput := state.vectors[output]
							wantFailure := missing >= 0 && needed[input]&(uint64(1)<<uint(missing)) != 0
							err := fixedLocalVectorStep(&ins, &state, nil, 0)
							if wantFailure {
								if !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatalf("%s missing %s byte %d acquired numerical result: %v", operation, input, missing, err)
								}
								if state.vectors[output] != beforeOutput || state.flags != x86ByteFlagsAll {
									t.Fatal("rejected input changed numerical output or FLAGS", operation)
								}
								continue
							}
							if err != nil {
								t.Fatal("unselected bytes became required inputs", operation, input, missing, err)
							}
							want := ^uint64(0)
							if shape.name == "PCLMULQDQ" {
								want = (uint64(1) << 60) | 0xffff
							}
							if state.vectors[output] != want || state.vectors["Z7"] != 0x1234 || state.flags != x86ByteFlagsAll {
								t.Fatal("carryless multiply changed upper aliases, unrelated state or FLAGS", operation, state)
							}
							for register, mask := range needed {
								if register != output && state.vectors[register] != mask {
									t.Fatal("non-destination input was modified", operation, register)
								}
							}
						}
					}
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalRequiredVectorBytesBoundaries(t *testing.T) {
	for _, row := range []struct {
		name            string
		kind            OperandKind
		register        Reg
		width           int64
		required, known uint64
		read, wantPass  bool
	}{
		{"default full", OpReg, "X1", 16, 0, 0xffff, true, true},
		{"default missing", OpReg, "X1", 16, 0, 0xff, true, false},
		{"selected complete", OpReg, "X1", 16, 0xff, 0xff, true, true},
		{"selected missing", OpReg, "X1", 16, 0xff, 0xfe, true, false},
		{"beyond width", OpReg, "X1", 16, 0x10000, ^uint64(0), true, false},
		{"empty width", OpReg, "X1", 0, 1, ^uint64(0), true, false},
		{"GP is not vector", OpReg, AX, 8, 1, ^uint64(0), true, false},
		{"memory is full tuple", OpMem, "", 16, 1, ^uint64(0), true, false},
		{"write is not read", OpReg, "X1", 16, 1, ^uint64(0), false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			ins := x86YMMReadSource(t, "PSHUFD $0,X1,X2")
			effect := x86TypedByteEffect{
				vector: x86TypedVectorEffect{x86TypedVectorUpperPreserve, 16},
				operands: []x86TypedByteOperand{{
					operand: Operand{Kind: row.kind, Reg: row.register}, width: row.width,
					read: row.read, write: !row.read, requiredBytes: row.required,
				}},
			}
			state := x86FixedLocalState{vectors: map[Reg]uint64{"Z1": row.known}, known: map[Reg]uint8{AX: 255}}
			err := fixedLocalTypedByteStep(&ins, &state, FuncSig{}, nil, 0, effect)
			if (err == nil) != row.wantPass {
				t.Fatal("required vector bytes changed their width/storage domain", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalCLMULFullMemoryAndFormGuards(t *testing.T) {
	for _, operation := range []string{
		"PCLMULQDQ $0,65(BP),X2", "PCLMULQDQ $0,256(BP),X2",
		"PCLMULQDQ $0,(AX),X2", "PCLMULQDQ $0,a+8(FP),X2", "PCLMULQDQ $0,X7,X2",
		"VPCLMULQDQ $0,256(BP),Y2,Y3", "VPCLMULQDQ $0,(AX),Y2,Y3",
		"VPCLMULQDQ $0,X16,X2,X3", "VPCLMULQDQ $0,Z1,Z2,Z3",
		"VPCLMULQDQ $0,X1,X2,K1,X3", "VPCLMULQDQ.Z $0,X1,X2,X3",
		"VPCLMULQDQ.BCST $0,(SI),X2,X3", "VPCLMULQDQ $-1,X1,X2,X3",
		"VPCLMULQDQ $256,X1,X2,X3", "VPCLMULQDQ $0.5,X1,X2,X3",
	} {
		t.Run(operation, func(t *testing.T) {
			fn, sig, _ := fixedLocalVEXFixture(t, operation)
			if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unknown storage or unadmitted form acquired a private-frame effect", err)
			}
		})
	}
	for _, operation := range []string{"PCLMULQDQ $0,64(BP),X2", "VPCLMULQDQ $0,64(BP),X2,X3", "VPCLMULQDQ $0,64(BP),Y2,Y3"} {
		t.Run(operation+"/unselected-memory-byte", func(t *testing.T) {
			_, sig, source := fixedLocalVEXFixture(t, operation)
			// CompleteFamilies owns the corresponding unchanged positive.
			// Register inputs use a disjoint range; the removed qword is
			// numerically unselected but still in the native memory tuple.
			changed := strings.ReplaceAll(source, "VMOVDQU 64(BP)", "VMOVDQU 128(BP)")
			if changed == source {
				t.Fatal("fixture no longer moved the register inputs to separate storage")
			}
			source = strings.Replace(changed, "MOVQ AX,72(BP)\n", "", 1)
			if source == changed {
				t.Fatal("fixture no longer removed the unselected memory qword")
			}
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("selected low qword replaced complete native memory tuple", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalCLMULObjects(t *testing.T) {
	operations := fixedLocalCLMULCases()
	var assembly, declarations strings.Builder
	for index, operation := range operations {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(fixedLocalVEXAssembly(operation), "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(p *uint64,a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(operations))
}
