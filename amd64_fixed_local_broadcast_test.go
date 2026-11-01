package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type fixedLocalBroadcastCase struct {
	name, source, destination string
	bytes                     int
}

// The independent complete Go table directory includes EVEX rows too. Only
// these four original ytabs contain VEX rows; GP, mask and newer block sources
// remain with their existing separate consumers.
func fixedLocalBroadcastCases(t *testing.T) []fixedLocalBroadcastCase {
	t.Helper()
	var rows []fixedLocalBroadcastCase
	for _, spec := range x86BroadcastTestDirectory {
		switch spec.table {
		case "_yvpbroadcastb", "_yvbroadcastss", "_yvbroadcastsd", "_yvbroadcastf128":
		default:
			continue
		}
		for _, bank := range spec.destinations {
			if bank == 'Z' {
				continue
			}
			sources := []string{"65(BP)"}
			if strings.Contains(spec.source, "X") {
				sources = append(sources, "X0")
			}
			for _, source := range sources {
				rows = append(rows, fixedLocalBroadcastCase{spec.name, source, string(bank) + "2", spec.bytes})
			}
		}
	}
	if len(rows) != 24 {
		t.Fatal("complete VEX broadcast memory/register and width inventory changed", len(rows))
	}
	return rows
}

func (row fixedLocalBroadcastCase) instruction() string {
	return row.name + " " + row.source + "," + row.destination
}

func TestX86FixedLocalBroadcastOriginalFormsAndEffects(t *testing.T) {
	rows := fixedLocalBroadcastCases(t)
	for _, arch := range []string{"amd64", "386"} {
		var source strings.Builder
		for _, row := range rows {
			source.WriteString(row.instruction() + "\n")
		}
		code, pcs := x86NumericalBoundaryGoBytes(t, arch, source.String()+"RET")
		if len(pcs) != len(rows)+1 {
			t.Fatal("original Go instruction inventory changed", len(pcs))
		}
		for index, row := range rows {
			t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
				encoded := code[pcs[index]:pcs[index+1]]
				if len(encoded) < 3 || encoded[0] != 0xc4 && encoded[0] != 0xc5 {
					t.Fatalf("original row did not select VEX: %x", encoded)
				}
				ins := x86ScalarLaneInstruction(t, row.instruction())
				effect, known, err := x86UnmaskedVEXByteEffect(ins.Op, ins, arch)
				if !known || err != nil || len(effect.operands) != 2 {
					t.Fatal("complete broadcast family lacks its typed dependency", known, err)
				}
				input, output := effect.operands[0], effect.operands[1]
				width := int64(row.bytes)
				var required uint64
				if row.source == "X0" {
					width, required = 16, uint64(1)<<uint(row.bytes)-1
				}
				if input.index != 0 || !input.read || input.write || input.width != width || input.requiredBytes != required ||
					output.index != 1 || output.read || !output.write || output.width != int64(amd64VectorByteWidth(Reg(row.destination))) ||
					effect.vector.upperWrite != x86TypedVectorUpperZero || effect.vector.memoryAlignment != 1 ||
					effect.flagsRead != 0 || effect.flagsDefined != 0 || effect.flagsKilled != 0 {
					t.Fatalf("broadcast source extent/upper alias/FLAGS changed: %+v", effect)
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalBroadcastSelectedBytes(t *testing.T) {
	for _, row := range fixedLocalBroadcastCases(t) {
		if row.source != "X0" {
			continue
		}
		for _, alias := range []bool{false, true} {
			destination := row.destination
			if alias {
				destination = destination[:1] + "0"
			}
			t.Run(row.name+"/"+destination, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.name+" X0,"+destination)
				required := uint64(1)<<uint(row.bytes) - 1
				for missing := -1; missing < row.bytes; missing++ {
					input := required
					if missing >= 0 {
						input &^= uint64(1) << uint(missing)
					}
					state := x86FixedLocalState{vectors: map[Reg]uint64{"Z0": input, "Z2": 0, "Z7": 0xa55a}, flags: x86ByteFlagsAll}
					before := cloneFixedLocalState(state)
					err := fixedLocalVectorStep(&ins, &state, nil, 0)
					if missing >= 0 {
						if !errors.Is(err, ErrProbeNeedsContext) || !reflect.DeepEqual(state.vectors, before.vectors) || state.flags != before.flags {
							t.Fatal("missing scalar byte invented or partially published", missing, err, state)
						}
						continue
					}
					before.vectors[x86CallerVectorRoot(Reg(destination))] = ^uint64(0)
					if err != nil || !reflect.DeepEqual(state.vectors, before.vectors) || state.flags != before.flags {
						t.Fatal("broadcast lost a source alias, upper zero or FLAGS", err, state)
					}
				}
			})
		}
	}
}

func fixedLocalBroadcastBody(row fixedLocalBroadcastCase) string {
	// Consume every byte of the Y alias, including VEX.128's zeroed upper
	// half, through private memory and the real ABI0 result.
	return row.instruction() + "\nVMOVDQU Y2,128(BP)\n" +
		"MOVQ 128(BP),AX\nXORQ 136(BP),AX\nORQ 144(BP),AX\nADDQ 152(BP),AX\nMOVQ AX,128(BP)"
}

func TestGoAMD64FixedLocalBroadcastCompleteFunctions(t *testing.T) {
	var original strings.Builder
	for index, row := range fixedLocalBroadcastCases(t) {
		original.WriteString(strings.Replace(fixedLocalVEXAssembly(fixedLocalBroadcastBody(row)), "·Value", fmt.Sprintf("·Value%d", index), 1))
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
	for _, row := range fixedLocalBroadcastCases(t) {
		t.Run(row.instruction(), func(t *testing.T) {
			fn, sig, _ := fixedLocalVEXFixture(t, fixedLocalBroadcastBody(row))
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("complete initialized broadcast frame/result rejected", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalBroadcastMemoryAndEncodingBoundaries(t *testing.T) {
	for _, row := range fixedLocalBroadcastCases(t) {
		if row.source == "X0" {
			continue
		}
		for _, offset := range []int{0, 65, 192 - row.bytes, 193 - row.bytes, 256} {
			t.Run(fmt.Sprintf("%s/%s/%d", row.name, row.destination, offset), func(t *testing.T) {
				operation := fmt.Sprintf("%s %d(BP),%s", row.name, offset, row.destination)
				fn, sig, source := fixedLocalVEXFixture(t, operation)
				requireX86GoAssemblerResult(t, "amd64", source, true)
				_, err := proveX86FixedLocal(fn, sig)
				want := offset >= 64 && offset+row.bytes <= 192
				if want && err != nil || !want && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("broadcast lost its exact initialized source extent", want, err)
				}
			})
		}
	}
	for _, source := range []string{
		"VPBROADCASTQ AX,Y2", "VPBROADCASTD X16,Y2", "VBROADCASTSS X0,Z2",
		"VPBROADCASTW X0,K1,Y2", "VPBROADCASTB.Z X0,K1,Y2",
		"VBROADCASTI32X2 X0,Y2", "VBROADCASTF32X4 64(BP),Y2", "VPBROADCASTMB2Q K1,Y2",
		"VBROADCASTI128 (AX),Y2", "VBROADCASTF128 256(BP),Y2",
	} {
		t.Run(source, func(t *testing.T) {
			fn, sig, original := fixedLocalVEXFixture(t, source)
			requireX86GoAssemblerResult(t, "amd64", original, true)
			if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("broadcast invented an EVEX, mask, pointer or memory role", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalBroadcastObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	rows := fixedLocalBroadcastCases(t)
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(fixedLocalVEXAssembly(fixedLocalBroadcastBody(row)), "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(p *uint64,a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}
