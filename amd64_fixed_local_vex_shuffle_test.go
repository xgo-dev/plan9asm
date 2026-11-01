package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalVEXShuffleWitnesses(t *testing.T) []fixedLocalVEXWitness {
	t.Helper()
	// This existing audit checks all 30 VEX/EVEX rows, including the
	// dword-only broadcast attribute; only 12 VEX rows enter this scope.
	x86OfficialImmediateShuffleRows(t)
	return fixedLocalVEXFamilyWitnesses(t, `^VPSHUF(D|HW|LW)$`, 12, 36)
}

func TestGoAMD64FixedLocalVEXShuffleOfficialEncodings(t *testing.T) {
	fixedLocalCheckVEXEncodings(t, fixedLocalVEXShuffleWitnesses(t))
}

func TestGoAMD64FixedLocalVEXShufflePhysicalBoundaries(t *testing.T) {
	fixedLocalCheckVEXPhysicalBoundaries(t, fixedLocalVEXShuffleWitnesses(t))
}

func TestGoAMD64FixedLocalVEXShuffleCompleteFamilies(t *testing.T) {
	fixedLocalCheckVEXFamilies(t, fixedLocalVEXShuffleWitnesses(t))
	for _, name := range []string{"VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
		for _, bank := range []string{"X", "Y"} {
			t.Run(name+"/unaligned/"+bank, func(t *testing.T) {
				fn, sig, _ := fixedLocalVEXFixture(t, name+" $255,65(BP),"+bank+"2")
				if _, err := proveX86FixedLocal(fn, sig); err != nil {
					t.Fatal("VEX full tuple incorrectly inherited legacy alignment", err)
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalVEXShuffleImmediateDomainAndUpperZeros(t *testing.T) {
	for _, name := range []string{"VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
		for _, bank := range []string{"X", "Y"} {
			for _, alias := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/alias=%t", name, bank, alias), func(t *testing.T) {
					destination := bank + "2"
					if alias {
						destination = bank + "1"
					}
					width := 16
					if bank == "Y" {
						width = 32
					}
					input := uint64(0x8040201000000000) | x86CallerVectorByteMask(int64(width))
					for immediate := -128; immediate <= 255; immediate++ {
						operation := fmt.Sprintf("%s $%d,%s1,%s", name, immediate, bank, destination)
						ins := x86YMMReadSource(t, operation)
						state := x86FixedLocalState{vectors: map[Reg]uint64{"Z1": input, "Z2": 0}, flags: x86ByteFlagsAll}
						if err := fixedLocalVectorStep(&ins, &state, nil, 0); err != nil {
							t.Fatal("complete VEX immediate domain or source-only dependency rejected", operation, err)
						}
						if state.vectors[x86CallerVectorRoot(Reg(destination))] != ^uint64(0) ||
							!alias && state.vectors["Z1"] != input || state.flags != x86ByteFlagsAll {
							t.Fatal("VEX shuffle failed upper-zero/source/FLAGS contract", operation, state)
						}
					}
				})
			}
		}
	}
}

func TestGoAMD64FixedLocalVEXShuffleBoundaries(t *testing.T) {
	for _, name := range []string{"VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
		t.Run(name+"/dispatch identity", func(t *testing.T) {
			ins := x86YMMReadSource(t, "PSHUFD $0,X1,X2")
			if _, known, err := x86UnmaskedVEXByteEffect(Op(name), ins, "amd64"); !known || err == nil {
				t.Fatal("VEX dispatch changed a legacy source's upper-write contract", known, err)
			}
		})
		for _, suffix := range []string{
			" $0,Z1,Z2", " $0,X16,X2", " $0,X1,X16", " $0,X1,K1,X2",
			".Z $0,X1,K1,X2", ".BCST $0,(SI),X2", " $0,M0,M1",
			" $-129,X1,X2", " $256,X1,X2", " $0.5,X1,X2", " $missing,X1,X2",
		} {
			operation := name + suffix
			t.Run(operation, func(t *testing.T) {
				ins := x86YMMReadSource(t, operation)
				if effect, known, err := fixedLocalVectorByteEffect(ins); known && err == nil {
					t.Fatal("separate EVEX/MMX or invalid syntax acquired VEX metadata", operation, effect)
				}
			})
		}
		for _, args := range []string{
			"$0,X7,X2", "$0,184(BP),X2", "$0,184(BP),Y2", "$0,256(BP),X2",
			"$0,(AX),X2", "$0,a+8(FP),X2",
		} {
			t.Run(name+"/unproved/"+args, func(t *testing.T) {
				fn, sig, _ := fixedLocalVEXFixture(t, name+" "+args)
				if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("uninitialized vector/private extent/numerical address gained backing", err)
				}
			})
		}
	}
}

func TestGoAMD64FixedLocalVEXShuffleObjects(t *testing.T) {
	witnesses := fixedLocalVEXShuffleWitnesses(t)
	for _, name := range []string{"VPSHUFD", "VPSHUFHW", "VPSHUFLW"} {
		for _, bank := range []string{"X", "Y"} {
			witnesses = append(witnesses, fixedLocalVEXWitness{source: name + " $255,65(BP)," + bank + "2"})
		}
	}
	if len(witnesses) != 42 {
		t.Fatal("complete VEX shuffle source denominator changed", len(witnesses))
	}
	var assembly, declarations strings.Builder
	for index, row := range witnesses {
		source := fixedLocalVEXAssembly(row.source)
		changed := strings.Replace(source, "VMOVDQU 64(BP),Y2\n", "", 1)
		if changed == source {
			t.Fatal("old destination removal did not change complete source")
		}
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(changed, "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(p *uint64,a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(witnesses))
}
