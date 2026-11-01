package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func TestX86IFMAPhysicalMode32RetainsEveryMaskAndWidth(t *testing.T) {
	count := 0
	for _, name := range []string{"VPMADD52HUQ", "VPMADD52LUQ"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			for mask := 1; mask <= 7; mask++ {
				for _, zero := range []bool{false, true} {
					op := name
					if zero {
						op += ".Z"
					}
					row := fmt.Sprintf("%s %s0,%s1,K%d,%s2", op, bank, bank, mask, bank)
					// The named mode32 parser cannot express this physical
					// four-operand row. Keep the original low-register bytes,
					// then normalize them in the actual source architecture.
					bytes := x86RawNumericalInstruction(t, "amd64", row)
					file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+bytes+"RET\n")
					if err != nil {
						t.Fatal(err)
					}
					file, err = normalizeX86RawFile(file, "386")
					if err != nil {
						t.Fatal("actual physical mode32 IFMA row rejected", row, err)
					}
					ins := file.Funcs[0].Instrs[1]
					form, known, err := x86IFMAProperties(ins.Op, ins, "386")
					if !known || err != nil || form.mask != 2 || form.zeroing != zero ||
						ins.Args[form.mask].Reg != Reg(fmt.Sprint("K", mask)) || !x86RawIFMASource(ins, "386") {
						t.Fatal("physical selector/zeroing was rewritten under named syntax", row, form, err)
					}
					count++
				}
			}
		}
	}
	if count != 84 {
		t.Fatal("complete physical IFMA mask/width inventory changed", count)
	}
}

func TestX86IFMAStandaloneAndNativeMemoryAuthoritiesRemainSeparate(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range []string{"VPMADD52HUQ", "VPMADD52LUQ"} {
			for _, bank := range []string{"X", "Y", "Z"} {
				ins := x86ScalarLaneInstruction(t, name+" (SI),"+bank+"1,"+bank+"2")
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionEither}
				state.pointerGP[6], state.gp[3], state.masks[1] = true, 0x55, true
				state.writeVector(1, 64, ^uint64(0), false)
				state.writeVector(2, 64, ^uint64(0), false)
				before := state.clone()
				if accepted, known := x86ResultIFMAStep(ins, &state, nil, arch); !known || accepted ||
					!reflect.DeepEqual(state, before) {
					t.Fatal("standalone IFMA query obtained native memory or changed a failed state", arch, name, bank)
				}
				want := before.clone()
				width := amd64VectorByteWidth(ins.Args[2].Reg)
				want.writeVector(2, width, x86CallerVectorByteMask(int64(width)), false)
				if accepted, known := x86LoweredIFMAStep(ins, &state, nil, arch); !known || !accepted ||
					!reflect.DeepEqual(state, want) {
					t.Fatal("paired IFMA lost its exact read or changed independent flags/pointer roles", arch, name, bank)
				}
			}
		}
	}
}
