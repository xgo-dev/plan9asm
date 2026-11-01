package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func x86ImplicitMultiplyNativeExpected(input x86ResultState, bits int, arch string) x86ResultState {
	result := input.clone()
	writes, width := []Reg{AX, DX}, int64(bits/8)
	if bits == 8 {
		writes, width = writes[:1], 2 // AL × m8 writes AX16, not DX.
	}
	for _, register := range writes {
		index, mask, _ := x86ResultGP(register, width, arch)
		result.pointerGP[index] = false
		result.gp[index] |= mask
		if width == 4 || width == 8 {
			result.gp[index] = 255
		}
	}
	result.flags = x86ByteFlagCF | x86ByteFlagOF
	return result
}

func TestX86ImplicitMultiplyNativeMemoryEveryByteAndExactOutputState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ImplicitMultiplyNativeOracle {
			if arch == "386" && row.bits == 64 {
				continue
			}
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				ins := x86YMMReadSource(t, row.op+" 1(SI)(BX*2)")
				ax, needed, _ := x86ResultGP(AX, int64(row.bits/8), arch)
				bx, _, _ := x86ResultGP(BX, x86ResultPointerWord(arch), arch)
				si, _, _ := x86ResultGP(SI, x86ResultPointerWord(arch), arch)
				dx, _, _ := x86ResultGP(DX, x86ResultPointerWord(arch), arch)
				original := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward,
					fp: []bool{true, false}, auto: []bool{false, true}}
				original.gp[bx], original.gp[dx], original.pointerGP[si] = 255, 0x80, true
				original.masks[2] = true
				original.writeVector(3, 64, 0x5555555555555555, false)
				for seed := 0; seed < 256; seed++ {
					before := original.clone()
					before.gp[ax] = uint8(seed)
					state, expected := before.clone(), before.clone()
					accept := uint8(seed)&needed == needed
					if accept {
						expected = x86ImplicitMultiplyNativeExpected(before, row.bits, arch)
					}
					got, known := x86LoweredImplicitMultiplyNativeRead(ins, &state, nil, 0, arch)
					if !known || got != accept || !reflect.DeepEqual(state, expected) {
						t.Fatal("native multiplication changed its exact byte/FLAGS/storage domain", seed, needed, got, state, expected)
					}
				}
				for _, missing := range []string{"pointer", "index"} {
					before := original.clone()
					before.gp[ax] = 255
					if missing == "pointer" {
						before.pointerGP[si], before.gp[si] = false, 255
					} else {
						before.gp[bx] = 0
					}
					state := before.clone()
					if accepted, known := x86LoweredImplicitMultiplyNativeRead(ins, &state, nil, 0, arch); !known || accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("a rejected native input invented permission or partially mutated state", missing)
					}
				}
				// A source address can be old DX without numerical DX. Read it
				// before the implicit high-product write revokes its pointer tag.
				alias := x86YMMReadSource(t, fmt.Sprintf("%s (DX)", row.op))
				before := original.clone()
				before.gp[ax], before.gp[dx], before.pointerGP[dx] = 255, 0, true
				state := before.clone()
				if accepted, known := x86LoweredImplicitMultiplyNativeRead(alias, &state, nil, 0, arch); !known || !accepted ||
					!reflect.DeepEqual(state, x86ImplicitMultiplyNativeExpected(before, row.bits, arch)) {
					t.Fatal("DX address/result alias was read after write or acquired missing upper bytes")
				}
			})
		}
	}
}
