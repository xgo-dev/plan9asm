package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func TestX86RawFP16ConversionExactSourceAndState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for member, op := range x86FP16ConversionResultNames {
			for length := 0; length < 3; length++ {
				for _, memory := range []bool{false, true} {
					for _, zero := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/%s/VL%d/memory=%t/zero=%t", arch, op, length, memory, zero), func(t *testing.T) {
							code := x86FP16ConversionResultEncoding(member, length, memory, false, zero)
							file := mustParseX86RawReturn(t, "TEXT Value(SB),4,$0-0\n"+x86RawDisplacementDirectives(code)+"RET\n")
							file, err := normalizeX86RawFile(file, arch)
							if err != nil {
								t.Fatal(err)
							}
							ins := file.Funcs[0].Instrs[1]
							inputBytes := []int{8 << length, 16 << length, 2, 4, 2, 8}[member]
							outputBytes := []int{16 << length, 8 << length, 4, 2, 8, 2}[member]
							state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
							state.pointerGP[0], state.callerAddressGP[0], state.masks[1] = true, true, true
							state.gp[2] = 0xa5
							state.writeVector(0, 64, ^uint64(0), false)
							state.writeVector(1, 64, ^uint64(0), false)
							state.writeVector(2, 64, 0xa55a, false)
							before := state.clone()
							want := before.clone()
							value, width := ^uint64(0), 64
							if member >= 2 {
								low := x86CallerVectorByteMask(int64(outputBytes))
								value, width = low|0xa55a&^low, 16
							}
							want.writeVector(0, width, value, false)
							accepted, known := x86LoweredFP16ConversionStep(ins, &state, nil, arch)
							if !accepted || !known || !reflect.DeepEqual(state, want) {
								t.Fatal("conversion invented passthrough bytes or changed unrelated state", accepted, known)
							}
							for _, mutation := range []string{"mask", "input", "merge", "origin", "length", "address", "segment", "return", "literal", "operand"} {
								if mutation == "merge" && zero {
									continue
								}
								changed, rejected := ins, before.clone()
								switch mutation {
								case "mask":
									rejected.masks[1] = false
								case "input":
									if memory {
										rejected.pointerGP[0] = false
									} else {
										rejected.writeVector(1, 64, ^(uint64(1) << uint(inputBytes-1)), false)
									}
								case "merge":
									rejected.writeVector(0, 64, ^(uint64(1) << uint(outputBytes-1)), false)
								case "origin":
									changed.x86SourceRaw = nil
								case "length":
									changed.x86VectorBytes ^= 16
								case "address":
									changed.x86AddressBits = 16
								case "segment":
									changed.x86SegmentPrefix = 0x64
								case "return":
									changed.x86RawNearReturn = new(x86RawNearReturnForm)
								case "literal":
									changed.x86RIPLiteral = true
								case "operand":
									changed.Args = append([]Operand(nil), ins.Args...)
									changed.Args[0] = Operand{Kind: OpReg, Reg: "X7"}
								}
								original := rejected.clone()
								accepted, known := x86LoweredFP16ConversionStep(changed, &rejected, nil, arch)
								if accepted || !known || !reflect.DeepEqual(original, rejected) {
									t.Fatal("conversion borrowed a missing input or stale source identity", mutation)
								}
							}
						})
					}
				}
			}
		}
	}
}
