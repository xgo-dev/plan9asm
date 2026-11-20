package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func TestX86RawFP16SqrtExactSourceAndState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, scalar := range []bool{false, true} {
			for length := byte(0); length < 3; length++ {
				for _, memory := range []bool{false, true} {
					for _, zero := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/scalar%t/VL%d/memory%t/zero%t", arch, scalar, length, memory, zero), func(t *testing.T) {
							code := x86FP16SqrtResultEncoding(scalar, length, memory, false, zero)
							file := mustParseX86RawReturn(t, "TEXT Value(SB),4,$0-0\n"+x86RawDisplacementDirectives(code)+"RET\n")
							file, err := normalizeX86RawFile(file, arch)
							if err != nil {
								t.Fatal(err)
							}
							ins := file.Funcs[0].Instrs[1]
							caller := x86SourceStackState{vectors: map[Reg]uint64{
								"Z0": ^uint64(0), "Z1": ^uint64(0), "Z2": ^uint64(0)}, masks: map[Reg]bool{"K1": true}}
							if x86CallerVectorMoveKnown(ins) || x86CallerVectorMoveStep(&ins, &caller, nil) {
								t.Fatal("raw sqrt acquired a standalone caller contract")
							}
							width, input := 16<<length, 16<<length
							if scalar {
								width, input = 16, 2
							}
							state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
							state.pointerGP[0], state.callerAddressGP[0], state.masks[1] = true, true, true
							state.gp[2] = 0xa5
							state.writeVector(0, 64, ^uint64(0), false)
							state.writeVector(1, 64, ^uint64(0), false)
							state.writeVector(2, 64, 0xa55a, false)
							before, want := state.clone(), state.clone()
							value := ^uint64(0)
							if scalar {
								value = 3 | 0xa55a&^3
							}
							want.writeVector(0, width, value, false)
							accepted, known := x86ResultSqrtStep(ins, &state, nil, arch, true)
							if !accepted || !known || !reflect.DeepEqual(state, want) {
								t.Fatal("raw sqrt lost exact input, passthrough or unrelated state", accepted, known)
							}
							for _, mutation := range []string{"mask", "input", "merge", "origin", "length", "address", "segment", "return", "literal", "operand", "standalone"} {
								if mutation == "merge" && zero {
									continue
								}
								changed, rejected, native := ins, before.clone(), true
								switch mutation {
								case "mask":
									rejected.masks[1] = false
								case "input":
									if memory {
										rejected.pointerGP[0] = false
									} else {
										rejected.writeVector(1, 64, ^(uint64(1) << uint(input-1)), false)
									}
								case "merge":
									rejected.writeVector(0, 64, ^(uint64(1) << uint(input-1)), false)
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
								case "standalone":
									native = false
								}
								original := rejected.clone()
								accepted, known := x86ResultSqrtStep(changed, &rejected, nil, arch, native)
								if accepted || !known || !reflect.DeepEqual(original, rejected) {
									t.Fatal("raw sqrt borrowed missing input or unbound source", mutation)
								}
							}
						})
					}
				}
			}
		}
	}
}
