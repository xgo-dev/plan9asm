package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86RawFP16FMAExactInputsAndState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for opcode, op := range rawFP16FMAOps() {
			for length := byte(0); length < 3; length++ {
				for _, memory := range []bool{false, true} {
					for mask := 0; mask < 3; mask++ {
						t.Run(fmt.Sprintf("%s/%s/VL%d/memory%t/mask%d", arch, op, length, memory, mask), func(t *testing.T) {
							code := x86FP16FMAResultEncoding(opcode, length, memory, false, mask == 2)
							if mask == 0 {
								code[3] &^= 7
							}
							file := mustParseX86RawReturn(t, "TEXT Value(SB),4,$0-0\n"+x86RawDisplacementDirectives(code)+"RET\n")
							file, err := normalizeX86RawFile(file, arch)
							if err != nil {
								t.Fatal(err)
							}
							ins := file.Funcs[0].Instrs[1]
							width, input := 16<<length, 16<<length
							scalar := strings.HasSuffix(string(op), "SH")
							if scalar {
								width, input = 16, 2
							}
							state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
							state.pointerGP[0], state.callerAddressGP[0], state.masks[1] = true, true, true
							state.gp[2] = 0xa5
							for reg := 0; reg < 3; reg++ {
								state.writeVector(reg, 64, ^uint64(0), false)
							}
							if scalar {
								state.writeVector(0, 64, 0xa55b, false)
								state.writeVector(1, 64, 3, false)
								state.writeVector(2, 64, 3, false)
							}
							before, want := state.clone(), state.clone()
							value := ^uint64(0)
							if scalar {
								value = 0xa55b // Preserve unknown upper X bytes, not the second source.
							}
							want.writeVector(0, width, value, false)
							accepted, known := x86LoweredFP16FMAStep(ins, &state, nil, arch)
							if !accepted || !known || !reflect.DeepEqual(state, want) {
								t.Fatal("FMA changed unrelated state or lost exact input/passthrough bytes", accepted, known)
							}

							caller := x86SourceStackState{vectors: map[Reg]uint64{
								"Z0": ^uint64(0), "Z1": ^uint64(0), "Z2": ^uint64(0)}, masks: map[Reg]bool{"K1": true}}
							standalone := before.clone()
							if x86CallerVectorMoveKnown(ins) || x86CallerVectorMoveStep(&ins, &caller, nil) ||
								x86ScalarFPResultTransfer(ins, &standalone, nil, -1, arch) {
								t.Fatal("raw FMA borrowed a caller or standalone query contract")
							}
							for _, mutation := range []string{"mask", "first", "second", "destination", "origin", "length", "address", "segment", "return", "literal", "operand"} {
								if mutation == "mask" && mask == 0 {
									continue
								}
								changed, rejected := ins, before.clone()
								switch mutation {
								case "mask":
									rejected.masks[1] = false
								case "first", "second", "destination":
									reg := map[string]int{"first": 1, "second": 2, "destination": 0}[mutation]
									if mutation == "first" && memory {
										rejected.pointerGP[0] = false
									} else {
										rejected.writeVector(reg, 64, rejected.vectorBytes(reg)&^(uint64(1)<<uint(input-1)), false)
									}
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
								accepted, known := x86LoweredFP16FMAStep(changed, &rejected, nil, arch)
								if accepted || !known || !reflect.DeepEqual(original, rejected) {
									t.Fatal("FMA invented input or original-source facts", mutation)
								}
							}
						})
					}
				}
			}
		}
	}
}
