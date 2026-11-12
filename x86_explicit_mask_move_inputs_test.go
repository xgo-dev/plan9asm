package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independent of the production form: integer and floating spellings select
// the high bit of each D/Q or PS/PD element, not any of its other bytes.
func x86ExplicitMaskMoveSignOracle(row x86ExplicitMaskMoveCase) uint64 {
	lane := 4
	if strings.HasPrefix(row.instruction, "VMASKMOVPD ") || strings.HasPrefix(row.instruction, "VPMASKMOVQ ") {
		lane = 8
	}
	var required uint64
	for offset := lane - 1; offset < row.width; offset += lane {
		required |= uint64(1) << uint(offset)
	}
	return required
}

func x86ExplicitMaskMoveInputState(arch string) x86ResultState {
	state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
	base, _, _ := x86ResultGP(AX, x86ResultPointerWord(arch), arch)
	state.pointerGP[base] = true
	state.gp[3], state.canonicalGP[3], state.pointerGP[3] = 0xa5, 0x11, true
	state.masks[5] = true
	state.writeVector(0, 64, ^uint64(0), false)
	state.writeVector(1, 64, ^uint64(0), false)
	state.writeVector(2, 64, 0x13579bdf02468ace, false)
	state.writeVector(3, 64, 0xabcdef1234567890, false)
	return state
}

func TestX86ExplicitMaskMoveEverySignDataByteAndUnaffectedState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ExplicitMaskMoveIndependentCases() {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction)
				for role := 0; role < 2; role++ {
					for missing := 0; missing < 64; missing++ {
						state := x86ExplicitMaskMoveInputState(arch)
						state.writeVector(role, 64, ^(uint64(1) << uint(missing)), false)
						want := state.clone()
						required := x86ExplicitMaskMoveSignOracle(row)
						if role == 0 {
							required = 0
							if row.memory == 2 {
								required = x86CallerVectorByteMask(int64(row.width))
							}
							// Data is operand zero; mask is operand one.
						}
						accepted := required&(uint64(1)<<uint(missing)) == 0
						if accepted && row.memory == 0 {
							want.writeVector(2, row.width, x86CallerVectorByteMask(int64(row.width)), false)
						}
						got, known := x86ResultExplicitMaskMoveStep(ins, &state, nil, 0, arch, true)
						if !known || got != accepted || !reflect.DeepEqual(state, want) {
							t.Fatal("mask move confused sign/data/upper bytes or changed independent state", role, missing, got, accepted)
						}
					}
				}
				// A load may alias its actual mask; read the input before clearing
				// all upper destination views. A store may alias data and mask.
				aliased := ins
				aliased.Args = append([]Operand(nil), ins.Args...)
				aliased.Args[1].Reg = aliased.Args[2-row.memory].Reg
				state := x86ExplicitMaskMoveInputState(arch)
				if row.memory == 0 {
					state.writeVector(2, 64, x86ExplicitMaskMoveSignOracle(row), false)
				}
				want := state.clone()
				if row.memory == 0 {
					want.writeVector(2, row.width, x86CallerVectorByteMask(int64(row.width)), false)
				}
				got, known := x86ResultExplicitMaskMoveStep(aliased, &state, nil, 0, arch, true)
				if !known || !got || !reflect.DeepEqual(state, want) {
					t.Fatal("legal same-register vector mask alias lost input-before-output ordering")
				}
			})
		}
	}
}

func TestX86ExplicitMaskMoveAddressAndStandaloneBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ExplicitMaskMoveIndependentCases() {
			for _, control := range []string{"standalone", "missing-address", "numeric-not-pointer", "missing-index", "segment", "address-size", "raw-origin", "raw-encoded"} {
				t.Run(arch+"/"+row.name+"/"+control, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, row.instruction)
					state := x86ExplicitMaskMoveInputState(arch)
					base, full, _ := x86ResultGP(AX, x86ResultPointerWord(arch), arch)
					native := true
					switch control {
					case "standalone":
						native = false
					case "missing-address":
						state.pointerGP[base] = false
					case "numeric-not-pointer":
						state.pointerGP[base], state.gp[base] = false, full
					case "missing-index":
						ins.Args[row.memory].Mem.Index, ins.Args[row.memory].Mem.Scale = SI, 2
					case "segment":
						ins.Args[row.memory].Mem.Segment = FS
					case "address-size":
						ins.x86AddressBits = 32
					case "raw-origin":
						ins.x86SourceRaw = &x86SourceRawInstruction{op: ins.Op, args: append([]Operand(nil), ins.Args...)}
					case "raw-encoded":
						ins.x86Encoded = true
					}
					before := state.clone()
					got, known := x86ResultExplicitMaskMoveStep(ins, &state, nil, 0, arch, native)
					if !known || got || !reflect.DeepEqual(before, state) {
						t.Fatal("mask move invented a numerical address, native source or backing fact", control)
					}
				})
			}
		}
	}
}

func TestX86ExplicitMaskMoveCallerConsumesActualSignBytesAndBounds(t *testing.T) {
	for _, row := range x86ExplicitMaskMoveIndependentCases() {
		for _, control := range []string{"complete", "unknown-sign", "unknown-data", "missing-address", "outside-region"} {
			t.Run(row.name+"/"+control, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction)
				state := x86SourceStackState{
					callers: map[Reg]x86CallerPointerValue{AX: {argument: 0}},
					vectors: map[Reg]uint64{"Z0": x86CallerVectorByteMask(int64(row.width)), "Z1": x86ExplicitMaskMoveSignOracle(row), "Z2": 0x5555},
				}
				kind := x86CallerSliceInput
				if row.memory == 2 {
					kind = x86CallerFreshResult
				}
				proof := &x86GoCallerRegionProof{arguments: []x86CallerArgumentRegion{{kind: kind, width: int64(row.width)}}}
				want := control == "complete" || control == "unknown-data" && row.memory == 0
				switch control {
				case "unknown-sign":
					state.vectors["Z1"] = 0
				case "unknown-data":
					state.vectors["Z0"] = 0
				case "missing-address":
					delete(state.callers, AX)
				case "outside-region":
					ins.Args[row.memory].Mem.Off = 1
					// Slice inputs have their own dynamic bounds; a fixed local
					// scalar input is enough to test this exact envelope here.
					if row.memory == 0 {
						proof.arguments[0].kind = x86CallerLocalLength
					}
				}
				if got := x86CallerVectorMoveStep(&ins, &state, proof); got != want {
					t.Fatal("caller proof confused numerical sign bytes with source/bounds", fmt.Sprint(got, want))
				}
				if want && row.memory == 0 && state.vectors["Z2"] != ^uint64(0) {
					t.Fatal("caller load did not zero every wider destination alias")
				}
			})
		}
	}
}

func TestX86ExplicitMaskMoveLogicalFieldsKeepReadWriteRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86ExplicitMaskMoveIndependentCases() {
			for _, control := range []string{"initialized-result", "unknown-result", "parameter", "padding", "static"} {
				t.Run(arch+"/"+row.name+"/"+control, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, row.instruction)
					state := x86ExplicitMaskMoveInputState(arch)
					state.fp = make([]bool, 2*row.width)
					owned := make([]bool, len(state.fp))
					for index := range state.fp {
						state.fp[index], owned[index] = true, true
					}
					ins.Args[row.memory] = Operand{Kind: OpFP, FPOffset: int64(row.width)}
					want := control == "initialized-result" || control == "parameter" && row.memory == 0
					switch control {
					case "unknown-result":
						for index := row.width; index < len(state.fp); index++ {
							state.fp[index] = false
						}
					case "parameter":
						ins.Args[row.memory].FPOffset = 0
					case "padding":
						owned[len(owned)-1] = false
					case "static":
						ins.Args[row.memory] = Operand{Kind: OpSym, Sym: "readonly(SB)"}
					}
					before := state.clone()
					if want && row.memory == 0 {
						before.writeVector(2, row.width, x86CallerVectorByteMask(int64(row.width)), false)
					}
					got, known := x86ResultExplicitMaskMoveStep(ins, &state, owned, int64(row.width), arch, false)
					if !known || got != want || !reflect.DeepEqual(before, state) {
						t.Fatal("masked logical memory confused prior NUM with a writable/owned span", control, got, want)
					}
				})
			}
		}
	}
}
