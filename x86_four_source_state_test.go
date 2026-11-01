package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func x86FourSourceKnownState(arch string) x86ResultState {
	state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
	for register := 0; register < 32; register++ {
		state.writeVector(register, 64, ^uint64(0), false)
	}
	index, _, _ := x86ResultGP(BX, x86ResultPointerWord(arch), arch)
	state.pointerGP[index] = true
	state.callerAddressGP[5] = true
	state.masks[1], state.masks[3] = true, true
	state.nativeMMX[7] = 0xa5
	return state
}

func TestX86FourSourceEveryActualByteAliasesAndAtomicState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86FourSourceOracleRows(arch) {
			t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction())
				before := x86FourSourceKnownState(arch)
				state := before.clone()
				if accepted, known := x86ResultFourSourceStep(ins, &state, nil, arch, true); !accepted || !known || !reflect.DeepEqual(state, before) {
					t.Fatal("complete initialized native bytes changed unrelated vectors/GP/FLAGS/DF/K/storage", accepted, known)
				}
				active := 64
				if row.scalar {
					active = 4
				}
				for role := 0; role < 5; role++ {
					register := role
					if role == 4 {
						register = row.dest
					}
					for missing := 0; missing < 64; missing++ {
						state := before.clone()
						state.writeVector(register, 64, ^(uint64(1) << uint(missing)), false)
						initial := state.clone()
						accepted, known := x86ResultFourSourceStep(ins, &state, nil, arch, true)
						if missing < active {
							if accepted || !known || !reflect.DeepEqual(initial, state) {
								t.Fatal("an actual implicit source or old accumulator byte was invented, or failed transfer was non-atomic", role, register, missing)
							}
							continue
						}
						want := initial.clone()
						defined := uint64(0xffff)
						if register == row.dest && missing < 16 {
							defined &^= uint64(1) << uint(missing)
						}
						want.writeVector(row.dest, 16, defined, false)
						if !accepted || !known || !reflect.DeepEqual(state, want) {
							t.Fatal("scalar ignored source bytes or old upper-X passthrough gained NUM or lost EVEX upper zeroing", role, register, missing)
						}
					}
				}
			})
		}
	}
}

func TestX86FourSourceNativeContinuationDoesNotGrantInputsOrOtherRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, member := range x86FourSourceOracle {
			mode := "plain"
			if arch == "amd64" {
				mode = "zero"
			}
			row := x86FourSourceOracleRow{op: member.op, scalar: member.scalar, dot: member.dot, first: 2, dest: 6, mode: mode}
			for _, mutation := range []string{"standalone", "missing pointer", "numeric address", "unknown index", "mask", "raw", "address size", "physical segment"} {
				if mutation == "mask" && arch == "386" {
					continue
				}
				t.Run(arch+"/"+member.op+"/"+mutation, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, row.instruction())
					state := x86FourSourceKnownState(arch)
					pointer, mask, _ := x86ResultGP(BX, x86ResultPointerWord(arch), arch)
					native := true
					switch mutation {
					case "standalone":
						native = false
					case "missing pointer":
						state.pointerGP[pointer] = false
					case "numeric address":
						state.pointerGP[pointer], state.gp[pointer] = false, mask
					case "unknown index":
						ins.Args[0].Mem.Index, ins.Args[0].Mem.Scale = CX, 1
					case "mask":
						state.masks[1] = false
					case "raw":
						ins.x86Encoded = true
					case "address size":
						ins.x86AddressBits = 32
					case "physical segment":
						ins.x86SegmentPrefix = 0x64
					}
					before := state.clone()
					if accepted, _ := x86ResultFourSourceStep(ins, &state, nil, arch, native); accepted || !reflect.DeepEqual(before, state) {
						t.Fatal("the paired complete opcode created an unbound input/native/caller/entry role", mutation)
					}
				})
			}
		}
	}
}

func TestX86FourSourceAllMembersRejectMalformedOperandAndDispatchClasses(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, member := range x86FourSourceOracle {
			row := x86FourSourceOracleRow{op: member.op, scalar: member.scalar, dot: member.dot, first: 2, dest: 6, mode: "plain"}
			original := x86ScalarLaneInstruction(t, row.instruction())
			for _, mutation := range []string{"register memory", "three range", "five range", "nonconsecutive", "list not range", "other bank", "other destination", "high bank", "arity", "K0", "source dispatch", "SP index", "unresolved offset"} {
				t.Run(arch+"/"+member.op+"/"+mutation, func(t *testing.T) {
					ins := original
					ins.Args = append([]Operand(nil), original.Args...)
					ins.Args[1].RegList = append([]Reg(nil), original.Args[1].RegList...)
					dispatch := ins.Op
					switch mutation {
					case "register memory":
						ins.Args[0] = Operand{Kind: OpReg, Reg: "X7"}
					case "three range":
						ins.Args[1].RegList = ins.Args[1].RegList[:3]
					case "five range":
						ins.Args[1].RegList = append(ins.Args[1].RegList, ins.Args[1].RegList[3])
					case "nonconsecutive":
						ins.Args[1].RegList[1] = ins.Args[1].RegList[0]
					case "list not range":
						ins.Args[1].RegListRange = false
					case "other bank":
						for index := range ins.Args[1].RegList {
							ins.Args[1].RegList[index] = Reg(fmt.Sprint("Y", index+2))
						}
					case "other destination":
						ins.Args[2].Reg = "Y6"
					case "high bank":
						bank, high := "Z", 32
						if member.scalar {
							bank = "X"
						}
						if arch == "386" {
							high = 8
						}
						ins.Args[2].Reg = Reg(fmt.Sprint(bank, high))
					case "arity":
						ins.Args = ins.Args[:2]
					case "K0":
						ins.Args = []Operand{ins.Args[0], ins.Args[1], {Kind: OpReg, Reg: "K0"}, ins.Args[2]}
					case "source dispatch":
						dispatch = "V4FMADDPS"
						if ins.Op == dispatch {
							dispatch = "VP4DPWSSD"
						}
					case "SP index":
						ins.Args[0].Mem.Index, ins.Args[0].Mem.Scale = SP, 1
					case "unresolved offset":
						ins.Args[0].Mem.OffRaw = "unbound"
					}
					if _, known, err := x86FourSourceProperties(dispatch, ins, arch); !known || err == nil {
						t.Fatal("an invalid source class escaped complete family validation", known, err)
					}
					if _, known, err := x86TypedInstructionByteEffect(dispatch, ins, arch); !known || err == nil {
						t.Fatal("an invalid source class acquired implicit byte effects", known, err)
					}
				})
			}
		}
	}
}
