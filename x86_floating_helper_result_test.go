package plan9asm

import (
	"reflect"
	"strings"
	"testing"
)

func x86FloatingHelperInitializedState() x86ResultState {
	state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
	state.gp[3], state.pointerGP[0], state.masks[1] = 0x55, true, true
	for index := 0; index < 32; index++ {
		state.writeVector(index, 64, ^uint64(0), false)
	}
	return state
}

func x86FloatingHelperMaskedInstruction(ins Instr, zero bool) Instr {
	ins.Args = append([]Operand(nil), ins.Args...)
	last := ins.Args[len(ins.Args)-1]
	ins.Args = append(ins.Args[:len(ins.Args)-1], Operand{Kind: OpReg, Reg: "K1"}, last)
	if zero {
		ins.Op += ".Z"
	}
	return ins
}

func TestX86FloatingHelperEveryNumericalInputMaskAndMergeByte(t *testing.T) {
	for _, member := range x86FloatingHelperOracleMembers() {
		banks := []string{member.bank}
		if !member.scalar && !member.maskResult {
			banks = []string{"X", "Y", "Z"}
		}
		for _, bank := range banks {
			member.bank = bank
			original := x86ScalarLaneInstruction(t, x86FloatingHelperOracleInstruction(member, false))
			width := amd64VectorByteWidth(original.Args[len(original.Args)-1].Reg)
			if member.maskResult {
				width = amd64VectorByteWidth(original.Args[1].Reg)
			}
			active := width
			if member.scalar {
				active = 4
				if strings.HasSuffix(member.name, "SD") {
					active = 8
				}
			}
			for _, mode := range []string{"plain", "merge", "zero"} {
				if member.maskResult && mode == "zero" {
					continue
				}
				ins := original
				if mode != "plain" {
					ins = x86FloatingHelperMaskedInstruction(ins, mode == "zero")
				}
				for _, arch := range []string{"amd64", "386"} {
					if arch == "386" && len(ins.Args) > 3 {
						continue
					}
					state := x86FloatingHelperInitializedState()
					before := state.clone()
					if accepted, known := x86ResultFloatingHelperStep(ins, &state, nil, arch, true); !known || !accepted {
						t.Fatal("complete initialized helper lost its typed numerical inputs", arch, member.name, bank, mode)
					}
					want := before.clone()
					if member.maskResult {
						want.masks[2] = true
					} else {
						want.writeVector(2, width, ^uint64(0), false)
					}
					if !reflect.DeepEqual(state, want) {
						t.Fatal("helper changed independent inputs, FLAGS, DF, pointers or storage", arch, member.name, bank, mode)
					}
					for _, source := range []int{0, 1, 2, -1} {
						required := source == 0 || source == 1 && member.second || source == 2 &&
							!member.maskResult && (strings.HasPrefix(member.name, "VFIXUPIMM") || mode == "merge") || source == -1 && mode != "plain"
						if !required {
							continue
						}
						limit := active
						if source < 0 {
							limit = 1
						}
						for missing := 0; missing < limit; missing++ {
							current := before.clone()
							if source < 0 {
								current.masks[1] = false
							} else {
								current.writeVector(source, 64, current.vectorBytes(source)&^(uint64(1)<<uint(missing)), false)
							}
							initial := current.clone()
							if accepted, _ := x86ResultFloatingHelperStep(ins, &current, nil, arch, true); accepted || !reflect.DeepEqual(current, initial) {
								t.Fatal("helper invented a missing source/mask/merge byte or partially changed state", arch, member.name, bank, mode, source, missing)
							}
						}
					}
				}
			}
		}
	}
}

func TestX86FloatingHelperScalarPassthroughRemainsSparse(t *testing.T) {
	for _, member := range x86FloatingHelperOracleMembers() {
		if !member.scalar || member.maskResult {
			continue
		}
		ins := x86ScalarLaneInstruction(t, x86FloatingHelperOracleInstruction(member, false))
		active := 4
		if strings.HasSuffix(member.name, "SD") {
			active = 8
		}
		for missing := 0; missing < 16; missing++ {
			state := x86FloatingHelperInitializedState()
			state.writeVector(1, 64, state.vectorBytes(1)&^(uint64(1)<<uint(missing)), false)
			before := state.clone()
			accepted, known := x86ResultFloatingHelperStep(ins, &state, nil, "amd64", true)
			if member.second && missing < active {
				if accepted || !known || !reflect.DeepEqual(state, before) {
					t.Fatal("scalar arithmetic supplied a missing low second source", member.name, missing)
				}
				continue
			}
			want := before.clone()
			defined := ^uint64(0)
			if missing >= active {
				defined &^= uint64(1) << uint(missing)
			}
			want.writeVector(2, 16, defined, false)
			if !accepted || !known || !reflect.DeepEqual(state, want) {
				t.Fatal("scalar passthrough lost unknown bytes or used ignored low bytes", member.name, missing)
			}
		}
	}
}

func TestX86FloatingHelperNativeContinuationRetainsItsSourceBoundary(t *testing.T) {
	for _, member := range x86FloatingHelperOracleMembers() {
		original := x86ScalarLaneInstruction(t, x86FloatingHelperOracleInstruction(member, true))
		for _, arch := range []string{"386", "amd64"} {
			if arch == "386" && len(original.Args) > 3 {
				continue
			}
			for _, mutation := range []string{"valid", "standalone", "pointer", "numerical address", "index", "raw", "address size", "source selector"} {
				ins := original
				ins.Args = append([]Operand(nil), original.Args...)
				state := x86FloatingHelperInitializedState()
				native := true
				first := 0
				if member.immediate {
					first = 1
				}
				switch mutation {
				case "standalone":
					native = false
				case "pointer", "numerical address":
					state.pointerGP[0] = false
					if mutation == "numerical address" {
						state.gp[0] = 0xff
					}
				case "index":
					ins.Args[first].Mem.Index, ins.Args[first].Mem.Scale = DX, 2
				case "raw":
					ins.x86SourceRaw = &x86SourceRawInstruction{op: original.Op, args: original.Args}
				case "address size":
					ins.x86AddressBits = 16
				case "source selector":
					if !member.immediate {
						continue
					}
					ins.Args[0].ImmIsFloat = true
				}
				before := state.clone()
				accepted, known := x86ResultFloatingHelperStep(ins, &state, nil, arch, native)
				if mutation == "valid" {
					if !accepted || !known {
						t.Fatal("incoming native pointer lost paired helper continuation", arch, member.name)
					}
				} else if accepted || !known || !reflect.DeepEqual(state, before) {
					t.Fatal("unproved helper input granted native data or changed state", arch, member.name, mutation)
				}
			}
		}
	}
}
