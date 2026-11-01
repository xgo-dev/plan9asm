package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func x86RawLegacyFloatCompareState() x86ResultState {
	state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
	state.pointerGP[0], state.pointerGP[3], state.callerAddressGP[0] = true, true, true
	state.gp[1], state.masks[7] = 0xff, true
	state.valueStack = &x86ResultValueStack{bytes: []uint8{0xff, 0xa5, 0x5a, 0xff, 0xff, 0xff, 0xff, 0xff}, id: true}
	state.writeVector(0, 64, ^uint64(0), false)
	state.writeVector(1, 64, ^uint64(0), false)
	return state
}

func TestX86RawLegacyFloatingCompareEveryByteAndIndependentState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86RawLegacyFloatCompareOracles {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				for _, memory := range []bool{false, true} {
					ins := x86RawMoveObservedInstruction(t, arch, row.code(memory, 255))
					for input := 0; input < 2; input++ {
						for missing := -1; missing < 64; missing++ {
							state := x86RawLegacyFloatCompareState()
							if missing >= 0 {
								state.writeVector(input, 64, ^(uint64(1) << uint(missing)), false)
							}
							before, want := state.clone(), state.clone()
							accept := missing < 0 || missing >= row.input || memory && input == 1
							if accept {
								want.writeVector(0, 16, before.vectorBytes(0)|x86CallerVectorByteMask(int64(row.input)), true)
							}
							accepted, known := x86ResultFloatCompareStep(ins, &state, nil, arch, true)
							if !known || accepted != accept || !reflect.DeepEqual(state, want) {
								t.Fatal("raw compare lost a required input, preserved unknown byte or independent state", memory, input, missing, accepted)
							}
						}
					}
					if memory {
						state := x86RawLegacyFloatCompareState()
						state.pointerGP[3], state.gp[3] = false, 0xff
						before := state.clone()
						if accepted, known := x86ResultFloatCompareStep(ins, &state, nil, arch, true); !known || accepted || !reflect.DeepEqual(state, before) {
							t.Fatal("numerical address acquired incoming pointer identity")
						}
					}
					if !x86ResultPreservesPrivateStorage(ins, arch) ||
						x86ResultDirectionAfterSource(ins, x86ResultDirectionBackward, arch) != x86ResultDirectionBackward ||
						x86ResultCallerAddressesAfter(ins, [16]bool{true}, nil, arch) != [16]bool{true} ||
						x86PreservesNumericalSourceState(ins) {
						t.Fatal("data-changing compare lost independent controls or became an inert instruction")
					}
				}
			})
		}
	}
}

func TestX86RawLegacyFloatingCompareRejectsEditedIdentityAtomically(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86RawLegacyFloatCompareOracles {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				original := x86RawMoveObservedInstruction(t, arch, row.code(true, 128))
				for _, control := range []struct {
					name string
					edit func(*Instr)
				}{
					// This is an encoded instruction without a source witness,
					// not an origin-only mutation. Legacy decoding does not set
					// x86Encoded; erasing only origin can look exactly named.
					{"unbound-encoded", func(ins *Instr) { ins.x86SourceRaw, ins.x86Encoded = nil, true }},
					{"snapshot", func(ins *Instr) { ins.x86SourceRaw.legacyFloatCompare = x86RawLegacyFloatCompareIdentity{} }},
					{"mode", func(ins *Instr) { ins.x86SourceRaw.legacyFloatCompare.arch = "arm64" }},
					{"generation", func(ins *Instr) { ins.x86Encoded = !ins.x86Encoded }},
					{"opcode", func(ins *Instr) {
						ins.Op = "CMPPS"
						if row.op == "CMPPS" {
							ins.Op = "CMPPD"
						}
					}},
					{"selector", func(ins *Instr) { ins.Args[2].Imm++ }},
					{"destination", func(ins *Instr) { ins.Args[1].Reg = "X2" }},
					{"memory", func(ins *Instr) { ins.Args[0].Mem.Off++ }},
					{"origin-selector", func(ins *Instr) { ins.x86SourceRaw.args[2].Imm++ }},
					{"width", func(ins *Instr) { ins.x86VectorBytes += 16 }},
					{"address-width", func(ins *Instr) { ins.x86AddressBits = 16 }},
					{"address-override", func(ins *Instr) { ins.x86UnboundAddressOverride = true }},
					{"segment", func(ins *Instr) { ins.x86SegmentPrefix = 0x64 }},
					{"literal", func(ins *Instr) { ins.x86RIPLiteral = true }},
					{"return", func(ins *Instr) { ins.x86RawNearReturn = new(x86RawNearReturnForm) }},
					{"numerical-read", func(ins *Instr) { ins.x86NumericalRead = new(x86NumericalReadCertificate) }},
				} {
					t.Run(control.name, func(t *testing.T) {
						changed := cloneX86ReplayInstrs([]Instr{original})[0]
						control.edit(&changed)
						state := x86RawLegacyFloatCompareState()
						before := state.clone()
						if accepted, _ := x86ResultFloatCompareStep(changed, &state, nil, arch, true); accepted ||
							x86RawLegacyFloatCompareSource(changed, arch) || !reflect.DeepEqual(state, before) {
							t.Fatal("changed raw identity acquired numerical input, native or independent DATA permission", control.name)
						}
					})
				}
				if !x86RawLegacyFloatCompareSource(original, arch) {
					t.Fatal("editing a mutable clone corrupted the immutable original mode snapshot")
				}
			})
		}
	}
}

func TestX86RawLegacyFloatingCompareNeedsWholeReplayAndActualInputs(t *testing.T) {
	for _, row := range x86RawLegacyFloatCompareOracles {
		for _, memory := range []bool{false, true} {
			t.Run(row.op+"/memory="+map[bool]string{false: "false", true: "true"}[memory], func(t *testing.T) {
				prefix := "TEXT ·Value(SB),4,$0-8\nMOVQ p+0(FP),BX\nPXOR X0,X0\nPXOR X1,X1\n"
				source := prefix + x86RawDisplacementDirectives(row.code(memory, 8)) + "RET\n"
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *byte)", "amd64", "x86_64-unknown-linux-gnu", api); ir == "" || err != nil {
						t.Fatal("initialized Void compare lost its original dead native exception effect", api, err)
					}
					for _, producer := range []string{"PXOR X0,X0\n", "PXOR X1,X1\n", "MOVQ p+0(FP),BX\n"} {
						if memory && producer == "PXOR X1,X1\n" || !memory && producer == "MOVQ p+0(FP),BX\n" {
							continue
						}
						changed := strings.Replace(source, producer, "", 1)
						if ir, err := x86ScalarFPBitViewAPI(t, changed, "func Value(p *byte)", "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("dead or reserved-selector compare borrowed a missing native input", producer, api, err)
						}
					}
				}
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), "amd64")
				if err != nil || file.Funcs[0].x86RawReplay == nil {
					t.Fatal("original raw source lost immutable whole replay", err)
				}
				original := file.Funcs[0]
				if err := original.x86RawReplay.validate(original, "amd64"); err != nil {
					t.Fatal("original replay did not bind its ordinary producers", err)
				}
				changed := original
				changed.Instrs = cloneX86ReplayInstrs(original.Instrs)
				changed.Instrs[2].Op = "XORPS" // Equivalent zero producer, different original source.
				if changed.x86RawReplay.validate(changed, "amd64") == nil || original.x86RawReplay.validate(original, "amd64") != nil {
					t.Fatal("rewritten producer borrowed or mutated the original immutable source replay")
				}
				// validate alone only tests the private replay object. Exercise
				// the actual whole-Func consumer that must enforce this identity.
				check := x86LegacyFloatReplayCheck(t, "amd64", source, "func Value(p *byte)")
				if check(original) != nil || !errors.Is(check(changed), ErrProbeNeedsContext) {
					t.Fatal("actual lowering consumer failed to retain its original complete-source replay restriction")
				}
			})
		}
	}
}
