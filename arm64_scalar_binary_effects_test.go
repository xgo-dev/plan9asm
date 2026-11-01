package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestARM64ScalarBinaryEveryInputByteAndNativeEffect(t *testing.T) {
	for _, operation := range arm64BinaryTestKinds {
		for _, bits := range []int{16, 32, 64} {
			for _, destination := range []Reg{"F0", "F31", "F15"} {
				for hole := -1; hole < 2*bits/8; hole++ {
					ctx, flow := arm64FlagScratchBankFixture()
					ctx.targetTriple = "aarch64-unknown-linux-gnu"
					ctx.vRegSlot = map[int]string{0: "%left", 31: "%right", 15: "%destination"}
					flow.used, flow.entry = true, &ARM64GoRegisterABI{}
					for source, register := range []string{"V0", "V31"} {
						for offset := 0; offset < bits; offset += 8 {
							if hole != source*bits/8+offset/8 {
								flow.blocks[0].effects = append(flow.blocks[0].effects, arm64MachineEffect{
									register: register, width: 8, vectorOffset: offset, vectorSpan: true, write: true,
								})
							}
						}
					}
					before, start := len(flow.blocks[0].effects), ctx.b.Len()
					form := arm64ScalarBinaryForm{arm64ScalarBinarySpec{strings.ToLower(operation.name), bits}, "F0", "F31", destination}
					if err := ctx.lowerARM64ScalarBinary(form); err != nil {
						t.Fatal(err)
					}
					ctx.recordMachineOpaqueIR(start, Instr{})
					effects := flow.blocks[0].effects[before:]
					if len(effects) != 4 || effects[0].write || effects[1].write || effects[0].width != bits || effects[1].width != bits ||
						effects[2].copyFrom != "V0" || effects[2].width != 128 || !effects[2].write || !effects[2].vectorSpan ||
						effects[3].width != bits || !effects[3].write || !effects[3].vectorSpan {
						t.Fatalf("wrong complete scalar effects: %+v", effects)
					}
					for _, effect := range effects {
						if effect.opaque || effect.store || effect.unavailable || effect.nzcv != 0 || effect.call != nil {
							t.Fatalf("scalar operation gained unrelated authority: %+v", effect)
						}
					}
					err := flow.validate()
					if hole < 0 && err != nil || hole >= 0 && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s %d hole %d destination %s: %v", operation.name, bits, hole, destination, err)
					}
					start = ctx.b.Len()
					fmt.Fprintln(ctx.b, `  call void asm sideeffect "nop", ""()`)
					ctx.recordMachineOpaqueIR(start, Instr{})
					if !flow.blocks[0].effects[len(flow.blocks[0].effects)-1].opaque {
						t.Fatal("family proof escaped its exact native instruction")
					}
				}
			}
		}
	}
}

func TestARM64ScalarBinarySparseMergeAndCFG(t *testing.T) {
	for _, bits := range []int{16, 32, 64} {
		for _, destination := range []string{"V0", "V31", "V15"} {
			state := arm64MachineState{values: make(map[string]int)}
			state.setVectorDefinition(destination, arm64MachineVectorMask(0, 128))
			want := arm64MachineVectorMask(0, bits)
			want.high = 0xff000000000000ff
			state.setVectorDefinition("V0", want)
			effect := arm64MachineEffect{register: destination, copyFrom: "V0", width: 128, vectorSpan: true, write: true}
			if err := state.applyVectorSpan(effect); err != nil {
				t.Fatal(err)
			}
			want.scalable = true
			if got := state.vectorDefinition(destination); got != want {
				t.Fatalf("sparse source identity lost: %+v != %+v", got, want)
			}
		}
		for _, complete := range []bool{false, true} {
			flow := &arm64MachineAvailability{used: true, entry: &ARM64GoRegisterABI{}, blocks: []arm64MachineBlock{
				{name: "entry", successors: []string{"left", "right"}},
				{name: "left", successors: []string{"join"}},
				{name: "right", successors: []string{"join"}},
				{name: "join"},
			}}
			for _, path := range []int{1, 2} {
				width := bits
				if complete || path == 1 {
					width = 128
				}
				flow.blocks[path].effects = []arm64MachineEffect{
					{register: "V0", width: width, write: true},
					{register: "V15", copyFrom: "V0", width: 128, write: true, vectorSpan: true},
					{register: "V15", width: bits, write: true, vectorSpan: true},
				}
			}
			flow.blocks[3].effects = []arm64MachineEffect{{register: "V15", width: 128}}
			err := flow.validate()
			if complete && err != nil || !complete && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("CFG borrowed another predecessor's upper source bits: %t %v", complete, err)
			}
		}
	}
}

func TestARM64ScalarBinaryDirectHelperContracts(t *testing.T) {
	for _, target := range []string{"", "x86_64-unknown-linux-gnu", "aarch64_be-unknown-linux-gnu"} {
		ctx, _ := arm64FlagScratchBankFixture()
		ctx.targetTriple = target
		instruction := arm64ImmediateTestInstruction(t, "FADDS F0,F1")
		known, _, err := ctx.lowerARM64ScalarFloatBinary(instruction.Op, instruction)
		if !known || !errors.Is(err, ErrProbeNeedsContext) || ctx.b.Len() != 0 {
			t.Fatalf("direct helper bypassed native target: %t %v", known, err)
		}
	}
	ctx, _ := arm64FlagScratchBankFixture()
	instruction := arm64ImmediateTestInstruction(t, "FADDS F0,F1")
	if _, known, err := parseARM64ScalarBinary("RET", instruction); known || err != nil {
		t.Fatal("typed family claimed unrelated dispatch")
	}
	if known, _, err := ctx.lowerARM64ScalarFloatBinary("FADDD", instruction); !known || err == nil || ctx.b.Len() != 0 {
		t.Fatal("source mismatch gained IR")
	}
	for _, form := range []arm64ScalarBinaryForm{
		{arm64ScalarBinarySpec{"fadd", 8}, "F0", "F1", "F2"},
		{arm64ScalarBinarySpec{"fmadd", 32}, "F0", "F1", "F2"},
		{arm64ScalarBinarySpec{"fadd", 32}, "R0", "F1", "F2"},
	} {
		if err := ctx.lowerARM64ScalarBinary(form); err == nil || errors.Is(err, ErrProbeNeedsContext) || ctx.b.Len() != 0 {
			t.Fatalf("invalid direct form gained Context or IR: %+v %v", form, err)
		}
	}
}

func TestARM64ScalarBinaryCannotInventSourceFlags(t *testing.T) {
	for _, api := range []string{"text", "module", "owned-module", "Go"} {
		for _, operation := range arm64ScalarBinaryNames {
			for _, complete := range []bool{false, true} {
				prefix := ""
				if complete {
					prefix = "CMP R0,R0\n"
				}
				source := "TEXT comparison(SB),4,$0-0\n" + prefix + "CBZ R0,use\nCMP R0,R0\nuse:\n" + operation + " F0,F1\nCSET EQ,R2\nRET\n"
				present, err := arm64BinaryTargetAPI(t, api, source, "aarch64-unknown-linux-gnu")
				if complete {
					if !present || err != nil {
						t.Fatalf("%s source flags lost across %s: %v", api, operation, err)
					}
				} else if present || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("%s %s borrowed entry/path NZCV: %t %v", api, operation, present, err)
				}
			}
		}
	}
}
