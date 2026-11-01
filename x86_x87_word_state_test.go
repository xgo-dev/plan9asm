package plan9asm

import (
	"errors"
	"testing"
)

func TestX86X87WordCompleteTypedGrammar(t *testing.T) {
	if len(x86X87WordSpecs) != 5 {
		t.Fatal("complete Go init/clear/word denominator changed")
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, source := range []string{
			"FINIT", "FCLEX", "FSTCW (AX)", "FSTSW (AX)", "FSTSW AX", "FLDCW (AX)",
			"FSTCW input+0(FP)", "FSTSW -2(SP)", "FLDCW ·control(SB)",
			"FSTCW -7(BX)(CX*4)", "FSTSW -7(BX)(CX*4)", "FLDCW -7(BX)(CX*4)",
		} {
			t.Run(arch+"/valid/"+source, func(t *testing.T) {
				if _, known, err := x86X87WordProperties(x86X87ValueInstruction(t, source), arch); !known || err != nil {
					t.Fatal("complete typed Go word form rejected", known, err)
				}
			})
		}
		for _, source := range []string{
			"FINIT AX", "FCLEX AX", "FSTCW AX", "FSTSW BX", "FLDCW AX",
			"FSTCW", "FSTSW", "FLDCW", "FINIT.Z", "FCLEX.Z", "FSTSW.Z AX",
			"FSTCW $0", "FLDCW $0", "FSTSW 0(AX)(SP*2)",
		} {
			t.Run(arch+"/invalid/"+source, func(t *testing.T) {
				if _, known, err := x86X87WordProperties(x86X87ValueInstruction(t, source), arch); !known || err == nil {
					t.Fatal("malformed word row was not rejected", known, err)
				}
			})
		}
	}
	for _, arch := range []string{"", "arm", "arm64", "wasm"} {
		if _, known, err := x86X87WordProperties(x86X87ValueInstruction(t, "FINIT"), arch); !known || err == nil {
			t.Fatal("word parser inferred a missing or foreign x86 mode", arch, known, err)
		}
	}
	for _, source := range []string{"FNINIT", "FNCLEX", "FLDENV (AX)", "WAIT"} {
		if _, known, _ := x86X87WordProperties(x86X87ValueInstruction(t, source), "amd64"); known {
			t.Fatal("separate named/raw/environment family entered the word descriptor", source)
		}
	}
}

func TestX86X87WordStateKnownBitsAliasesAndCallRevocation(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		layout := &x86X87WordLayout{parameters: map[int64]bool{0: true}}
		state := x86ResultState{x87: &x86ResultX87State{
			slots: 3, depth: 2, status: 0x4500,
			word: &x86ResultX87WordState{layout: layout},
		}}
		step := func(source string) {
			t.Helper()
			if accepted, known := x86ResultX87ValueStep(x86X87ValueInstruction(t, source), &state, nil, 0, arch); !known || !accepted {
				t.Fatal("independent word transfer rejected", arch, source, known, accepted)
			}
		}
		step("FCLEX")
		if state.x87.status != 0xc5ff || state.x87.word.control != 0 || state.x87.slots != 3 || state.x87.depth != 2 {
			t.Fatal("FCLEX invented control, TOP, condition or stack facts", arch, *state.x87)
		}
		step("FINIT")
		if state.x87.status != 0xffff || state.x87.word.control != 0xffff || state.x87.slots != 0 || state.x87.depth != 0 {
			t.Fatal("FINIT failed to define its words while leaving all x87 values unavailable", arch, *state.x87)
		}
		copy := state.clone()
		copy.x87.word.control, copy.x87.status = 0x00ff, 0x80ff
		if state.x87.word.control != 0xffff || state.x87.status != 0xffff || copy.x87.word.layout != layout {
			t.Fatal("word clone shared mutable state or lost its actual layout", arch)
		}
		joined := state.intersect(copy)
		if joined.x87.invalid || joined.x87.word.control != 0x00ff || joined.x87.status != 0x80ff {
			t.Fatal("word join manufactured known bits", arch)
		}
		copy.x87.word.layout = &x86X87WordLayout{parameters: map[int64]bool{0: true}}
		if joined := state.intersect(copy); !joined.x87.invalid {
			t.Fatal("equal-looking foreign layouts acquired the original word role", arch)
		}
		for _, bits := range []uint16{0, 0x00ff, 0xff00, 0x4500, 0x80ff, 0xffff} {
			state.x87.status = bits
			state.gp[0], state.canonicalGP[0] = 0xff, 0xff
			state.pointerGP[0], state.callerAddressGP[0] = true, true
			state.callerAddressOrigin[0] = 1
			state.resultAddressGP[0] = x86ResultSlotAddress{valid: true}
			state.boolFrameGP = new([16]x86ResultSlotAddress)
			state.boolFrameGP[0] = x86ResultSlotAddress{valid: true}
			state.flags, state.direction = x86ByteFlagsAll, x86ResultDirectionForward
			step("FSTSW AX")
			want := uint8(0xfc)
			if bits&0xff == 0xff {
				want |= 1
			}
			if bits&0xff00 == 0xff00 {
				want |= 2
			}
			if state.gp[0] != want || state.canonicalGP[0] != 0xfc || state.x87.gp[0] != bits ||
				state.x87.status != 0 || state.pointerGP[0] || state.callerAddressGP[0] ||
				state.callerAddressOrigin[0] != 0 || state.resultAddressGP[0].valid || state.boolFrameGP[0].valid ||
				state.flags != x86ByteFlagsAll || state.direction != x86ResultDirectionForward {
				t.Fatal("status capture manufactured bytes/roles or changed unwritten state", arch, bits)
			}
		}
		x86ResultX87After(Instr{Op: OpCALL}, &state, arch)
		if !state.x87.invalid || state.x87.word == nil || state.x87.word.control != 0 ||
			state.x87.word.layout != layout || state.x87.status != 0 || state.x87.gp[0] != 0 {
			t.Fatal("outer CALL retained hardware facts or erased immutable argument layout", arch)
		}
		step("FINIT")
		if state.x87.invalid || state.x87.depth != 0 || state.x87.slots != 0 || state.x87.status != 0xffff ||
			state.x87.word.control != 0xffff || state.x87.word.layout != layout {
			t.Fatal("FINIT failed to restore empty shape and words without inventing an F0 value", arch)
		}
	}
	// The direct typed CALL consumer must revoke without relying on After.
	for _, shape := range []bool{false, true} {
		plan, state, owned := x86ABI0BoolCallDomainState(t)
		state.shapeOnly = shape
		layout := &x86X87WordLayout{parameters: map[int64]bool{}}
		state.x87 = &x86ResultX87State{status: 0xffff, word: &x86ResultX87WordState{control: 0xffff, layout: layout}}
		for ordinal := range plan.calls {
			if accepted, known := x86ABI0BoolCallStep(ordinal, plan.function.Instrs[ordinal], &state, owned, 4, "386"); !known || !accepted {
				t.Fatal("independently closed typed CALL no longer accepted", shape, known, accepted)
			}
			if !state.x87.invalid || state.x87.word == nil || state.x87.word.control != 0 ||
				state.x87.word.layout != layout || state.x87.status != 0 {
				t.Fatal("direct typed CALL retained hardware facts or erased immutable source layout", shape)
			}
		}
	}
}

func TestX86X87WordStateConsumesSharedBudgetAndPrivateRole(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\nFINIT\nFCLEX\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	// Complete no-FP state, logical x87 payload45 and two-byte control
	// knownness remain independently charged. Immutable layout metadata
	// is not a CFG copy.
	const payload = x86IndependentResultBasePayload + 45 + 2
	const limit = (64 << 20) / 8
	for _, room := range []int{3*payload - 1, 3 * payload} {
		fn := file.Funcs[0]
		fn.x86ResultFlowBudget = &x86ResultFlowBudget{bytes: limit - room}
		err := checkX86ScalarFPResultInitialization(fn, FuncSig{Name: "Value", Ret: Void}, "386")
		visits := 0
		if room == 3*payload {
			visits = 3
		}
		if fn.x86ResultFlowBudget.visits != visits || fn.x86ResultFlowBudget.bytes != limit+3*payload-room+8*payload*visits {
			t.Fatal("word source work differs from its exact complete-state charge", fn.x86ResultFlowBudget.bytes)
		}
		if room == 3*payload && err != nil || room != 3*payload && !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("initialized word state escaped or raised the existing shared budget", room, err)
		}
	}
	_, resultFile, sig, _ := x86ResultInitializationFixture(t, "386", "func Value() uint16", "FINIT\nFSTSW ret+0(FP)\nRET")
	if err := checkX86ScalarFPResultInitialization(resultFile.Funcs[0], sig, "386"); err != nil {
		t.Fatal("private word result did not consume its explicit initializer", err)
	}
	if err := CheckX86ABI0ResultInitialization(resultFile.Funcs[0], sig, "386"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("private word effect widened the declaration-only result query", err)
	}
}
