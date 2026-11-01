package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86X87ValueInstruction(t *testing.T, source string) Instr {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+source+"\nRET\n")
	if err != nil || len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) != 3 {
		t.Fatalf("invalid independent instruction fixture %q: %v", source, err)
	}
	return file.Funcs[0].Instrs[1]
}

func TestX86X87ValueCompleteGrammarAndMode(t *testing.T) {
	names := strings.Fields(`
		FMOVF FMOVFP FMOVD FMOVDP FMOVB FMOVBP FMOVX FMOVXP FXCHD FTST FSTSW
		FMOVW FMOVWP FMOVL FMOVLP FMOVV FMOVVP FRNDINT
		FLD1 FLDL2E FLDL2T FLDLG2 FLDLN2 FLDPI FLDZ FABS FCHS FSQRT
		FADDW FADDL FADDF FADDD FADDDP FMULW FMULL FMULF FMULD FMULDP
		FSUBW FSUBL FSUBF FSUBD FSUBDP FSUBRW FSUBRL FSUBRF FSUBRD FSUBRDP
		FDIVW FDIVL FDIVF FDIVD FDIVDP FDIVRW FDIVRL FDIVRF FDIVRD FDIVRDP
		FCOMW FCOMWP FCOML FCOMLP FCOMF FCOMFP FCOMD FCOMDP FCOMDPP
		FCOMI FCOMIP FUCOM FUCOMP FUCOMPP FUCOMI FUCOMIP
		FCMOVCC FCMOVCS FCMOVEQ FCMOVHI FCMOVLS FCMOVB FCMOVBE
		FCMOVNB FCMOVNBE FCMOVE FCMOVNE FCMOVNU FCMOVU FCMOVUN
	`)
	if len(names) != 88 || len(x86X87ValueSpecs) != len(names) {
		t.Fatal("complete independent x87 value-family denominator changed", len(names), len(x86X87ValueSpecs))
	}
	for _, name := range names {
		if _, exists := x86X87ValueSpecs[Op(name)]; !exists {
			t.Fatal("missing complete Go value mnemonic", name)
		}
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, source := range []string{
			"FMOVD 0(AX),F0", "FMOVD F7,F0", "FMOVD F0,F7", "FMOVD F0,F0",
			"FMOVDP F0,F7", "FMOVF 0(AX),F0", "FMOVF $(2.0),F0", "FMOVD $(2.0),F0",
			"FMOVFP F0,0(AX)", "FXCHD F0,F7", "FXCHD F7,F0", "FSTSW AX", "FSTSW 0(AX)",
			"FADDD F7,F0", "FADDD F0,F7", "FADDDP F0,F7", "FADDF $(2.0),F0",
			"FCOMD F7,F0", "FCOMDPP F0,F1", "FUCOMPP F0,F1", "FCOMI F7,F0", "FUCOMI F0,F7",
		} {
			t.Run(arch+"/"+source, func(t *testing.T) {
				_, known, err := x86X87ValueProperties(x86X87ValueInstruction(t, source), arch)
				if !known || err != nil {
					t.Fatal("complete typed Go form rejected", err)
				}
			})
		}
		for _, source := range []string{
			"FMOVD F1,F2", "FMOVD $2,F0", "FMOVF F1,F0", "FMOVFP 0(AX),F0",
			"FXCHD F1,F2", "FADDL F1,F0", "FADDDP F1,F0", "FCOMI F0,F1", "FUCOMI F1,F0",
			"FSTSW BX", "FTST F0", "FLD1 F0", "FMOVD.Z 0(AX),F0", "FMOVD 0(AX)(SP*2),F0",
		} {
			t.Run(arch+"/invalid/"+source, func(t *testing.T) {
				_, known, err := x86X87ValueProperties(x86X87ValueInstruction(t, source), arch)
				if !known || err == nil {
					t.Fatal("malformed typed form was not rejected", err)
				}
			})
		}
	}
	for _, arch := range []string{"", "arm", "arm64", "wasm"} {
		if _, known, err := x86X87ValueProperties(x86X87ValueInstruction(t, "FLD1"), arch); !known || err == nil {
			t.Fatal("typed parser inferred a missing or foreign x86 mode", arch, known, err)
		}
	}
}

// These Go rows are recognized but are not yet numerical witnesses. The reverse
// FCOMD/DP register rows and non-F1 two-pop rows have table-level botch notes;
// the existing independent byte oracle deliberately does not certify them.
func TestX86X87UnobservedEncodingRowsRetainContext(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		if target.arch != "386" {
			continue
		}
		for _, op := range []string{"FCOMD", "FCOMDP", "FCOMDPP", "FUCOMPP"} {
			for lane := 0; lane < 8; lane++ {
				pops := 0
				switch op {
				case "FCOMD", "FCOMDP":
					if lane == 0 {
						continue // F0,F0 uses the earlier ordinary register row.
					}
					if op == "FCOMDP" {
						pops = 1
					}
				default:
					if lane == 1 {
						continue // The documented two-pop dependency is exactly F0,F1.
					}
					pops = 2
				}
				instruction := fmt.Sprintf("%s F0,F%d", op, lane)
				form, known, err := x86X87ValueProperties(x86X87ValueInstruction(t, instruction), target.arch)
				if !known || err != nil || !form.unprovedEncoding {
					t.Fatal("unobserved Go row lost its explicit proof boundary", instruction, known, err)
				}
				body := strings.Repeat("FLD1\n", 8) + instruction + "\nFMOVDP F0,ret+28(FP)\n" +
					strings.Repeat("FMOVDP F0,F0\n", 7-pops)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+instruction+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, x86X87ValueSource(body), x86X87ValueDeclaration,
							target.arch, target.triple, api)
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatalf("unobserved encoding supplied a logical effect: output=%t error=%v", ir != "", err)
						}
					})
				}
			}
		}
	}
}

func TestX86X87ValueStateCloneJoinAndCallRevocation(t *testing.T) {
	f0 := Operand{Kind: OpReg, Reg: "F0"}
	for _, arch := range []string{"386", "amd64"} {
		state := x86ResultState{x87: new(x86ResultX87State)}
		step := func(source string) {
			t.Helper()
			if accepted, known := x86ResultX87ValueStep(x86X87ValueInstruction(t, source), &state, nil, 0, arch); !known || !accepted {
				t.Fatal("independent logical state transfer rejected", source, known, accepted)
			}
		}
		step("FLD1")
		step("FTST")
		step("FSTSW AX")
		if !state.x87.read(f0) || state.x87.gp[0] != 0x4500 || state.gp[0] != 0 || state.x87.status != 0 {
			t.Fatal("status capture became whole NUM or a fresh x87 status", arch, *state.x87)
		}
		copy := state.clone()
		copy.x87.slots, copy.x87.gp[0] = 0, 0
		if !state.x87.read(f0) || state.x87.gp[0] != 0x4500 {
			t.Fatal("cloned x87 state shared mutable cells", arch)
		}
		joined := state.intersect(copy)
		if joined.x87.read(f0) || joined.x87.gp[0] != 0 {
			t.Fatal("join manufactured availability or captured bits", arch)
		}
		copy.x87.depth = 0
		if joined := state.intersect(copy); !joined.x87.invalid {
			t.Fatal("different authored stack shapes joined as an empty known stack", arch)
		}
		x86ResultX87After(Instr{Op: OpCALL}, &state, arch)
		if !state.x87.invalid || state.x87.read(f0) || state.x87.gp[0] != 0 {
			t.Fatal("CALL retained availability or manufactured an empty-stack fact", arch)
		}
		if accepted, known := x86ResultX87ValueStep(x86X87ValueInstruction(t, "FLD1"), &state, nil, 0, arch); !known || accepted {
			t.Fatal("new push revived an unknown post-CALL stack shape", arch)
		}
	}
	// Exercise the existing typed CALL producer without the universal outer
	// post-transfer hook. It must independently revoke the same optional domain.
	for _, shape := range []bool{false, true} {
		plan, state, owned := x86ABI0BoolCallDomainState(t)
		state.shapeOnly = shape
		state.x87 = &x86ResultX87State{slots: 3, depth: 2, status: 0x4500, gp: [16]uint16{0x4500}}
		for ordinal := range plan.calls {
			if accepted, known := x86ABI0BoolCallStep(ordinal, plan.function.Instrs[ordinal], &state, owned, 4, "386"); !known || !accepted || !state.x87.invalid || state.x87.slots != 0 || state.x87.gp[0] != 0 {
				t.Fatal("direct typed CALL retained an independent x87 fact", shape, known, accepted, state.x87)
			}
		}
	}
}

func TestX86X87CapturedStatusRevokesOnEveryGPOverwrite(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, source := range []string{
			"MOVB BX,AL", "MOVB BX,AH", "MOVW BX,AX", "MOVL BX,AX",
			"ADDL $1,AX", "LEAL 1(AX),AX", "INCL AX", "BSFL BX,AX", "SETEQ AH",
		} {
			t.Run(arch+"/"+source, func(t *testing.T) {
				state := x86ResultState{x87: &x86ResultX87State{gp: [16]uint16{0x4500}}}
				x86ResultX87After(x86X87ValueInstruction(t, source), &state, arch)
				remaining := uint16(0)
				if source == "MOVB BX,AL" {
					remaining = 0x4500 // Only the untouched AH bits survive.
				}
				if state.x87.gp[0] != remaining {
					t.Fatal("GP overwrite retained stale captured status", source, state.x87.gp[0], remaining)
				}
			})
		}
	}
}

func TestX86X87ValueStateConsumesSharedBudgetAndPrivateRole(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\nFLD1\nFMOVDP F0,F0\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	// The complete no-FP state includes native MMX and the separate string
	// counter. This optional domain adds
	// exactly 45: slots/depth/invalid, status16, sixteen captured words and
	// eight source signed-width facts. This does not raise the shared limit.
	const payload = x86IndependentResultBasePayload + 45
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
			t.Fatal("logical x87 source work differs from its exact complete-state charge", fn.x86ResultFlowBudget.bytes)
		}
		if room == 3*payload && err != nil || room != 3*payload && !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("logical x87 state escaped or raised the existing shared budget", room, err)
		}
	}
	_, resultFile, sig, _ := x86ResultInitializationFixture(t, "386", "func Value() float64",
		"FLD1\nFMOVDP F0,ret+0(FP)\nRET")
	if err := checkX86ScalarFPResultInitialization(resultFile.Funcs[0], sig, "386"); err != nil {
		t.Fatal("private mapped result proof did not consume its own x87 value", err)
	}
	if err := CheckX86ABI0ResultInitialization(resultFile.Funcs[0], sig, "386"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("private logical effect widened the declaration-only query", err)
	}
	x86X87FloatingStoresUseOnlyCheckedByteRoles(t)
}

func TestX86X87LegacyDirectHelperBindsDispatchAndDefaultMode(t *testing.T) {
	var body strings.Builder
	fn := Func{Instrs: []Instr{{Op: "FLD1"}}}
	consumer := newAMD64Ctx(&body, fn, FuncSig{Name: "Value", Ret: Void}, testResolveSym("example"), nil, false)
	if err := consumer.emitEntryAllocas(); err != nil {
		t.Fatal(err)
	}
	consumer.goarch = "" // Old private direct-helper callers used the default mode.
	if known, terminated, err := consumer.lowerX87("FLD1", Instr{Raw: "FLD1"}); !known || terminated || err != nil {
		t.Fatal("legacy private default-mode dispatch was lost", known, terminated, err)
	}
	if known, _, err := consumer.lowerX87("FLD1", Instr{Op: "FLDZ", Raw: "FLDZ"}); !known || err == nil {
		t.Fatal("conflicting dispatch/source heads acquired a typed form", known, err)
	}
}
