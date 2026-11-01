package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"testing"
)

func TestX86ABI0Mode32CanonicalBoolByteResult(t *testing.T) {
	for _, condition := range amd64RegisterBoolConditions {
		t.Run(condition, func(t *testing.T) {
			checkMode32CanonicalBool(t, "MOVL $1,AX\nTESTL AX,AX\n"+condition+" ret+0(FP)", true)
		})
	}
	for _, body := range []string{
		"MOVB $0,ret+0(FP)",
		"MOVB $1,ret+0(FP)",
		"MOVB $1,AL\nMOVB AL,ret+0(FP)",
		"MOVB $1,ret+0(FP)\nMOVB ret+0(FP),AL\nMOVB AL,ret+0(FP)",
		"MOVB $2,ret+0(FP)\nMOVBLZX ret+0(FP),AX\nTESTL AX,AX\nSETEQ ret+0(FP)",
		"MOVB $3,ret+0(FP)\nMOVBLZX ret+0(FP),AX\nTESTL AX,AX\nSETNE ret+0(FP)",
		"MOVB $2,ret+0(FP)\nMOVB $1,ret+0(FP)",
		"MOVL $2,AX\nTESTL AX,AX\nJE other\nMOVB $0,ret+0(FP)\nJMP finish\nother:\nMOVB $1,ret+0(FP)\nfinish:",
	} {
		checkMode32CanonicalBool(t, body, true)
	}
}

func TestX86ABI0Mode32BoolThreeAPIsCannotBypassCanonicalProof(t *testing.T) {
	for _, raw := range []int{2, 3, 255} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("%d/%s", raw, api), func(t *testing.T) {
				source := fmt.Sprintf("TEXT ·view(SB),4,$0-1\nMOVB $%d,ret+0(FP)\nRET\n", raw)
				ir, err := x86ScalarFPBitViewAPI(t, source, "func view() bool\n", "386", "i386-unknown-linux-gnu", api)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatal("initialized noncanonical byte escaped the no-probe bool entry guard", len(ir), err)
				}
			})
		}
	}
}

func TestX86ABI0Mode32BoolIntermediateBytesSurviveThreeAPIs(t *testing.T) {
	logicalTruncation := regexp.MustCompile(`trunc i8 [^\n]+ to i1\b`)
	for _, raw := range []int{2, 3, 255} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("%d/%s", raw, api), func(t *testing.T) {
				source := fmt.Sprintf("TEXT ·view(SB),4,$0-1\nMOVB $%d,ret+0(FP)\nMOVBLZX ret+0(FP),AX\nTESTL AX,AX\nSETNE ret+0(FP)\nRET\n", raw)
				ir, err := x86ScalarFPBitViewAPI(t, source, "func view() bool\n", "386", "i386-unknown-linux-gnu", api)
				if err != nil || ir == "" {
					t.Fatal("raw initialized byte could not be used before canonical restoration", err)
				}
				if count := len(logicalTruncation.FindAllString(ir, -1)); count != 1 {
					t.Fatal("a numeric bool-slot read/store normalized the physical byte before RET", count, ir)
				}
			})
		}
	}
}

func TestX86ABI0Mode32BoolWholeCFGAndOverwriteThreeAPIs(t *testing.T) {
	for name, row := range map[string]struct {
		body string
		good bool
	}{
		"raw-read-byte-restore":      {"MOVB $255,ret+0(FP)\nMOVB ret+0(FP),AL\nTESTB AL,AL\nSETNE ret+0(FP)", true},
		"raw-overwrite-restore":      {"MOVB $2,ret+0(FP)\nMOVB $0,ret+0(FP)", true},
		"high-byte-canonical-copy":   {"MOVB $1,AH\nMOVB AH,ret+0(FP)", true},
		"all-predecessors-canonical": {"MOVB $3,ret+0(FP)\nMOVL $1,AX\nTESTL AX,AX\nJE other\nMOVB $0,ret+0(FP)\nJMP end\nother:\nSETNE ret+0(FP)\nend:", true},
		"one-predecessor-raw":        {"MOVL $1,AX\nTESTL AX,AX\nJE other\nMOVB $1,ret+0(FP)\nJMP end\nother:\nMOVB $3,ret+0(FP)\nend:", false},
		"canonical-slot-overwritten": {"MOVB $1,ret+0(FP)\nMOVB $255,AL\nMOVB AL,ret+0(FP)", false},
		"raw-copy-is-not-canonical":  {"MOVB $2,ret+0(FP)\nMOVB ret+0(FP),AL\nMOVB AL,ret+0(FP)", false},
		"unknown-upper-byte":         {"MOVB $1,AL\nMOVB AH,ret+0(FP)", false},
		"undeclared-slot":            {"MOVB $1,ret+1(FP)\nMOVB $1,ret+0(FP)", false},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(name+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, "TEXT ·view(SB),4,$0-1\n"+row.body+"\nRET\n", "func view() bool\n", "386", "i386-unknown-linux-gnu", api)
				if row.good && (err != nil || ir == "") || !row.good && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
					t.Fatal("whole-source canonical slot/CFG gate was bypassed", row.good, len(ir), err)
				}
			})
		}
	}
}

func TestX86ABI0Mode32CanonicalBoolRoleAndSourceIdentity(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT ·entry(SB),4,$0-1\nMOVB $1,ret+0(FP)\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	fn, sig := file.Funcs[0], x86SDKLiteral386Signature()
	before, err := Parse(ArchAMD64, "TEXT ·entry(SB),4,$0-1\nMOVB $1,ret+0(FP)\nRET\n")
	if err != nil || checkX86ScalarFPResultInitialization(fn, sig, "386") != nil || !reflect.DeepEqual(file, before) {
		t.Fatal("canonical proof rewrote original Op/Raw/source identities", err)
	}
	for name, mutate := range map[string]func(*Func, *FuncSig){
		"argument":        func(_ *Func, sig *FuncSig) { sig.Args = []LLVMType{I8} },
		"arg-register":    func(_ *Func, sig *FuncSig) { sig.ArgRegs = []Reg{AX} },
		"parameter":       func(_ *Func, sig *FuncSig) { sig.Frame.Params = []FrameSlot{{Type: I8}} },
		"frame":           func(fn *Func, _ *FuncSig) { fn.FrameSize = 8 },
		"unknown-argsize": func(fn *Func, _ *FuncSig) { fn.ArgSize = -1 },
		"internal":        func(fn *Func, _ *FuncSig) { fn.Sym = "·entry<ABIInternal>" },
		"multiple-results": func(_ *Func, sig *FuncSig) {
			sig.Frame.Results = append(sig.Frame.Results, FrameSlot{Type: I1, Offset: 1})
		},
		"result-offset": func(_ *Func, sig *FuncSig) { sig.Frame.Results[0].Offset = 1 },
		"result-index":  func(_ *Func, sig *FuncSig) { sig.Frame.Results[0].Index = 1 },
		"result-field":  func(_ *Func, sig *FuncSig) { sig.Frame.Results[0].Field = 0 },
		"result-type":   func(_ *Func, sig *FuncSig) { sig.Frame.Results[0].Type = I8 },
		"wasm":          func(_ *Func, sig *FuncSig) { sig.WASMNative = true },
	} {
		t.Run(name, func(t *testing.T) {
			fn, sig := fn, sig
			sig.Frame.Results = append([]FrameSlot(nil), sig.Frame.Results...)
			mutate(&fn, &sig)
			if x86ABI0SingleByteBoolResultRole(fn, sig, "386") || !errors.Is(checkX86ScalarFPResultInitialization(fn, sig, "386"), ErrProbeNeedsContext) {
				t.Fatal("shape query borrowed a different argument/frame/result role")
			}
		})
	}
	for _, arch := range []string{"amd64", "arm", "arm64", "wasm", ""} {
		if x86ABI0SingleByteBoolResultRole(fn, sig, arch) {
			t.Fatal("386 bool byte invented another architecture's transport", arch)
		}
	}
}

func TestX86ABI0Mode32CanonicalFPCloneJoinAndBudget(t *testing.T) {
	first := x86ResultState{fp: []bool{true}, canonicalFP: []bool{true}}
	second := first.clone()
	second.canonicalFP[0] = false
	if !first.canonicalFP[0] || !second.fp[0] {
		t.Fatal("canonical clone aliased its origin or erased NUM initialization")
	}
	joined := first.intersect(second)
	if !joined.fp[0] || joined.canonicalFP[0] {
		t.Fatal("CFG join merged canonicality with NUM initialization")
	}
	if missing := first.intersect(x86ResultState{fp: []bool{true}}); missing.canonicalFP[0] {
		t.Fatal("a predecessor missing its canonical role invented a bool byte")
	}
	file, err := Parse(ArchAMD64, "TEXT ·entry(SB),4,$0-1\nMOVB $1,ret+0(FP)\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	const limit = (64 << 20) / 8
	// Ordinary state includes every independent domain, including native MMX.
	// One FP byte and its separately allocated canonical result byte each
	// count exactly once, without changing the shared limit.
	const ordinary = x86IndependentResultBasePayload + 1
	for _, room := range []int{2*(ordinary+1) - 1, 2 * (ordinary + 1)} {
		fn := file.Funcs[0]
		fn.x86ResultFlowBudget = &x86ResultFlowBudget{bytes: limit - room}
		err := checkX86ScalarFPResultInitialization(fn, x86SDKLiteral386Signature(), "386")
		visits := 0
		if room == 2*(ordinary+1) {
			visits = 2
		}
		if fn.x86ResultFlowBudget.visits != visits || fn.x86ResultFlowBudget.bytes != limit+2*(ordinary+1)-room+8*(ordinary+1)*visits {
			t.Fatal("canonical source work differs from its exact complete-state charge", fn.x86ResultFlowBudget.bytes)
		}
		if room == 2*(ordinary+1) && err != nil || room != 2*(ordinary+1) && !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("canonical FP state received unaccounted extra source work", room, err)
		}
	}
}

func TestX86ABI0Mode32BoolPreflightUsesOneBoundedWholeProof(t *testing.T) {
	for _, raw := range []int{1, 2} {
		file, err := Parse(ArchAMD64, fmt.Sprintf("TEXT ·entry(SB),4,$0-1\nMOVB $%d,ret+0(FP)\nRET\n", raw))
		if err != nil {
			t.Fatal(err)
		}
		fn := file.Funcs[0]
		fn.x86ResultFlowBudget = &x86ResultFlowBudget{}
		sig := x86SDKLiteral386Signature()
		consumer := &amd64Ctx{fpScalarSource: fn, sig: sig, fpResults: sig.Frame.Results, goarch: "386"}
		first := consumer.validateScalarFPSourceViews()
		used := *fn.x86ResultFlowBudget
		second := consumer.validateScalarFPSourceViews()
		if !consumer.fpScalarChecked || first != second || used != *fn.x86ResultFlowBudget || used.visits == 0 {
			t.Fatal("bool preflight omitted or repeated its bounded whole-source proof", first, second, used, fn.x86ResultFlowBudget)
		}
		if raw == 1 && (first != nil || !consumer.abi0BoolResultByteStorage()) || raw == 2 && (!errors.Is(first, ErrProbeNeedsContext) || consumer.abi0BoolResultByteStorage()) {
			t.Fatal("physical I8 handling was detached from canonical whole-return validation", raw, first)
		}
	}
}

func TestX86ABI0Mode32InitializedByteIsNotCanonicalBool(t *testing.T) {
	for _, value := range []int{2, 3, 255} {
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			body := fmt.Sprintf("MOVB $%d,ret+0(FP)", value)
			file, err := Parse(ArchAMD64, "TEXT ·entry(SB),4,$0-1\n"+body+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], x86SDKLiteral386Signature(), "386"); err != nil {
				t.Fatal("raw numerical byte is initialized independently of canonicality", err)
			}
			checkMode32CanonicalBool(t, body, false)
		})
	}
	for _, body := range []string{
		"MOVB $2,AL\nMOVB AL,ret+0(FP)",
		"MOVL $1,AX\nTESTL AX,AX\nSETEQ ret+0(FP)\nMOVB $2,ret+0(FP)",
		"MOVL $1,AX\nTESTL AX,AX\nJE other\nMOVB $1,ret+0(FP)\nJMP finish\nother:\nMOVB $2,ret+0(FP)\nfinish:",
		"MOVB $1,AH\nMOVB AL,ret+0(FP)",
		"MOVB $1,AL\nMOVL AX,ret+0(FP)",
		"SETEQ ret+0(FP)",
	} {
		checkMode32CanonicalBool(t, body, false)
	}
}

func checkMode32CanonicalBool(t *testing.T, body string, accepted bool) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT ·entry(SB),4,$0-1\n"+body+"\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	err = checkX86ScalarFPResultInitialization(file.Funcs[0], x86SDKLiteral386Signature(), "386")
	if accepted && err != nil || !accepted && !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("canonical bool-byte result accepted=%v body=%s: %v", accepted, body, err)
	}
}

func TestX86ABI0Mode32CanonicalFactDomainIsIndependent(t *testing.T) {
	for _, raw := range []int{0, 1, 2, 3, 255} {
		t.Run(fmt.Sprint(raw), func(t *testing.T) {
			file, err := Parse(ArchAMD64, fmt.Sprintf("TEXT ·entry(SB),4,$0-1\nMOVB $%d,ret+0(FP)\nMOVBLZX ret+0(FP),AX\nTESTL AX,AX\nSETEQ ret+0(FP)\nRET\n", raw))
			if err != nil {
				t.Fatal(err)
			}
			numeric := x86ResultState{fp: []bool{false}}
			canonicalFP, canonicalGP := []bool{false}, [16]uint8{}
			for ordinal, ins := range file.Funcs[0].Instrs[1:5] {
				if !x86ScalarFPResultTransfer(ins, &numeric, []bool{true}, 0, "386") {
					t.Fatal("independent numerical transfer did not validate the typed instruction", ins.Raw)
				}
				canonicalFP, canonicalGP = x86ABI0CanonicalBytesAfter(ins, canonicalFP, canonicalGP, "386")
				if !numeric.fp[0] || ordinal == 0 && canonicalFP[0] != (raw == 0 || raw == 1) {
					t.Fatal("canonicality changed numerical byte initialization", raw, ordinal)
				}
				lowCanonical := canonicalGP[0]&1 != 0
				if ordinal == 1 && (numeric.gp[0]&15 != 15 || lowCanonical != (raw == 0 || raw == 1) || canonicalGP[0]&240 != 0) {
					t.Fatal("FP bool-byte load invented low/high GP canonicality", raw, canonicalGP[0])
				}
			}
			if !canonicalFP[0] {
				t.Fatal("actual SETcc did not restore the canonical result after raw byte computation")
			}
		})
	}
}
