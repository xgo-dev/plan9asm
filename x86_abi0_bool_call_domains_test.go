package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86ABI0BoolCallDomainState(t *testing.T) (*x86ABI0BoolCallPlan, x86ResultState, []bool) {
	t.Helper()
	source := x86ABI0BoolCallAssembly("MOVB $1,0(SP)\nCALL ·callee(SB)\nMOVB 4(SP),AX\nMOVB AX,ret+4(FP)", x86ABI0BoolCallLeaf)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "calldomains", "package calldomains\nfunc caller(p *byte) bool\nfunc callee(x bool) bool\n")
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "386", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := prepareX86ABI0BoolCalls(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	plan := observed.callers["·caller"]
	sig := sigs["caller"]
	state := x86ResultState{fp: make([]bool, 5), canonicalFP: make([]bool, 5), pointerFP: make(map[int64]bool),
		boolCalls: plan, boolOutgoing: make([]bool, 5), boolOutgoingCanonical: make([]bool, 5),
		boolFrameSlots: append(append([]FrameSlot(nil), sig.Frame.Params...), sig.Frame.Results...)}
	owned := make([]bool, 5)
	for _, slot := range sig.Frame.Params {
		if slot.Type != Ptr {
			t.Fatal("fixture lost its actual declared pointer role")
		}
		state.pointerFP[slot.Offset] = true
		for i := int64(0); i < x86FrameScalarBytes(slot.Type, "386"); i++ {
			owned[slot.Offset+i] = true
		}
	}
	owned[sig.Frame.Results[0].Offset] = true
	state.callerAddressFP = state.pointerFP
	store := x86ScalarLaneInstruction(t, "MOVB $1,0(SP)")
	if accepted, known := x86ABI0BoolCallStep(1, store, &state, owned, 4, "386"); !accepted || !known {
		t.Fatal("actual outgoing parameter was not written")
	}
	return plan, state, owned
}

// Replay the existing independent typed producer and its existing after-effect
// observations. No invented GP, vector, flag or native-entry fact seeds these
// domains. The actual pointer slot remains opaque/non-numerical.
func x86ABI0BoolCallDomainEffect(t *testing.T, state *x86ResultState, owned []bool, line string) Instr {
	t.Helper()
	ins := x86ScalarLaneInstruction(t, line)
	addresses, origins, predicate := state.callerAddressGP, state.callerAddressOrigin, state.predicate
	if !x86ScalarFPResultTransfer(ins, state, owned, 4, "386") {
		t.Fatal("actual typed producer failed", line)
	}
	state.callerAddressGP = x86ResultCallerAddressesAfter(ins, addresses, state.callerAddressFP, "386")
	state.callerAddressOrigin = x86ResultCallerOriginsAfter(ins, origins, state.callerAddressGP, state.callerAddressFP, "386")
	state.predicate = x86ResultPredicateAfter(ins, predicate, "386")
	return ins
}

func TestX86ABI0Mode32CanonicalBoolCallRevokesAllDerivedDomains(t *testing.T) {
	for _, domain := range []string{"caller-origin", "scan-pending", "predicate"} {
		t.Run(domain, func(t *testing.T) {
			plan, state, owned := x86ABI0BoolCallDomainState(t)
			switch domain {
			case "caller-origin":
				x86ABI0BoolCallDomainEffect(t, &state, owned, "MOVL p+0(FP),SI")
				x86ABI0BoolCallDomainEffect(t, &state, owned, "LEAL 7(SI),DI")
				if state.callerAddressOrigin[6] != 1 || state.callerAddressOrigin[7] != 1 || state.gp[6] != 0 || state.gp[7] != 0 {
					t.Fatal("actual opaque pointer origin was not independently derived")
				}
			case "scan-pending":
				x86ABI0BoolCallDomainEffect(t, &state, owned, "MOVL $1,AX")
				x86ABI0BoolCallDomainEffect(t, &state, owned, "BSFL AX,BX")
				if state.bitScanPending.mask == 0 || state.gp[3] != 0 {
					t.Fatal("pending scan was not tied to an actual unknown destination")
				}
			case "predicate":
				for _, line := range []string{"MOVL $1,AX", "MOVL AX,X0", "VPBROADCASTD X0,Y1", "VPCMPEQB Y1,Y1,Y2", "VPTEST Y2,Y2"} {
					x86ABI0BoolCallDomainEffect(t, &state, owned, line)
				}
				branch := x86ScalarLaneInstruction(t, "JZ zero")
				state = x86ResultPredicateEdge(state, branch, 0)
				x86ABI0BoolCallDomainEffect(t, &state, owned, "VPMOVMSKB Y2,DX")
				if state.predicate.kind != x86ResultNonzeroMaskGP || state.predicate.register != 2 || state.predicate.width != 32 {
					t.Fatal("typed comparison/test/edge/movemask did not produce its actual bounded relation")
				}
			}
			before := state.clone()
			var ordinal int
			for index := range plan.calls {
				ordinal = index
			}
			if accepted, known := x86ABI0BoolCallStep(ordinal, plan.function.Instrs[ordinal], &state, owned, 4, "386"); !accepted || !known {
				t.Fatal("actual canonical bool CALL was not accepted")
			}
			if state.callerAddressOrigin != [16]uint16{} || state.bitScanPending != (x86ResultBitScanPending{}) || state.predicate != (x86ResultPredicate{}) {
				t.Fatal("CALL retained a derived domain after revoking its machine inputs", domain, state.callerAddressOrigin, state.bitScanPending, state.predicate)
			}
			if state.callerAddressFP[0] != before.callerAddressFP[0] || !state.boolOutgoing[0] || !state.boolOutgoingCanonical[0] || !state.boolOutgoing[4] || !state.boolOutgoingCanonical[4] {
				t.Fatal("domain revoke erased actual readonly entry/parameter or declared result")
			}
		})
	}
}

func TestX86ABI0Mode32CanonicalBoolCallDerivedDomainsThreeAPIs(t *testing.T) {
	const vector = "MOVL $1,AX\nMOVL AX,X0\nVPBROADCASTD X0,Y1\nVPCMPEQB Y1,Y1,Y2\nVPTEST Y2,Y2\nJZ zero\n"
	for name, row := range map[string]struct {
		body, declaration string
		good              bool
	}{
		"stale-origin":           {"MOVB $1,0(SP)\nMOVL p+0(FP),SI\nLEAL 7(SI),DI\nCALL ·callee(SB)\nSUBL SI,DI\nTESTL DI,DI\nSETNE ret+4(FP)", "func caller(p *byte) bool", false},
		"fresh-origin":           {"MOVB $1,0(SP)\nMOVL p+0(FP),SI\nLEAL 7(SI),DI\nCALL ·callee(SB)\nMOVL p+0(FP),SI\nLEAL 7(SI),DI\nSUBL SI,DI\nTESTL DI,DI\nSETNE ret+4(FP)", "func caller(p *byte) bool", true},
		"stale-pending-flags":    {"MOVB $1,0(SP)\nMOVL $1,AX\nBSFL AX,BX\nCALL ·callee(SB)\nJZ zero\nTESTL BX,BX\nSETNE ret+4(FP)\nRET\nzero:\nMOVB $0,ret+4(FP)", "func caller(x bool) bool", false},
		"fresh-scan":             {"MOVB $1,0(SP)\nMOVL $1,AX\nBSFL AX,BX\nCALL ·callee(SB)\nMOVL $1,AX\nBSFL AX,BX\nJZ zero\nTESTL BX,BX\nSETNE ret+4(FP)\nRET\nzero:\nMOVB $0,ret+4(FP)", "func caller(x bool) bool", true},
		"stale-predicate-vector": {"MOVB $1,0(SP)\n" + vector + "CALL ·callee(SB)\nVPMOVMSKB Y2,DX\nBSFL DX,BX\nTESTL BX,BX\nSETNE ret+4(FP)\nRET\nzero:\nMOVB $0,ret+4(FP)", "func caller(x bool) bool", false},
		"fresh-predicate":        {"MOVB $1,0(SP)\nCALL ·callee(SB)\n" + vector + "VPMOVMSKB Y2,DX\nBSFL DX,BX\nTESTL BX,BX\nSETNE ret+4(FP)\nRET\nzero:\nMOVB $0,ret+4(FP)", "func caller(x bool) bool", true},
		"unknown-call-target":    {strings.Replace(x86ABI0BoolCallBody, "CALL ·callee(SB)", "CALL AX", 1), "func caller(x bool) bool", false},
		"native-call-target":     {strings.Replace(x86ABI0BoolCallBody, "CALL ·callee(SB)", "CALL ·callee<ABIInternal>(SB)", 1), "func caller(x bool) bool", false},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(fmt.Sprintf("%s/%s", name, api), func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, x86ABI0BoolCallAssembly(row.body, x86ABI0BoolCallLeaf), row.declaration+"\nfunc callee(x bool) bool\n", "386", "i386-unknown-linux-gnu", api)
				if row.good && (err != nil || ir == "") || !row.good && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
					t.Fatal("actual stale/fresh CALL domain boundary", row.good, len(ir), err)
				}
			})
		}
	}
}
