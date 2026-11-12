package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const x86ABI0BoolVoidCallSource = "TEXT ·probe(SB),4,$0-5\nCALL ·notify(SB)\nMOVL x+0(FP),AX\nTESTL AX,AX\nSETNE ret+4(FP)\nRET\nTEXT ·notify(SB),4,$0-0\nRET\n"
const x86ABI0BoolVoidCallDeclarations = "func probe(x uint32) bool\nfunc notify()\n"

func TestX86ABI0Mode32CanonicalBoolVoidCallThreeAPIs(t *testing.T) {
	for name, row := range map[string]struct {
		source, declarations string
		good                 bool
	}{
		"actual-noarg-void": {x86ABI0BoolVoidCallSource, x86ABI0BoolVoidCallDeclarations, true},
		"declared-Go-void":  {strings.Replace(x86ABI0BoolVoidCallSource, "TEXT ·notify(SB),4,$0-0\nRET\n", "", 1), x86ABI0BoolVoidCallDeclarations, true},
		"unknown-target":    {strings.Replace(x86ABI0BoolVoidCallSource, "CALL ·notify(SB)", "CALL ·unknown(SB)", 1), x86ABI0BoolVoidCallDeclarations, false},
		"nonvoid-target": {strings.Replace(x86ABI0BoolVoidCallSource, "TEXT ·notify(SB),4,$0-0\nRET", "TEXT ·notify(SB),4,$0-4\nMOVL $0,ret+0(FP)\nRET", 1),
			strings.Replace(x86ABI0BoolVoidCallDeclarations, "func notify()", "func notify() uint32", 1), false},
		"parameter-target": {strings.Replace(x86ABI0BoolVoidCallSource, "TEXT ·notify(SB),4,$0-0", "TEXT ·notify(SB),4,$0-4", 1),
			strings.Replace(x86ABI0BoolVoidCallDeclarations, "func notify()", "func notify(x uint32)", 1), false},
		"raw-result-2": {strings.Replace(x86ABI0BoolVoidCallSource, "SETNE ret+4(FP)", "MOVB $2,ret+4(FP)", 1), x86ABI0BoolVoidCallDeclarations, false},
		"stale-flags":  {strings.Replace(x86ABI0BoolVoidCallSource, "CALL ·notify(SB)\nMOVL x+0(FP),AX\nTESTL AX,AX", "MOVL x+0(FP),AX\nTESTL AX,AX\nCALL ·notify(SB)", 1), x86ABI0BoolVoidCallDeclarations, false},
		"stale-GP":     {strings.Replace(x86ABI0BoolVoidCallSource, "CALL ·notify(SB)\nMOVL x+0(FP),AX", "MOVL x+0(FP),AX\nCALL ·notify(SB)", 1), x86ABI0BoolVoidCallDeclarations, false},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(name+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, row.source, row.declarations, "386", "i386-unknown-linux-gnu", api)
				if row.good && (err != nil || ir == "") || !row.good && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
					t.Fatal("typed void CALL acquired a bool transport or retained machine state", row.good, len(ir), err)
				}
			})
		}
	}
}

func TestX86ABI0Mode32CanonicalBoolVoidCallHasNoResultOrOutgoingBytes(t *testing.T) {
	for _, domain := range []string{"caller-origin", "scan-pending", "predicate"} {
		t.Run(domain, func(t *testing.T) {
			_, state, owned := x86ABI0BoolCallDomainState(t)
			file, err := Parse(ArchAMD64, "TEXT ·caller(SB),4,$0-5\nCALL ·notify(SB)\nMOVB $1,ret+4(FP)\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			pkg := mustGoPackage(t, "voiddomains", "package voiddomains\nfunc caller(p *byte) bool\nfunc notify()\n")
			resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "386", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			source, err := prepareX86ABI0BoolCalls(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs})
			if err != nil || source == nil {
				t.Fatal("actual independent noarg void declaration lost its source", err)
			}
			plan := source.callers["·caller"]
			state.boolCalls, state.boolOutgoing, state.boolOutgoingCanonical = plan, nil, nil
			store := x86ScalarLaneInstruction(t, "MOVB $1,ret+4(FP)")
			if !x86ABI0CanonicalBoolTransfer(func(_ int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
				return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch)
			})(2, store, &state, owned, 4, "386") || !state.fp[4] || !state.canonicalFP[4] {
				t.Fatal("actual prior result byte was not independently written canonical")
			}
			switch domain {
			case "caller-origin":
				x86ABI0BoolCallDomainEffect(t, &state, owned, "MOVL p+0(FP),SI")
				x86ABI0BoolCallDomainEffect(t, &state, owned, "LEAL 7(SI),DI")
				if state.callerAddressOrigin[6] == 0 || state.callerAddressOrigin[7] == 0 {
					t.Fatal("typed pointer origin producer did not run")
				}
			case "scan-pending":
				x86ABI0BoolCallDomainEffect(t, &state, owned, "MOVL $1,AX")
				x86ABI0BoolCallDomainEffect(t, &state, owned, "BSFL AX,BX")
				if state.bitScanPending.mask == 0 {
					t.Fatal("typed pending scan producer did not run")
				}
			case "predicate":
				for _, line := range []string{"MOVL $1,AX", "MOVL AX,X0", "VPBROADCASTD X0,Y1", "VPCMPEQB Y1,Y1,Y2", "VPTEST Y2,Y2"} {
					x86ABI0BoolCallDomainEffect(t, &state, owned, line)
				}
				state = x86ResultPredicateEdge(state, x86ScalarLaneInstruction(t, "JZ zero"), 0)
				x86ABI0BoolCallDomainEffect(t, &state, owned, "VPMOVMSKB Y2,DX")
				if state.predicate.kind != x86ResultNonzeroMaskGP {
					t.Fatal("typed predicate producer did not run")
				}
			}
			before := state.clone()
			if accepted, known := x86ABI0BoolCallStep(1, file.Funcs[0].Instrs[1], &state, owned, 4, "386"); !accepted || !known {
				t.Fatal("actual declared void call was not observed")
			}
			if len(plan.bytes) != 0 || len(state.boolOutgoing) != 0 || len(state.boolOutgoingCanonical) != 0 ||
				!reflect.DeepEqual(state.fp, before.fp) || !reflect.DeepEqual(state.canonicalFP, before.canonicalFP) ||
				state.callerAddressOrigin != [16]uint16{} || state.bitScanPending != (x86ResultBitScanPending{}) || state.predicate != (x86ResultPredicate{}) ||
				state.gp != [16]uint8{} || state.canonicalGP != [16]uint8{} || state.xmm != [32]uint16{} || state.vectorUpper != [32]uint64{} ||
				state.masks != [8]bool{} || state.flags != 0 || state.pointerGP != [16]bool{} || state.callerAddressGP != [16]bool{} {
				t.Fatal("void call supplied a result/backing fact or retained unknown machine state", domain)
			}
		})
	}
}
