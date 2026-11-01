package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ResultCallerAddressDifferenceCancelsSameTypedOrigin(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, typ, move, lea, add, sub := 8, "uint64", "MOVQ", "LEAQ", "ADDQ", "SUBQ"
		if arch == "386" {
			word, typ, move, lea, add, sub = 4, "uint32", "MOVL", "LEAL", "ADDL", "SUBL"
		}
		for name, middle := range map[string]string{
			"copy":                     move + " SI,DI",
			"constant affine":          lea + " 17(SI),DI",
			"numerical affine":         lea + " -16(SI)(AX*1),DI",
			"numerical delta":          move + " SI,DI\n" + add + " AX,DI",
			"numerical negative delta": move + " SI,DI\n" + sub + " AX,DI",
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				body := fmt.Sprintf("%s p+0(FP),SI\n%s n+%d(FP),AX\n%s\n%s SI,DI\n%s DI,ret+%d(FP)\nRET", move, move, word, middle, sub, move, 2*word)
				_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(p *byte,n "+typ+") "+typ, body)
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					if err := check(file.Funcs[0], sig, arch); err != nil {
						t.Fatal("same actual input origin did not cancel", err)
					}
				}
			})
		}
	}
}

func TestX86ResultCallerAddressDifferenceUnknownOrMixedOriginsRemainContext(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, typ, move, sub := 8, "uint64", "MOVQ", "SUBQ"
		if arch == "386" {
			word, typ, move, sub = 4, "uint32", "MOVL", "SUBL"
		}
		for name, middle := range map[string]string{
			"different typed pointer field":               fmt.Sprintf("%s q+%d(FP),DI", move, word),
			"literal pointer bits":                        move + " $8,DI",
			"partial overwrite":                           move + " SI,DI\nMOVB $0,DI",
			"same origin only on one edge":                move + " SI,DI\nCMP" + strings.TrimPrefix(move, "MOV") + " AX,$0\nJZ joined\n" + fmt.Sprintf("%s q+%d(FP),DI\njoined:", move, word),
			"vector transport is not an address identity": move + " SI,DI\nMOVL DI,X0\nMOVL X0,DI",
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				body := fmt.Sprintf("%s p+0(FP),SI\n%s n+%d(FP),AX\n%s\n%s SI,DI\n%s DI,ret+%d(FP)\nRET", move, move, 2*word, middle, sub, move, 3*word)
				_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value(p,q *byte,n "+typ+") "+typ, body)
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					if err := check(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("pointer bits acquired numerical subtraction", err)
					}
				}
			})
		}
	}
}

func TestX86ResultCallerAddressDifferenceThreeAPIWholeSourceAdmission(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, typ, move, lea, sub, triple := 8, "uint64", "MOVQ", "LEAQ", "SUBQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, typ, move, lea, sub, triple = 4, "uint32", "MOVL", "LEAL", "SUBL", "i386-unknown-linux-gnu"
		}
		declaration := "func Value(p,q *byte,n " + typ + ") " + typ + "\n"
		for _, sameOrigin := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/same%t", arch, sameOrigin), func(t *testing.T) {
				middle := fmt.Sprintf("%s q+%d(FP),DI", move, word)
				if sameOrigin {
					middle = lea + " -16(SI)(AX*1),DI"
				}
				body := fmt.Sprintf("%s p+0(FP),SI\n%s n+%d(FP),AX\n%s\n%s SI,DI\n%s DI,ret+%d(FP)\nRET", move, move, 2*word, middle, sub, move, 3*word)
				_, file, sig, source := x86ResultInitializationFixture(t, arch, strings.TrimSpace(declaration), body)
				for _, ins := range file.Funcs[0].Instrs {
					if ins.Op == Op(sub) && !x86ResultCallerAddressDifferenceNeedsProof(ins, sig, arch) {
						t.Fatal("actual pointer result bypassed the complete-source cost predicate")
					}
				}
				ctx := newX86Ctx(new(strings.Builder), file.Funcs[0], sig,
					func(symbol string) string { return strings.TrimPrefix(symbol, "·") }, nil, arch, triple, false)
				proofErr := ctx.checkLoweredScalarFPResultInitialization()
				if sameOrigin && proofErr != nil || !sameOrigin && !errors.Is(proofErr, ErrProbeNeedsContext) {
					t.Fatal("paired source proof disagrees with the actual input origins", sameOrigin, proofErr)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if sameOrigin {
							if err != nil || ir == "" {
								t.Fatal("same-origin numerical difference rejected", err)
							}
						} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("unrelated pointer fields bypassed complete result proof", len(ir), err)
						}
					})
				}
			})
		}
	}
}

func TestX86ResultCallerAddressDifferenceCFGAndRevocation(t *testing.T) {
	for _, fixture := range []struct {
		name, body string
		pass       bool
	}{
		{"same origin different offsets", "CMPQ AX,$0\nJZ alternate\nLEAQ 8(SI),DI\nJMP joined\nalternate:\nLEAQ 16(SI),DI\njoined:", true},
		{"different origin join", "CMPQ AX,$0\nJZ alternate\nLEAQ 8(SI),DI\nJMP joined\nalternate:\nMOVQ q+8(FP),DI\njoined:", false},
		{"loop preserves only original input", "MOVQ SI,DI\nloop:\nADDQ $1,DI\nSUBQ $1,AX\nJNZ loop", true},
		{"loop imports another input", "MOVQ SI,DI\nloop:\nMOVQ q+8(FP),DI\nSUBQ $1,AX\nJNZ loop", false},
		{"partial source overwrite", "MOVQ SI,DI\nMOVB $0,SI", false},
		{"difference is not an address", "MOVQ SI,DI\nSUBQ SI,DI\nLEAQ 8(DI),DI", false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			body := "MOVQ p+0(FP),SI\nMOVQ n+16(FP),AX\n" + fixture.body + "\nSUBQ SI,DI\nMOVQ DI,ret+24(FP)\nRET"
			_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(p,q *byte,n uint64) uint64", body)
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				err := check(file.Funcs[0], sig, "amd64")
				if fixture.pass && err != nil || !fixture.pass && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("CFG retained a stale or foreign input origin", fixture.pass, err)
				}
			}
		})
	}
}

func TestX86ResultCallerAddressOriginIsBoundedIndependentMustState(t *testing.T) {
	state := x86ResultState{}
	state.callerAddressGP[3], state.callerAddressGP[6] = true, true
	state.callerAddressOrigin[3], state.callerAddressOrigin[6] = 1, 1
	other := state.clone()
	other.callerAddressOrigin[3] = 9
	if state.callerAddressOrigin[3] != 1 || state.intersect(other).callerAddressOrigin[3] != 0 || state.intersect(state).callerAddressOrigin[3] != 1 {
		t.Fatal("origin clone or must-intersection aliases another state")
	}
	other = state.clone()
	other.callerAddressGP[3] = false
	if state.intersect(other).callerAddressOrigin[3] != 0 {
		t.Fatal("origin survived loss of independently proved address role")
	}
	if size := len(state.callerAddressOrigin) * 2; size != 32 {
		t.Fatal("unbounded or changed origin state payload", size)
	}
	ins := x86ScalarLaneInstruction(t, "SUBQ SI,BX")
	for name, mutate := range map[string]func(*Instr, *x86ResultState){
		"different origin": func(_ *Instr, s *x86ResultState) { s.callerAddressOrigin[3] = 9 },
		"missing origin":   func(_ *Instr, s *x86ResultState) { s.callerAddressOrigin[3] = 0 },
		"encoded effect":   func(i *Instr, _ *x86ResultState) { i.x86Encoded = true },
		"address override": func(i *Instr, _ *x86ResultState) { i.x86AddressBits = 32 },
		"segment":          func(i *Instr, _ *x86ResultState) { i.x86SegmentPrefix = 0x64 },
	} {
		t.Run(name, func(t *testing.T) {
			local, next := ins, state.clone()
			mutate(&local, &next)
			before := next.clone()
			accepted, known := x86ResultCallerAddressDifferenceStep(local, &next, "amd64")
			if accepted || !known || next.callerAddressOrigin != before.callerAddressOrigin || next.gp != before.gp {
				t.Fatal("rejected origin effect leaked a numerical definition", accepted, known)
			}
		})
	}
	importPointer := x86ScalarLaneInstruction(t, "MOVQ p+0(FP),SI")
	var addresses [16]bool
	addresses[6] = true
	if ids := x86ResultCallerOriginsAfter(importPointer, [16]uint16{}, addresses, map[int64]bool{0: true}, "amd64"); ids[6] != 1 {
		t.Fatal("actual zero-offset pointer slot collided with absent origin")
	}
	if ids := x86ResultCallerOriginsAfter(importPointer, state.callerAddressOrigin, addresses, nil, "amd64"); ids != [16]uint16{} {
		t.Fatal("a numerical-only entry invented an actual pointer origin")
	}
}
