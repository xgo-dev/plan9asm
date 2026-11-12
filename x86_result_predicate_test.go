package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86ResultPredicateFixture(t *testing.T, compare, test, movemask, scan, between string) (Func, FuncSig, string) {
	t.Helper()
	ins := x86ScalarLaneInstruction(t, scan)
	if len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		t.Fatal("predicate fixture needs its actual scan destination")
	}
	destination := string(ins.Args[1].Reg)
	body := "MOVQ x+0(FP),AX\nMOVQ AX,X0\nVPBROADCASTQ X0,Y1\nVPBROADCASTQ X0,Y2\n" + compare + "\n" + test + "\nJZ zero\n" + between + movemask + "\n" + scan + "\nMOVL " + destination + ",ret+8(FP)\nRET\nzero:\nMOVL $0,ret+8(FP)\nRET"
	_, file, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value(x uint64) uint32", body)
	return file.Funcs[0], sig, source
}

func TestX86ResultPredicateNonzeroComparisonMaskBitScan(t *testing.T) {
	for _, compare := range []string{"VPCMPEQB", "VPCMPEQW", "VPCMPEQD", "VPCMPEQQ", "VPCMPGTB", "VPCMPGTW", "VPCMPGTD", "VPCMPGTQ"} {
		for _, test := range []string{"VPTEST", "VTESTPS", "VTESTPD"} {
			for _, mask := range []string{"VPMOVMSKB", "VMOVMSKPS", "VMOVMSKPD"} {
				t.Run(compare+"/"+test+"/"+mask, func(t *testing.T) {
					fn, sig, _ := x86ResultPredicateFixture(t, compare+" Y1,Y2,Y3", test+" Y3,Y3", mask+" Y3,DX", "BSFL DX,DX", "")
					if err := checkX86ScalarFPResultInitialization(fn, sig, "amd64"); err != nil {
						t.Fatal("typed nonzero comparison mask rejected", err)
					}
				})
			}
		}
	}
}

func TestX86ResultPredicateNonzeroCannotBorrowOtherValueOrWidth(t *testing.T) {
	for name, change := range map[string]struct{ compare, test, mask, scan, between string }{
		"plain vector is not a comparison mask":     {"VMOVDQU Y1,Y3", "VPTEST Y3,Y3", "VPMOVMSKB Y3,DX", "BSFL DX,DX", ""},
		"different tested vector":                   {"VPCMPEQB Y1,Y2,Y3", "VPTEST Y2,Y2", "VPMOVMSKB Y3,DX", "BSFL DX,DX", ""},
		"mixed test intersection":                   {"VPCMPEQB Y1,Y2,Y3", "VPTEST Y2,Y3", "VPMOVMSKB Y3,DX", "BSFL DX,DX", ""},
		"different movemask vector":                 {"VPCMPEQB Y1,Y2,Y3", "VPTEST Y3,Y3", "VPMOVMSKB Y2,DX", "BSFL DX,DX", ""},
		"narrowing discards only nonzero high half": {"VPCMPEQB Y1,Y2,Y3", "VPTEST Y3,Y3", "VPMOVMSKB X3,DX", "BSFL DX,DX", ""},
		"word scan discards nonzero mask high bits": {"VPCMPEQB Y1,Y2,Y3", "VPTEST Y3,Y3", "VPMOVMSKB Y3,DX", "BSFW DX,DX", ""},
		"vector replaced":                           {"VPCMPEQB Y1,Y2,Y3", "VPTEST Y3,Y3", "VPMOVMSKB Y3,DX", "BSFL DX,DX", "VMOVDQU Y1,Y3\n"},
	} {
		t.Run(name, func(t *testing.T) {
			fn, sig, _ := x86ResultPredicateFixture(t, change.compare, change.test, change.mask, change.scan, change.between)
			if err := checkX86ScalarFPResultInitialization(fn, sig, "amd64"); err != nil {
				t.Fatal("the original initialized self-alias is a valid numerical control", err)
			}
			unknownScan := strings.Replace(change.scan, ",DX", ",BX", 1)
			fn, sig, _ = x86ResultPredicateFixture(t, change.compare, change.test, change.mask, unknownScan, change.between)
			if err := checkX86ScalarFPResultInitialization(fn, sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("nonzero relationship laundered a different value", err)
			}
		})
	}
	for _, replacement := range []string{"JNZ zero", "JCS zero", "CMPL AX,$0\nJZ zero"} {
		t.Run(fmt.Sprintf("replaced guard %s", replacement), func(t *testing.T) {
			_, sig, source := x86ResultPredicateFixture(t, "VPCMPEQB Y1,Y2,Y3", "VPTEST Y3,Y3", "VPMOVMSKB Y3,DX", "BSFL DX,DX", "")
			changed := strings.Replace(source, "JZ zero", replacement, 1)
			file, err := Parse(ArchAMD64, changed)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, "amd64"); err != nil {
				t.Fatal("original initialized self-alias ceased to be numerical", err)
			}
			unknown := strings.ReplaceAll(strings.Replace(changed, "BSFL DX,DX", "BSFL DX,BX", 1), "MOVL DX,ret", "MOVL BX,ret")
			file, err = Parse(ArchAMD64, unknown)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, "amd64"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("wrong/stale predicate authorized a nonzero mask", err)
			}
		})
	}
}

func TestX86ResultPredicateBoundedStateAndRawRevocation(t *testing.T) {
	base := x86ResultPredicate{kind: x86ResultNonzeroComparisonBytes, register: 3, width: 32}
	ins := x86ScalarLaneInstruction(t, "VPMOVMSKB Y3,DX")
	for _, kind := range []x86ResultPredicateKind{x86ResultNoPredicate, x86ResultComparisonBytes, x86ResultTestComparisonBytes, x86ResultNonzeroComparisonBytes, x86ResultNonzeroMaskGP} {
		for _, width := range []uint8{16, 32, 64} {
			for _, register := range []uint8{2, 3, 4} {
				before := x86ResultPredicate{kind: kind, register: register, width: width}
				next := x86ResultPredicateAfter(ins, before, "amd64")
				want := kind == base.kind && width == base.width && register == base.register
				if (next.kind == x86ResultNonzeroMaskGP) != want {
					t.Fatal("predicate accepts a different domain/view/physical register", before, next)
				}
				left := x86ResultState{predicate: base}
				right := x86ResultState{predicate: before}
				if (left.intersect(right).predicate == base) != (base == before) {
					t.Fatal("predicate intersection manufactured a relation", base, before)
				}
			}
		}
	}
	for _, raw := range []bool{false, true} {
		local := ins
		local.x86Encoded = raw
		next := x86ResultPredicateAfter(local, base, "amd64")
		if raw && next.kind != x86ResultNoPredicate || !raw && next.kind != x86ResultNonzeroMaskGP {
			t.Fatal("named predicate adopted encoded source authority", raw, next)
		}
	}
	state := x86ResultState{predicate: x86ResultPredicate{kind: x86ResultTestComparisonBytes, register: 3, width: 32}}
	branch := x86ScalarLaneInstruction(t, "JNZ matched")
	zero := x86ResultPredicateEdge(state, branch, 0)
	nonzero := x86ResultPredicateEdge(state, branch, 1)
	if zero.predicate.kind != x86ResultNoPredicate || nonzero.predicate.kind != x86ResultNonzeroComparisonBytes || state.predicate.kind != x86ResultTestComparisonBytes {
		t.Fatal("predicate edge mutated predecessor or sibling")
	}
}

func TestX86ResultPredicateLegacyAndVEXCompleteComparisonFamilies(t *testing.T) {
	for _, compare := range []string{"PCMPEQB", "PCMPEQW", "PCMPEQL", "PCMPEQQ", "PCMPGTB", "PCMPGTW", "PCMPGTL", "PCMPGTQ"} {
		for _, test := range []string{"PTEST", "VPTEST", "VTESTPS", "VTESTPD"} {
			for _, mask := range []string{"PMOVMSKB", "MOVMSKPS", "MOVMSKPD", "VPMOVMSKB", "VMOVMSKPS", "VMOVMSKPD"} {
				t.Run(compare+"/"+test+"/"+mask, func(t *testing.T) {
					fn, sig, _ := x86ResultPredicateFixture(t, compare+" X1,X2", test+" X2,X2", mask+" X2,DX", "BSFW DX,DX", "")
					if err := checkX86ScalarFPResultInitialization(fn, sig, "amd64"); err != nil {
						t.Fatal("complete typed X comparison/test/mask rejected", err)
					}
				})
			}
		}
	}
}

func TestX86ResultPredicateWholeSourceThreeAPIsAndMode32(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, mutation := range []string{"none", "zero edge", "different vector", "GP replaced", "flags replaced"} {
			t.Run(arch+"/"+mutation, func(t *testing.T) {
				_, _, source := x86ResultPredicateFixture(t, "VPCMPEQB Y1,Y2,Y3", "VPTEST Y3,Y3", "VPMOVMSKB Y3,DX", "BSFL DX,BX", "")
				declaration := "func Value(x uint64) uint32\n"
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					declaration, triple = "func Value(x uint32) uint32\n", "i386-unknown-linux-gnu"
					source = strings.ReplaceAll(source, "MOVQ", "MOVL")
					source = strings.ReplaceAll(source, "VPBROADCASTQ", "VPBROADCASTD")
					source = strings.ReplaceAll(source, "ret+8(FP)", "ret+4(FP)")
					source = strings.Replace(source, "$0-12", "$0-8", 1)
				}
				switch mutation {
				case "zero edge":
					source = strings.Replace(source, "JZ zero", "JNZ zero", 1)
				case "different vector":
					source = strings.Replace(source, "VPMOVMSKB Y3", "VPMOVMSKB Y2", 1)
				case "GP replaced":
					source = strings.Replace(source, "BSFL DX,BX", "MOVL $0,DX\nBSFL DX,BX", 1)
				case "flags replaced":
					source = strings.Replace(source, "JZ zero", "CMPL AX,$0\nJZ zero", 1)
				}
				// Preserve every original self-alias source as a separate
				// positive. Its already initialized DX supplies numeric bytes
				// even when the relationship does not prove a nonzero mask.
				selfAlias := strings.ReplaceAll(strings.Replace(source, "BSFL DX,BX", "BSFL DX,DX", 1), "MOVL BX,ret", "MOVL DX,ret")
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						known, err := x86ScalarFPBitViewAPI(t, selfAlias, declaration, arch, triple, api)
						if err != nil || known == "" {
							t.Fatal("original initialized self-alias rejected", err)
						}
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if mutation == "none" {
							if err != nil || ir == "" {
								t.Fatal("original complete nonzero chain rejected", err)
							}
						} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("changed chain acquired original predicate", len(ir), err)
						}
					})
				}
			})
		}
	}
}
