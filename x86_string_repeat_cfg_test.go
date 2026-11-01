package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86StringRepeatCFGBody(op, prefix, shape string) string {
	switch shape {
	case "adjacent":
		return prefix + "\n" + op + "\n"
	case "fallthrough-label":
		return prefix + "\nconsume:\n" + op + "\n"
	case "fallthrough-label-chain":
		return prefix + "\nfirst:\nsecond:\nconsume:\n" + op + "\n"
	case "branch-to-prefix":
		return "JMP repeat\nrepeat:\n" + prefix + "\n" + op + "\n"
	case "pc-to-prefix":
		return "JMP 1(PC)\n" + prefix + "\n" + op + "\n"
	case "loopback-to-prefix":
		return "repeat:\n" + prefix + "\n" + op + "\nTESTL BX,BX\nJNE repeat\n"
	case "conditional-bypass":
		return "TESTL BX,BX\nJE consume\n" + prefix + "\nconsume:\n" + op + "\n"
	case "unreachable-prefix":
		return "JMP consume\n" + prefix + "\nconsume:\n" + op + "\n"
	case "backedge-to-body":
		return prefix + "\nconsume:\n" + op + "\nTESTL BX,BX\nJNE consume\n"
	case "pc-bypass":
		return "JMP 2(PC)\n" + prefix + "\n" + op + "\n"
	case "unknown-indirect":
		return "JMP BX\n" + prefix + "\n" + op + "\n"
	default:
		panic("unknown independent repeat CFG fixture")
	}
}

func x86StringRepeatCFGFixture(row x86StringMemoryRow, arch, prefix, shape string) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	return fmt.Sprintf(`TEXT ·repeatcfg(SB),4,$0-%d
%s dst+0(FP),DI
%s src+%d(FP),SI
MOVL mode+%d(FP),BX
MOVL $3,CX
MOVL $19,AX
CLD
%sCLD
RET
`, 2*word+4, move, move, word, 2*word, x86StringRepeatCFGBody(row.op, prefix, shape)),
		"func repeatcfg(dst,src *byte,mode uint32)\n"
}

func TestX86StringRepeatCFGAcceptsOnlyUnambiguousAdjacency(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, prefix := range []string{"REP", "REPN"} {
			for _, shape := range []string{"adjacent", "fallthrough-label", "fallthrough-label-chain",
				"branch-to-prefix", "pc-to-prefix", "loopback-to-prefix"} {
				for _, row := range x86StringMemoryModeRows(arch) {
					// Repeat the complete family through the text consumer. The
					// tool-backed owner separately retains all three public APIs.
					t.Run(arch+"/"+prefix+"/"+shape+"/"+row.op, func(t *testing.T) {
						source, declarations := x86StringRepeatCFGFixture(row, arch, prefix, shape)
						if shape == "loopback-to-prefix" {
							file, err := Parse(ArchAMD64, source)
							if err != nil {
								t.Fatal(err)
							}
							if _, err := x86ResultStringMemorySourcePlan(file.Funcs[0], arch); err != nil {
								t.Fatal("the original loop lost its unambiguous prefix binding", err)
							}
							for _, api := range []string{"text", "module", "Go"} {
								ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
								if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("prefix binding granted a reusable updated native cursor", api, err)
								}
							}
							// The original Go loop remains unchanged in its object
							// owner above. This separate positive replenishes the
							// declared inputs on every iteration; it does not certify
							// the original loop's updated-cursor memory contract.
							begin := strings.IndexByte(source, '\n') + 1
							label := strings.Index(source, "repeat:\n")
							if begin <= 0 || label <= begin {
								t.Fatal("complete independent loop fixture changed")
							}
							source = strings.Replace(source, "repeat:\n", "repeat:\n"+source[begin:label], 1)
						}
						ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, "text")
						if err != nil || !strings.Contains(ir, "@"+x86StringMemoryHelper(row)+"(") {
							t.Fatal("a uniquely executed prefix lost its complete typed follower", err)
						}
					})
				}
			}
		}
	}
}

func TestX86StringRepeatCFGRejectsBypassedOrAmbiguousPrefix(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, prefix := range []string{"REP", "REPN"} {
			for _, shape := range []string{"conditional-bypass", "unreachable-prefix", "backedge-to-body", "pc-bypass", "unknown-indirect"} {
				for _, row := range x86StringMemoryModeRows(arch) {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(arch+"/"+prefix+"/"+shape+"/"+row.op+"/"+api, func(t *testing.T) {
							source, declarations := x86StringRepeatCFGFixture(row, arch, prefix, shape)
							_, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
							if !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("lexical source order cannot give an incoming edge the skipped REP/REPN byte", err)
							}
						})
					}
				}
			}
		}
	}
}

func TestX86StringRepeatCFGFixtureKeepsActualBranchAndPrefixNodes(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, prefix := range []string{"REP", "REPN"} {
			for _, shape := range []string{"adjacent", "fallthrough-label", "fallthrough-label-chain",
				"branch-to-prefix", "pc-to-prefix", "loopback-to-prefix",
				"conditional-bypass", "unreachable-prefix", "backedge-to-body", "pc-bypass", "unknown-indirect"} {
				for _, row := range x86StringMemoryModeRows(arch) {
					source, _ := x86StringRepeatCFGFixture(row, arch, prefix, shape)
					file, err := Parse(ArchAMD64, source)
					if err != nil || len(file.Funcs) != 1 {
						t.Fatal("complete independent CFG fixture did not parse", err)
					}
					prefixes, followers := 0, 0
					for _, ins := range file.Funcs[0].Instrs {
						if ins.Op == Op(prefix) {
							prefixes++
						}
						if ins.Op == Op(row.op) {
							followers++
						}
					}
					if prefixes != 1 || followers != 1 {
						t.Fatal("fixture removed or duplicated the original prefix/follower", arch, prefix, shape, row)
					}
				}
			}
		}
	}
}

func TestX86StringRepeatCFGPortGrammarRemainsIndependent(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, prefix := range []string{"REP", "REPN"} {
			for _, op := range []string{"INSB", "INSW", "INSL", "OUTSB", "OUTSW", "OUTSL"} {
				sourceForShape := func(shape string) string {
					return "TEXT port(SB),4,$0-0\nMOVL $3,CX\nMOVL $0,DX\nCLD\n" +
						x86StringRepeatCFGBody(op, prefix, shape) + "RET\n"
				}
				for _, shape := range []string{"adjacent", "fallthrough-label-chain", "branch-to-prefix", "conditional-bypass"} {
					t.Run(arch+"/"+prefix+"/"+op+"/"+shape, func(t *testing.T) {
						file, err := Parse(ArchAMD64, sourceForShape(shape))
						if err != nil {
							t.Fatal(err)
						}
						ir, err := Translate(file, Options{Goarch: arch, TargetTriple: testTargetTriple("linux", arch),
							Sigs: map[string]FuncSig{"port": {Name: "port", Ret: Void}}})
						if shape == "conditional-bypass" {
							if !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("port I/O acquired a skipped prefix", err)
							}
							return
						}
						if err != nil || !strings.Contains(ir, "asm sideeffect") ||
							!strings.Contains(ir, "; "+strings.ToLower(op)) {
							t.Fatal("existing complete native port-I/O emitter changed", err)
						}
					})
				}
				if prefix == "REP" {
					t.Run(arch+"/"+op+"/unspecified-target", func(t *testing.T) {
						file, err := Parse(ArchAMD64, sourceForShape("adjacent"))
						if err != nil {
							t.Fatal(err)
						}
						ir, err := Translate(file, Options{Goarch: arch,
							Sigs: map[string]FuncSig{"port": {Name: "port", Ret: Void}}})
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "native inline assembly") {
							t.Fatal("native port-I/O escaped its explicit target requirement", ir != "", err)
						}
					})
				}
			}
			for _, follower := range []string{"REP", "REPN", "NOP", "INB", "OUTL", "INSB AX", "OUTSL $1"} {
				source := "TEXT bad(SB),4,$0-0\nJMP done\n" + prefix + "\n" + follower + "\ndone:\nRET\n"
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Translate(file, Options{Goarch: arch, TargetTriple: testTargetTriple("linux", arch),
					Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}}); err == nil {
					t.Fatal("dead or malformed nonstring follower was silently skipped", arch, prefix, follower)
				}
			}
		}
	}
}
