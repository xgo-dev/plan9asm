package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86ScalarCountNativeFixture(arch, opcode string, dead bool) (string, string) {
	word, move, typ := 8, "MOVQ", "uint64"
	if arch == "386" {
		word, move, typ = 4, "MOVL", "uint32"
	}
	body := fmt.Sprintf("%s p+0(FP),AX\nMOVL $1,DX\n%s $0,BX\n%s 3(AX)(DX*2),BX\n", move, move, opcode)
	if dead {
		body += "MOVL $7,BX\n"
	}
	body += fmt.Sprintf("%s BX,ret+%d(FP)\nRET\n", move, word)
	return fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", word*2, body),
		"func Value(p *[64]byte) " + typ
}

func TestX86ScalarBitCountPairedNativeReadCompleteFamily(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var assembly, declarations strings.Builder
			var names []string
			for _, family := range []string{"POPCNT", "LZCNT", "TZCNT"} {
				suffixes := []string{"W", "L"}
				if target.arch == "amd64" {
					suffixes = append(suffixes, "Q")
				}
				for _, suffix := range suffixes {
					for _, dead := range []bool{false, true} {
						source, declaration := x86ScalarCountNativeFixture(target.arch, family+suffix, dead)
						name := fmt.Sprint("Count", len(names))
						names = append(names, name)
						assembly.WriteString(strings.ReplaceAll(source, "Value", name))
						declarations.WriteString(strings.ReplaceAll(declaration, "Value", name) + "\n")
					}
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, assembly.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("complete scalar-count family lost its paired native input", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						x86CompactExpandRequireAllDefinitions(t, text, names)
						if strings.Count(text, "load volatile") != len(names) {
							t.Fatal("live or dead scalar count lost its exact observable source width")
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86ScalarBitCountPairedNativeReadKeepsInputBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		move, triple := "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, triple = "MOVL", "i386-unknown-linux-gnu"
		}
		for _, family := range []string{"POPCNT", "LZCNT", "TZCNT"} {
			suffixes := []string{"W", "L"}
			if arch == "amd64" {
				suffixes = append(suffixes, "Q")
			}
			for _, suffix := range suffixes {
				op := family + suffix
				t.Run(arch+"/"+op, func(t *testing.T) {
					source, declaration := x86ScalarCountNativeFixture(arch, op, false)
					body := source[strings.Index(source, "\n")+1:]
					_, file, sig, _ := x86ResultInitializationFixture(t, arch, declaration, body)
					for _, check := range []func(Func, FuncSig, string) error{
						CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization,
					} {
						if err := check(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("standalone scalar-count query acquired native input", err)
						}
					}
					for _, missing := range []string{move + " p+0(FP),AX\n", "MOVL $1,DX\n", move + " $0,BX\n"} {
						changed := strings.Replace(source, missing, "", 1)
						want := missing == move+" $0,BX\n" && suffix != "W"
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, triple, api)
							if want && (err != nil || ir == "") || !want && (ir != "" || !errors.Is(err, ErrProbeNeedsContext)) {
								t.Fatal("scalar count invented an address, index or untouched upper byte", missing, api, err)
							}
						}
					}
				})
			}
		}
	}
}

func TestX86ScalarBitCountVoidCannotHideNativeInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, move, triple := 8, "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "MOVL", "i386-unknown-linux-gnu"
		}
		for _, family := range []string{"POPCNT", "LZCNT", "TZCNT"} {
			suffixes := []string{"W", "L"}
			if arch == "amd64" {
				suffixes = append(suffixes, "Q")
			}
			for _, suffix := range suffixes {
				for _, unusedBool := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s%s/bool-%t", arch, family, suffix, unusedBool), func(t *testing.T) {
						source, _ := x86ScalarCountNativeFixture(arch, family+suffix, true)
						body := source[strings.Index(source, "\n")+1:]
						body = strings.Replace(body, fmt.Sprintf("%s BX,ret+%d(FP)\n", move, word), "", 1)
						declaration := "func Value(p *[64]byte)"
						arguments := word
						if unusedBool {
							declaration = "func Value(p *[64]byte,unused bool)"
							arguments++
						}
						source = fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", arguments, body)
						goAssemblerOracleOutput(t, arch, source, "", true)
						for _, api := range []string{"text", "module", "Go"} {
							t.Run(api, func(t *testing.T) {
								if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api); err != nil || ir == "" {
									t.Fatal("complete Void count lost its native continuation", api, err)
								}
								for _, input := range []struct{ name, line string }{
									{"pointer", move + " p+0(FP),AX\n"}, {"index", "MOVL $1,DX\n"},
								} {
									t.Run(input.name, func(t *testing.T) {
										changed := strings.Replace(source, input.line, "", 1)
										if ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
											t.Fatal("Void count invented a native pointer or index", api, err)
										}
									})
								}
							})
						}
					})
				}
			}
		}
	}
}
