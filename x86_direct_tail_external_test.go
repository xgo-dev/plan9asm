package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86DirectTailOrdinaryTypedExternalTerminal(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, width, typ, triple := "Q", 8, "uint64", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, width, typ, triple = "L", 4, "uint32", "i386-unknown-linux-gnu"
		}
		source := fmt.Sprintf(`TEXT ·First(SB),NOSPLIT,$0-%d
 MOV%s a+0(FP),SI
 CMP%s SI,$0
 JEQ 2(PC)
 JMP ·ordinary(SB)
 JMP body<>(SB)
TEXT body<>(SB),NOSPLIT,$0-0
 ADD%s $7,SI
 MOV%s SI,ret+%d(FP)
 RET
`, width*2, word, word, word, word, width)
		for _, ordinary := range []struct {
			name, declaration string
			context           bool
		}{
			{"same_role", "func ordinary(other " + typ + ") " + typ, false},
			{"different_arg", "func ordinary(other uint8) " + typ, true},
			{"different_result", "func ordinary(other " + typ + ") uint8", true},
			{"missing", "", true},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+ordinary.name+"/"+api, func(t *testing.T) {
					_, err := x86ScalarFPBitViewAPI(t, source, "func First(a "+typ+") "+typ+"\n"+ordinary.declaration, arch, triple, api)
					if ordinary.context && !errors.Is(err, ErrProbeNeedsContext) || !ordinary.context && err != nil {
						t.Fatalf("ordinary typed terminal: %v", err)
					}
				})
			}
		}
		for _, target := range []string{"ordinary+1", "ordinary<ABIInternal>", "ordinary<>(SB)", "*ordinary"} {
			t.Run(arch+"/"+target, func(t *testing.T) {
				mutated := strings.ReplaceAll(source, "·ordinary(SB)", "·"+strings.TrimSuffix(target, "(SB)")+"(SB)")
				_, err := x86ScalarFPBitViewAPI(t, mutated, "func First(a "+typ+") "+typ+"\nfunc ordinary(other "+typ+") "+typ, arch, triple, "text")
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("offset/native/unbound terminal accepted", err)
				}
			})
		}
	}
}

func TestX86DirectTailExternalTerminalRequiresNamedIdentity(t *testing.T) {
	source, declarations := x86DirectTailFollowupFixture("amd64")
	pkg := mustGoPackage(t, "bitview", "package bitview\n"+declarations)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	normalResolve := func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") }
	sigs, err := goSigsForAsmFile(pkg, file, normalResolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// An explicit manual caller cannot use an empty mapping/name to recreate
	// the declaration which the Go producer correctly refuses to synthesize.
	ordinary := sigs["ordinary"]
	delete(sigs, "ordinary")
	ordinary.Name = ""
	sigs[""] = ordinary
	resolve := func(symbol string) string {
		name := strings.TrimPrefix(goStripABISuffix(symbol), "·")
		if name == "ordinary" {
			return ""
		}
		return name
	}
	_, err = PrepareX86DirectTailSource(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs})
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("empty external source identity accepted", err)
	}
}
