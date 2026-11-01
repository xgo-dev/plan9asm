package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const repeatEmptyGuardDeclaration = "func view(p,q *byte,n,needle uintptr) uintptr"

func repeatEmptyGuardPrefix(arch, opcode, prefix, direction string) string {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	body := fmt.Sprintf("%s p+0(FP),SI\n%s q+%d(FP),DI\n%s DI,BX\n%s n+%d(FP),CX\n%s needle+%d(FP),AX\n%s\n%s\n%s\n",
		move, move, word, move, move, 2*word, move, 3*word, direction, prefix, opcode)
	if direction == "STD" {
		// Restore Go's direction convention without defining status FLAGS.
		body += "CLD\n"
	}
	return body
}

func repeatEmptyGuardBody(arch, opcode, prefix, direction, branch string) string {
	move, sub := "MOVQ", "SUBQ"
	if arch == "386" {
		move, sub = "MOVL", "SUBL"
	}
	// The source does not initialize ZF. A nonempty repeated comparison defines
	// it. On the empty path DI is exactly its saved BX, so either Jcc outcome
	// returns the same -1. Same pointer origin alone would not prove that fact.
	return repeatEmptyGuardPrefix(arch, opcode, prefix, direction) + branch + " matched\n" +
		move + " $-1,ret+RESULT(FP)\nRET\nmatched:\n" + sub + " BX,DI\n" +
		sub + " $1,DI\n" + move + " DI,ret+RESULT(FP)"
}

func repeatEmptyGuardCompleteSource(t *testing.T, arch string, priorFlags bool) (string, string, int) {
	t.Helper()
	widths := "BWLQ"
	if arch == "386" {
		widths = "BWL"
	}
	var source, declarations strings.Builder
	count := 0
	for _, stem := range []string{"SCAS", "CMPS"} {
		for _, width := range widths {
			for _, prefix := range []string{"REP", "REPN"} {
				for _, direction := range []string{"CLD", "STD"} {
					for _, branch := range []string{"JE", "JZ", "JNE", "JNZ"} {
						body := repeatEmptyGuardBody(arch, stem+string(width), prefix, direction, branch)
						if priorFlags {
							// Independent old-contract control: this actual comparison
							// supplies all six entry status flags even at zero count.
							body = strings.Replace(body, prefix+"\n", "CMPL AX,AX\n"+prefix+"\n", 1)
						}
						name := fmt.Sprintf("RepeatEmpty%d", count)
						assembly := x86ResultGPSIMDAdmissionSource(t, arch, repeatEmptyGuardDeclaration, body)
						source.WriteString(strings.Replace(assembly, "·view(SB)", "·"+name+"(SB)", 1))
						declarations.WriteString(strings.Replace(repeatEmptyGuardDeclaration, "view(", name+"(", 1) + "\n")
						count++
					}
				}
			}
		}
	}
	want := 128
	if arch == "386" {
		want = 96
	}
	if count != want || strings.Count(source.String(), "TEXT ") != want || strings.Count(declarations.String(), "func ") != want {
		t.Fatal("complete independent repeated comparison/branch directory changed", arch, count, want)
	}
	return source.String(), declarations.String(), count
}

func repeatEmptyGuardFamily(t *testing.T, priorFlags bool) {
	t.Helper()
	for _, arch := range []string{"386", "amd64"} {
		source, declarations, count := repeatEmptyGuardCompleteSource(t, arch, priorFlags)
		// One complete original-Go assembler command per architecture, not a
		// process per form. This is encoding evidence, not native execution.
		goAssemblerOracleOutput(t, arch, source, "", true)
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
				if err != nil || ir == "" {
					t.Fatalf("%d complete repeat/empty-path functions rejected: priorFLAGS=%t output=%t err=%v", count, priorFlags, ir != "", err)
				}
				for index := 0; index < count; index++ {
					name := fmt.Sprintf("@RepeatEmpty%d(", index)
					if !strings.Contains(ir, name) {
						t.Fatal("complete original family lost a callable entry", name)
					}
				}
			})
		}
	}
}

func TestX86RepeatEmptyGuardCompleteScalarFamily(t *testing.T) {
	repeatEmptyGuardFamily(t, false)
}

func TestX86RepeatEmptyGuardPriorFlagsControl(t *testing.T) {
	repeatEmptyGuardFamily(t, true)
}

func TestX86RepeatEmptyGuardOriginalSDKIndexByte386WholeSource(t *testing.T) {
	directory := filepath.Join(testGOROOT(t), "src", "internal", "bytealg")
	input := filepath.Join(directory, "indexbyte_386.s")
	source, err := os.ReadFile(input)
	if err != nil {
		t.Fatal("selected SDK complete 386 IndexByte source is required", err)
	}
	declarations, err := os.ReadFile(filepath.Join(directory, "indexbyte_native.go"))
	if err != nil {
		t.Fatal("selected SDK actual IndexByte declarations are required", err)
	}
	pkg := importedGlobalPackage(t, "internal/bytealg", "386", []string{string(declarations)}, nil)
	if strings.Count(string(source), "TEXT ") != 2 || strings.Count(string(source), "JZ 3(PC)") != 2 ||
		strings.Count(string(source), "REPN; SCASB") != 2 {
		t.Fatal("the complete original two-entry 386 counterexample changed")
	}
	for _, target := range []struct{ goos, triple string }{
		{"linux", "i386-unknown-linux-gnu"}, {"windows", "i686-pc-windows-msvc"},
	} {
		for _, api := range []string{"public", "owned-context"} {
			t.Run(target.goos+"/"+api, func(t *testing.T) {
				// Pass the unchanged complete source, real declarations and target.
				// No KeepFunc, invented FP/signature, FLAGS seed or native ABI flag.
				ir, err := importedGlobalReadRequest(t, pkg, source, "386", target.triple, api, false, func(options *GoModuleOptions) {
					options.GOOS, options.FileName = target.goos, input
				})
				if err != nil || ir == "" {
					t.Fatalf("complete original SDK IndexByte/IndexByteString rejected: output=%t err=%v", ir != "", err)
				}
				for _, name := range []string{"IndexByte", "IndexByteString"} {
					if !strings.Contains(ir, "internal/bytealg."+name) {
						t.Fatal("complete original source lost its public entry", name)
					}
				}
			})
		}
	}
}

func TestX86RepeatEmptyGuardCannotInventFlagsOrSuppressEffects(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, move, lea := 8, "MOVQ", "LEAQ"
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, lea, triple = 4, "MOVL", "LEAL", "i386-unknown-linux-gnu"
		}
		for _, stem := range []string{"SCAS", "CMPS"} {
			for _, prefix := range []string{"REP", "REPN"} {
				complete := repeatEmptyGuardBody(arch, stem+"B", prefix, "CLD", "JZ")
				for _, mutation := range []string{
					"different-empty-results", "one-arm-native-store", "nonzero-saved-offset", "different-pointer-origin",
					"partial-counter", "missing-direction", "missing-accumulator", "skipped-prefix", "missing-result",
					"unrelated-unknown-Jcc", "direct-status-result",
				} {
					if mutation == "missing-accumulator" && stem == "CMPS" {
						continue // CMPS has two memory inputs, not an AX input.
					}
					body := complete
					switch mutation {
					case "different-empty-results":
						body = strings.Replace(body, move+" $-1,ret+RESULT(FP)", move+" $0,ret+RESULT(FP)", 1)
					case "one-arm-native-store":
						body = strings.Replace(body, "matched:\n", "matched:\nMOVB $1,(BX)\n", 1)
					case "nonzero-saved-offset":
						body = strings.Replace(body, move+" DI,BX\n", move+" DI,BX\n"+lea+" 1(DI),DI\n", 1)
					case "different-pointer-origin":
						body = strings.Replace(body, move+" DI,BX\n", move+" SI,BX\n", 1)
					case "partial-counter":
						body = strings.Replace(body, fmt.Sprintf("%s n+%d(FP),CX", move, 2*word), fmt.Sprintf("MOVW n+%d(FP),CX", 2*word), 1)
					case "missing-direction":
						body = strings.Replace(body, "CLD\n", "", 1)
					case "missing-accumulator":
						body = strings.Replace(body, fmt.Sprintf("%s needle+%d(FP),AX\n", move, 3*word), "", 1)
					case "skipped-prefix":
						body = strings.Replace(body, prefix+"\n"+stem+"B", "CMPL AX,AX\nJE body\n"+prefix+"\nbody:\n"+stem+"B", 1)
					case "missing-result":
						body = strings.Replace(body, move+" DI,ret+RESULT(FP)", "NOP", 1)
					case "unrelated-unknown-Jcc":
						body = strings.Replace(body, prefix+"\n"+stem+"B\n", "", 1)
					case "direct-status-result":
						body = repeatEmptyGuardPrefix(arch, stem+"B", prefix, "CLD") + "MOVL $0,DX\nSETEQ DL\n" + move + " DX,ret+RESULT(FP)"
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(arch+"/"+stem+"/"+prefix+"/"+mutation+"/"+api, func(t *testing.T) {
							source := x86ResultGPSIMDAdmissionSource(t, arch, repeatEmptyGuardDeclaration, body)
							ir, err := x86ScalarFPBitViewAPI(t, source, repeatEmptyGuardDeclaration, arch, triple, api)
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatalf("empty-repeat guard manufactured a FLAGS/result/alias/memory fact: output=%t err=%v", ir != "", err)
							}
						})
					}
				}
			}
		}
	}
}
