package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestX86DirectTailInteriorCallSource(t *testing.T) {
	source, declarations := x86DirectTailInteriorCallFixture()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				if !strings.Contains(ir, "i32 73") || !strings.Contains(ir, "i32 11") {
					t.Fatal(api, "both real source entry bodies must be lowered", ir)
				}
				dir := t.TempDir()
				input := filepath.Join(dir, "entries.ll")
				if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
					t.Fatal(err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					output := filepath.Join(dir, "entries"+level+".o")
					x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple="+target.triple, "-filetype=obj", input, "-o", output))
					if info, err := os.Stat(output); err != nil || info.Size() == 0 {
						t.Fatalf("%s/%s missing real LLVM object: %v", api, level, err)
					}
				}
				for _, offset := range []string{"+1", "+12", "-1"} {
					changed := strings.ReplaceAll(source, "+6(SB)", offset+"(SB)")
					if _, err := x86ScalarFPBitViewAPI(t, changed, declarations, target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal(api, offset, "unbound byte entry was accepted", err)
					}
				}
				changed := strings.Replace(source, "MOVL $11,AX", "MOVL datum<>(SB),AX", 1)
				if _, err := x86ScalarFPBitViewAPI(t, changed, declarations, target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal(api, "global relocation layout was assumed", err)
				}
			}
		})
	}
}

func TestX86DirectTailNamedInteriorCallPreservesOrdinaryEntry(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	callKinds := []string{"R_CALL"}
	for value, kind := range x86StackControlRelocationEnums(t) {
		if kind == "R_CALL" {
			callKinds = append(callKinds, value)
		}
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			for _, symbol := range []struct {
				name, source, goObject, llvm string
				flags                        int
			}{
				{"Target", "·Target", "plan9asmentries.Target", "Target", 516},
				{"foo", "foo", "foo", "foo", 516},
				{"foo/implicit-frameless", "foo", "foo", "foo", 4},
			} {
				t.Run(symbol.name, func(t *testing.T) {
					assembly, signatures := x86DirectTailNamedInteriorCallFixture(target.arch, symbol.source, symbol.flags)
					original, err := x86InteriorCallGoListing(assembly, target.arch, target.triple)
					names := []string{regexp.QuoteMeta(symbol.goObject)}
					if symbol.source == "·Target" {
						names = append(names, regexp.QuoteMeta(`"".Target`)) // Go 1.20 -S uses the local package placeholder.
					}
					relocation := regexp.MustCompile(`(?m)^\s*rel [0-9]+\+4 t=(?:` + strings.Join(callKinds, "|") +
						`) (?:` + strings.Join(names, "|") + `)\+4\s*$`)
					if err != nil || len(relocation.FindAll(original, -1)) != 1 {
						t.Fatalf("original Go did not retain the direct +4 relocation: %v\n%s", err, original)
					}
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, assembly, signatures, target.arch, target.triple, api)
						if err != nil {
							t.Fatal(api, err)
						}
						if !strings.Contains(ir, "define void @"+symbol.llvm+"(") {
							t.Fatal(api, "byte entry consumed the independently callable TEXT")
						}
						for _, optimization := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, ir, optimization)
						}
						wrongEntry := strings.Replace(assembly, "+4(SB)", "+3(SB)", 1)
						if _, err := x86ScalarFPBitViewAPI(t, wrongEntry, signatures, target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal(api, "middle of an original machine instruction accepted", err)
						}
						external, _, _ := strings.Cut(assembly, "TEXT "+symbol.source)
						if _, err := x86ScalarFPBitViewAPI(t, external, signatures, target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal(api, "external byte entry accepted without its original TEXT", err)
						}
					}
				})
			}
		})
	}
}

func TestX86InteriorCallPositionsRejectGeneratedPrologue(t *testing.T) {
	const source = "TEXT foo(SB),4,$0-0\nXORL AX,AX\nADDL $73,AX\nRET\n"
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	points := []x86DirectTailPoint{{text: -1}, {0, 0}, {0, 1}, {0, 2}, {0, 3}}
	const frameless = `
  0x0000 00000 (entries.s:2) TEXT foo(SB), NOSPLIT, $0-0
  0x0000 00000 (entries.s:3) XORL AX, AX
  0x0002 00002 (entries.s:4) ADDL $73, AX
  0x0005 00005 (entries.s:5) RET
`
	positions := x86InteriorCallPositions([]byte(frameless), points, file)
	if point, found := positions[0][2]; !found || point != (x86DirectTailPoint{0, 2}) {
		t.Fatal("an implicit frameless entry lost its exact source instruction")
	}
	for _, listing := range []string{
		strings.Replace(frameless, "$0-0", "$8-0", 1),
		strings.Replace(frameless, "  0x0000 00000 (entries.s:3)",
			"  0x0000 00000 (entries.s:2) PUSHQ BP\n  0x0001 00001 (entries.s:3)", 1),
	} {
		if got := x86InteriorCallPositions([]byte(listing), points, file); len(got) != 0 {
			t.Fatal("assembler-generated frame entered the source continuation graph", got)
		}
	}
}

func TestX86DirectTailPCCompleteGoBranchRowsAndAliases(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "var yjcond = []ytab{\n\t{Zbr, 0, argList{Ybr}},\n\t{Zbr, 0, argList{Yi0, Ybr}},\n\t{Zbr, 1, argList{Yi1, Ybr}},\n}") {
		t.Fatal("complete Go conditional Ybr/hint rows changed")
	}
	rows := regexp.MustCompile(`\{A(J[A-Z]+), yjcond, Px, opBytes\{[^}]+\}\}`).FindAllStringSubmatch(string(data), -1)
	if len(rows) != 16 {
		t.Fatal("complete Go conditional encoder rows changed", len(rows))
	}
	names := make(map[string]bool)
	for _, row := range rows {
		names[row[1]] = true
		if !isAMD64ConditionalBranch(Op(row[1])) {
			t.Fatal("Go branch row missing source CFG", row)
		}
	}
	aliases, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/arch/arch.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range regexp.MustCompile(`instructions\["(J[A-Z]+)"\] = x86\.A(J[A-Z]+)`).FindAllStringSubmatch(string(aliases), -1) {
		if names[alias[2]] {
			names[alias[1]] = true
			if !isAMD64ConditionalBranch(Op(alias[1])) {
				t.Fatal("registered Go Jcc alias missing CFG", alias)
			}
		}
	}
	opcodes := make([]string, 0, len(names))
	for name := range names {
		opcodes = append(opcodes, name)
	}
	sort.Strings(opcodes)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"386", "amd64"} {
		var source strings.Builder
		source.WriteString("TEXT ·Value(SB),4,$0-12\n MOVL a+0(FP),AX\n MOVL b+4(FP),BX\n XORL CX,CX\n")
		for _, name := range opcodes {
			for _, hint := range []string{"", "$0,", "$1,"} {
				// Each branch sees a fresh set of FLAGS and skips a change
				// to the observed result only when it actually jumps.
				fmt.Fprintf(&source, " MOVL AX,DX\n ADDL BX,DX\n %s %s2(PC)\n INCL CX\n", name, hint)
			}
		}
		source.WriteString(" MOVL CX,ret+8(FP)\n JMP 1(PC)\n RET\n")
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), "func Value(a,b uint32) uint32", arch, triple, api)
				if err != nil {
					t.Fatal(err)
				}
				if got, want := strings.Count(ir, "br i1 "), 3*len(opcodes); got != want {
					t.Fatalf("lowered %d conditional edges, want %d", got, want)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, ir, level)
				}
			})
		}
		for _, malformed := range []string{"JEQ $2,1(PC)", "JEQ $1.0,1(PC)", "JEQ 1(PC)(AX*1)", "JMP $1,1(PC)"} {
			goAssemblerOracleOutput(t, arch, "TEXT ·Value(SB),4,$0-0\n"+malformed+"\n RET\n", "", false)
		}
	}
}

func TestX86DirectTailFollowupOriginalGoAndFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86DirectTailFollowupFixture(target.arch)
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					dir := t.TempDir()
					input, output := filepath.Join(dir, "followup.ll"), filepath.Join(dir, "followup.o")
					if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
						t.Fatal(err)
					}
					x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple="+target.triple, "-filetype=obj", input, "-o", output))
					if info, err := os.Stat(output); err != nil || info.Size() == 0 {
						t.Fatalf("%s/%s missing real LLVM object: %v", api, level, err)
					}
				}
			}
		})
	}
}
