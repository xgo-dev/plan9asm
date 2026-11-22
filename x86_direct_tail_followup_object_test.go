package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
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
	for _, arch := range []string{"386", "amd64"} {
		var source strings.Builder
		source.WriteString("TEXT ·Value(SB),4,$0-0\n CMPL AX,AX\n")
		for name := range names {
			for _, hint := range []string{"", "$0,", "$1,"} {
				source.WriteString(fmt.Sprintf(" %s %s1(PC)\n", name, hint))
			}
		}
		source.WriteString(" JMP 1(PC)\n RET\n")
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
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
