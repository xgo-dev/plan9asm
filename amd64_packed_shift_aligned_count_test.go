package plan9asm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var x86LegacyShiftMemoryOpcodes = []struct {
	name string
	code byte
}{
	{"PSLLW", 0xf1}, {"PSLLL", 0xf2}, {"PSLLQ", 0xf3},
	{"PSRLW", 0xd1}, {"PSRLL", 0xd2}, {"PSRLQ", 0xd3},
}

func TestX86PackedShiftLegacyMemoryActualGoEncoding(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, operation := range x86LegacyShiftMemoryOpcodes {
			source := "TEXT shifts(SB),4,$0-0\n" + operation.name + " (CX),X0\nRET\n"
			dir := t.TempDir()
			input, object := filepath.Join(dir, "original.s"), filepath.Join(dir, "original.o")
			if err := os.WriteFile(input, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			command := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-o", object, input)
			command.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "GOTOOLCHAIN=local")
			output, err := runtimeOracleCombinedOutput(ctx, command)
			cancel()
			if err != nil {
				t.Fatalf("actual Go %s %s: %v\n%s", arch, operation.name, err, output)
			}
			var code []byte
			for _, line := range regexp.MustCompile(`(?m)^\s*0x[[:xdigit:]]+\s+((?:[[:xdigit:]]{2} )+)`).FindAllSubmatch(output, -1) {
				part, err := hex.DecodeString(strings.ReplaceAll(string(line[1]), " ", ""))
				if err != nil {
					t.Fatal(err)
				}
				code = append(code, part...)
			}
			want := []byte{0x66, 0x0f, operation.code, 0x01, 0xc3}
			if !bytes.Equal(code, want) {
				t.Fatalf("actual Go %s %s memory encoding=%x, want=%x\n%s", arch, operation.name, code, want, output)
			}
		}
	}
}

func TestX86PackedShiftNativeCountThreeAPIsFiveO2Objects(t *testing.T) {
	llc, disassembler := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || disassembler == "" {
		t.Fatal("LLVM22 llc and llvm-objdump required")
	}
	var source strings.Builder
	source.WriteString("TEXT shifts(SB),4,$0-0\n")
	for _, operation := range x86LegacyShiftMemoryOpcodes {
		for _, memory := range []string{"(AX)", "8(AX)(FS)", "8(AX)(GS)"} {
			fmt.Fprintf(&source, "%s %s,X0\n", operation.name, memory)
		}
	}
	source.WriteString("RET\n")
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		requireX86GoAssemblerResult(t, target.arch, source.String(), true)
		for _, api := range []string{"text", "module", "Go"} {
			if ir, err := x86ScalarFPBitViewPackageAPI(t, source.String(), x86PackedShiftGoPackage(t, target.arch), target.arch, target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("original native/segment count source invented entry inputs", api, err)
			}
		}
		ir := x86InstructionFormatObjectUnit(t, file, map[string]FuncSig{"shifts": {Name: "shifts", Ret: Void}},
			target.arch, target.triple, 0, func(c *amd64Ctx, ins Instr) (bool, bool, error) {
				return c.lowerX86PackedShift(ins.Op, ins)
			})
		for axis, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
			for _, mnemonic := range []string{"psllw", "pslld", "psllq", "psrlw", "psrld", "psrlq"} {
				for _, segment := range []string{"", "%fs:", "%gs:"} {
					if strings.Count(body, `asm sideeffect "`+mnemonic+` `+segment+`($2), $0", "=x,0,r,~{memory}"`) != 1 {
						t.Fatalf("%s IR%d lost original %s %s m128 count operation", target.triple, axis, mnemonic, segment)
					}
				}
			}
			if strings.Contains(body, `asm sideeffect "movdqa`) {
				t.Fatal("count access was replaced by a stronger MOVDQA access")
			}
			dir := t.TempDir()
			input, object := filepath.Join(dir, "native-count.ll"), filepath.Join(dir, "native-count.o")
			if err := os.WriteFile(input, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			stage, cancel := runtimeOracleStageContext(t)
			command := exec.CommandContext(stage, llc, "-O2", "-mtriple="+target.triple, "-filetype=obj", input, "-o", object)
			output, err := runtimeOracleCombinedOutput(stage, command)
			cancel()
			if err != nil {
				t.Fatalf("O2 %s IR%d: %v\n%s", target.triple, axis, err, output)
			}
			stage, cancel = runtimeOracleStageContext(t)
			command = exec.CommandContext(stage, disassembler, "-d", object)
			output, err = runtimeOracleCombinedOutput(stage, command)
			cancel()
			if err != nil {
				t.Fatalf("O2 disassembly %s IR%d: %v\n%s", target.triple, axis, err, output)
			}
			for _, mnemonic := range []string{"psllw", "pslld", "psllq", "psrlw", "psrld", "psrlq"} {
				pattern := regexp.MustCompile(`(?m)\b` + mnemonic + `\s+[^\n]*\([^\n]*\)`)
				if len(pattern.FindAll(output, -1)) != 3 {
					t.Fatalf("O2 actual original %s m128 count %s IR%d:\n%s", mnemonic, target.triple, axis, output)
				}
			}
			for _, segment := range []string{"%fs:", "%gs:"} {
				if strings.Count(string(output), segment) != 6 {
					t.Fatalf("O2 lost six native %s count overrides %s IR%d:\n%s", segment, target.triple, axis, output)
				}
			}
		}
	}
}

func TestX86PackedShiftLegacyNativeBackingAndCallerPermissionsRemainContext(t *testing.T) {
	for _, operation := range x86LegacyShiftMemoryOpcodes {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+operation.name+" count+0(FP),X0\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
		before := output.Len()
		if _, _, err := ctx.lowerX86PackedShift(ins.Op, ins); !errors.Is(err, ErrProbeNeedsContext) || output.Len() != before {
			t.Fatalf("unproved native FP backing emitted IR: %s %v", operation.name, err)
		}
	}
	// Initialized vectors do not supply native backing or memory permission.
	for _, operation := range x86LegacyShiftMemoryOpcodes {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+operation.name+" (CX),X0\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		form, recognized, err := x86PackedShiftProperties(ins.Op, ins, "amd64")
		if !recognized || err != nil {
			t.Fatal(err)
		}
		state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": ^uint64(0)}}
		if x86CallerPackedShiftStep(&ins, form, &state, nil) {
			t.Fatal("initialized vector granted legacy native-memory permission")
		}
	}
}
