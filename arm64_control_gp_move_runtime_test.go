package plan9asm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type arm64GPMoveOracle struct {
	text, goValue, cValue string
}

func arm64GPMoveOracles() []arm64GPMoveOracle {
	var forms []arm64GPMoveOracle
	for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
		goValue, cValue := "a", "a"
		if op != "MOVD" {
			bits := arm64RawPrivateScalarBytes(Op(op)) * 8
			if strings.HasSuffix(op, "U") {
				goValue = fmt.Sprintf("uint64(uint%d(a))", bits)
				cValue = fmt.Sprintf("(uint64_t)(uint%d_t)a", bits)
			} else {
				goValue = fmt.Sprintf("uint64(int%d(a))", bits)
				cValue = fmt.Sprintf("(uint64_t)(int%d_t)a", bits)
			}
		}
		for _, input := range []string{"R4", "R30"} {
			forms = append(forms, arm64GPMoveOracle{op + " " + input + ",R30", goValue, cValue})
		}
		forms = append(forms, arm64GPMoveOracle{op + " ZR,R30", "uint64(0)", "0"})
		forms = append(forms, arm64GPMoveOracle{op + " $0,R30", "uint64(0)", "0"})
	}
	for _, op := range []string{"MOVW", "MOVD"} {
		for _, literal := range []int64{-601, 806, 0x12340000} {
			value := uint64(literal)
			if op != "MOVD" {
				value = uint64(uint32(literal))
			}
			forms = append(forms, arm64GPMoveOracle{
				text:    fmt.Sprintf("%s $%d,R30", op, literal),
				goValue: fmt.Sprintf("uint64(%d)", value),
				cValue:  fmt.Sprintf("UINT64_C(%d)", value),
			})
		}
	}
	return forms
}

func TestCrossLinuxRuntimeMatrixARM64GPMoveSourceInputs(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	var source, goDecls, goChecks, cDecls, cChecks strings.Builder
	sigs := make(map[string]FuncSig)
	forms := arm64GPMoveOracles()
	for index, form := range forms {
		name := fmt.Sprintf("gpMoveCaller%d", index)
		body := "MOVD (R0),R4\nMOVD 8(R0),R5\nCMP R5,R4\n"
		if strings.Contains(form.text, " R30,") {
			body += "MOVD R4,R30\n"
		}
		body += form.text + "\nMOVD R30,(R1)\n" +
			"CSET VS,R7\nCSET CS,R8\nLSL $1,R8\nORR R8,R7\n" +
			"CSET EQ,R8\nLSL $2,R8\nORR R8,R7\nCSET MI,R8\nLSL $3,R8\nORR R8,R7\nMOVD R7,8(R1)\n"
		source.WriteString(strings.Replace(arm64RawZeroFrameFixture(516, false, body), "rawZero", name, 1))
		sig := arm64RawZeroFrameSig()
		sig.Name = name
		sigs[name] = sig
		fmt.Fprintf(&goDecls, "func %s(*byte, *byte)\n", name)
		fmt.Fprintf(&goDecls, "func expected%d(a, b, c uint64) (uint64, uint64) {\n result := %s\n return result, flags(a, b, result, 2, 64)\n}\n", index, form.goValue)
		fmt.Fprintf(&cDecls, "extern void %s(const unsigned char *, unsigned char *);\n", name)
		fmt.Fprintf(&cDecls, "static uint64_t expected%d(uint64_t a, uint64_t b, uint64_t c, uint64_t *nzcv) {\n uint64_t result = %s;\n *nzcv = flags(a, b, result, 2, 64);\n return result;\n}\n", index, form.cValue)
		fmt.Fprintf(&goChecks, "check(%s, expected%d)\n", name, index)
		fmt.Fprintf(&cChecks, "if (check(%s, expected%d)) { return 1; }\n", name, index)
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":  "module gpmovecalleroracle\n\ngo 1.20\n",
		"main.go": arm64GPDataOracleGo + goDecls.String() + "func main() {\n" + goChecks.String() + "}\n",
		"oracle_arm64.s": strings.ReplaceAll(source.String(), "TEXT gpMoveCaller", "TEXT ·gpMoveCaller") +
			"\nTEXT ·readGoG(SB),516,$0-8\nMOVD g,R0\nMOVD R0,ret+0(FP)\nRET\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	args := []string{"run", "-p=1", "."}
	if len(runner) != 0 {
		args = []string{"run", "-p=1", "-exec=qemu-aarch64", "."}
	}
	command := exec.CommandContext(ctx, "go", args...)
	command.Dir = dir
	command.Env = append(os.Environ(), "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if len(runner) != 0 {
		command.Env = append(command.Env, "GOOS=linux")
	}
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual Go scalar MOV/LR/canary oracle: %v\n%s", err, output)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "gp_move_caller", triple, ir,
		arm64GPDataOracleC+cDecls.String()+"int main(void) {\n"+cChecks.String()+"return 0;\n}\n", runner)
	t.Logf("%d original Go/LLVM move forms x 128 patterns x 5 unaligned offsets; numeric/NZCV/canaries/caller g and LR", len(forms))
}
