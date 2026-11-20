package plan9asm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func arm64LocalRegisterBranchSig(name string) FuncSig {
	return FuncSig{Name: name, Args: []LLVMType{I64}, Ret: I64, Frame: FrameLayout{
		Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
		Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
	}}
}

func TestARM64RegisterControlCompleteGoForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	forms := 0
	for _, op := range []string{"B", "JMP", "BL", "CALL", "RET"} {
		operands := []string{"(R0)", "0(R(1))", "(LR)", "(R30)", "(g)", "(R18_PLATFORM)", "(ZR)", "(RSP)"}
		if op == "BL" || op == "CALL" || op == "RET" {
			operands = append(operands, "R0", "R(1)", "LR", "R30", "g", "R18_PLATFORM", "ZR")
		}
		if op == "RET" {
			operands = append(operands, "8(R0)", "(R0)(R1)", "RSP", "$1")
		}
		for _, operand := range operands {
			for _, marker := range []string{"", "*"} {
				if strings.HasPrefix(operand, "$") && marker != "" {
					continue // '*' accepts register/memory operands, not immediates.
				}
				name := fmt.Sprintf("registerForm%d", forms)
				forms++
				prefix, suffix := "", "RET\n"
				if op == "B" || op == "JMP" || op == "BL" || op == "CALL" || op == "RET" {
					target, err := parseOperandForArch(ArchARM64, operand)
					if err != nil {
						t.Fatal(err)
					}
					reg := target.Reg
					if target.Kind == OpMem {
						reg = target.Mem.Base
					}
					if op == "RET" && target.Kind == OpImm {
						reg = Reg("R30")
					}
					if reg != ZR && reg != SP && reg != Reg("RSP") {
						spelling := string(reg)
						if reg == Reg("R28") {
							spelling = "g"
						}
						if reg == Reg("R18") {
							spelling = "R18_PLATFORM"
						}
						prefix = fmt.Sprintf("MOVD R30,R19\nADR localTarget,%s\n", spelling)
						if op == "BL" || op == "CALL" {
							suffix = "MOVD R19,R30\nRET\nlocalTarget:\nB (R30)\n"
						} else {
							suffix = "localTarget:\nMOVD R19,R30\nRET\n"
						}
					} else if op == "BL" || op == "CALL" {
						suffix = "B (ZR)\n"
					} else {
						suffix = ""
					}
				}
				fmt.Fprintf(&source, "TEXT %s(SB),516,$0-0\n%s%s %s%s\n%s", name, prefix, op, marker, operand, suffix)
				sigs[name] = FuncSig{Name: name, Ret: Void}
			}
		}
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(ir, "callbr") {
				t.Fatal("opaque blockaddress must not escape through asm-goto labels")
			}
			compileLLVMToObject(t, llc, triple, "register-control.ll", "register-control.o", ir)
		})
	}
	t.Logf("Go assembler and LLVM 22 accepted %d register/alias/indirect-marker forms on four targets", forms)
}

func TestARM64RegisterControlRejectsGoInvalidForms(t *testing.T) {
	var instructions []string
	for _, op := range []string{"B", "JMP", "BL", "CALL", "RET"} {
		operands := []string{"V0", "(V0)", "R0, R1"}
		if op != "RET" {
			operands = append(operands, "8(R0)", "(R0)(R1)", "$1", "RSP")
		}
		for _, operand := range operands {
			instructions = append(instructions, op+" "+operand)
		}
		instructions = append(instructions, op+".P (R0)", op+".W (R0)")
	}
	instructions = append(instructions, "B R0", "JMP R0", "RET *$1")
	for _, instruction := range instructions {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT badRegisterControl(SB),$0-0\n" + instruction + "\nRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{"badRegisterControl": {Name: "badRegisterControl", Ret: Void}}})
			if err == nil {
				t.Fatalf("accepted Go-rejected %q", instruction)
			}
		})
	}
}

func TestARM64LocalControlRejectsUnprovedAddressProvenance(t *testing.T) {
	for name, body := range map[string]string{
		"mixed_join":          "ADR target, R1\nCBZ R0, jump\nMOVD R0, R1\njump:\nB (R1)",
		"mixed_caller_local":  "MOVD R30,R1\nCBZ R0,jump\nADR target,R1\njump:\nB (R1)",
		"arithmetic":          "ADR target, R1\nADD $4, R1\nB (R1)",
		"bit_transform":       "ADR target, R1\nEOR R0, R1\nB (R1)",
		"partial_frame_write": "ADR target, R1\nMOVD R1, 24(RSP)\nMOVB R0, 27(RSP)\nMOVD 24(RSP), R2\nB (R2)",
		"escaped_memory":      "ADR target, R1\nMOVD R1, (R0)\nMOVD (R0), R2\nB (R2)",
		"unproved_pair_load":  "ADR target, R1\nMOVD R1, 24(RSP)\nLDPW 24(RSP), (R2,R3)\nB (R2)",
	} {
		t.Run(name, func(t *testing.T) {
			source := "TEXT provenance(SB),$48-0\n" + body + "\ntarget:\nRET\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{"provenance": {Name: "provenance", Ret: Void}}})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved address did not fail closed: %v", err)
			}
		})
	}
}

func TestARM64LocalControlRejectsCrossAllocaFPAlias(t *testing.T) {
	const source = `TEXT fpAlias(SB),$48-16
MOVD $a+0(FP),R10
ADR target,R1
MOVD R1,8(R10)
MOVD b+8(FP),R2
B (R2)
target:
RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{"fpAlias": {
		Name: "fpAlias", Args: []LLVMType{I64, I64}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: I64, Index: 0, Field: -1},
			{Offset: 8, Type: I64, Index: 1, Field: -1},
		}},
	}}})
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("FP scalar allocations are independent; cross-slot pointer must fail closed: %v", err)
	}
}

func runARM64LocalRegisterGoOracle(t *testing.T, source, main string, cross bool, minimumVersions ...string) {
	t.Helper()
	// These first-party fixtures also exercise the Go 1.20 compatibility lane.
	// A caller needing newer language semantics must request them explicitly.
	minimum := "1.20"
	if len(minimumVersions) > 1 {
		t.Fatal("native Go oracle requires at most one module Go minimum")
	}
	if len(minimumVersions) == 1 {
		minimum = minimumVersions[0]
	}
	dir := t.TempDir()
	for name, data := range map[string]string{
		"go.mod":  "module localregisteroracle\n\ngo " + minimum + "\n",
		"main.go": main, "oracle_arm64.s": source,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"run", "-p=2", "."}
	env := append(os.Environ(), "GOARCH=arm64", "CGO_ENABLED=0")
	if cross {
		args = []string{"run", "-p=2", "-exec=qemu-aarch64", "."}
		env = append(env, "GOOS=linux")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir, cmd.Env = dir, env
	if out, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
		t.Fatalf("native Go local register-branch oracle: %v\n%s", err, out)
	}
	t.Log("native Go local register-branch oracle passed")
}

func TestCrossLinuxRuntimeMatrixARM64LocalRegisterReturn(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	var source, goDecl, cDecl, goChecks, cChecks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, op := range []string{"BL", "CALL"} {
		name := "localRegister" + op
		fmt.Fprintf(&source, "TEXT ·%s(SB),$0-16\nMOVD a+0(FP), R0\n%s helper\nADD $2, R0\nMOVD R0, ret+8(FP)\nRET\nhelper:\nADD $5, R0\nB (R30)\n", name, op)
		sigs[name] = arm64LocalRegisterBranchSig(name)
		fmt.Fprintf(&goDecl, "func %s(uint64) uint64\n", name)
		fmt.Fprintf(&cDecl, "extern uint64_t %s(uint64_t);\n", name)
		fmt.Fprintf(&goChecks, "if got := %s(123); got != 130 { println(got); panic(\"local-return mismatch\") }\n", name)
		fmt.Fprintf(&cChecks, "if (%s(123) != 130) { fprintf(stderr, \"%s local-return mismatch\\n\"); return 1; }\n", name, name)
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	runARM64LocalRegisterGoOracle(t, source.String(), "package main\n"+goDecl.String()+"func main() {\n"+goChecks.String()+"}\n", len(runner) != 0)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") }, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := "#include <stdint.h>\n#include <stdio.h>\n" + cDecl.String() + "int main(void) {\n" + cChecks.String() + "return 0;\n}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "local_register_return", triple, ir, main, runner)
}
