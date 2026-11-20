package plan9asm

import (
	"context"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
)

const x86LinuxSyscallDeclaration = `func Raw(number, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr)`

// Complete Linux AMD64 register inputs and the original two-result ABI0 form.
// DX is both the third argument and a preserved register after normal return.
//
//go:embed testdata/amd64/linux-syscall/raw_amd64.s
var x86LinuxSyscallAssembly string

func TestX86LinuxSyscallOriginalGo(t *testing.T) {
	directory := t.TempDir()
	files := make(map[string]string)
	for _, name := range []string{"go.mod.txt", "main.go", "raw_amd64.s"} {
		data, err := os.ReadFile(filepath.Join("testdata/amd64/linux-syscall", name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "go.mod.txt" {
			name = "go.mod"
		}
		files[name] = string(data)
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin/go"), "build", "-p=1", "-mod=readonly", "-o", filepath.Join(directory, "original"), ".")
	command.Dir = directory
	command.Env = append(os.Environ(), "GOROOT="+runtime.GOROOT(), "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOPROXY=off")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("original full Go assembly/ELF link: %v\n%s", err, output)
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		command = exec.CommandContext(ctx, filepath.Join(directory, "original"))
		output, err := command.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "ORIGINAL_RAW_SYSCALL_PASS") {
			t.Fatalf("original Linux raw kernel semantics: %v\n%s", err, output)
		}
		t.Log(strings.TrimSpace(string(output)))
	}
}

func TestX86LinuxSyscallPairedResult(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, x86LinuxSyscallAssembly, x86LinuxSyscallDeclaration, "amd64", "x86_64-unknown-linux-gnu", api)
			if err != nil {
				t.Fatal("paired Linux kernel result transfer", err)
			}
			if !strings.Contains(ir, "asm sideeffect \"syscall\"") || strings.Contains(ir, "call i64 @syscall(") || strings.Contains(ir, "call i32 @cliteErrno(") {
				t.Fatal("Linux raw instruction was replaced by a hosted errno-changing wrapper", ir)
			}
		})
	}
}

// This observes the actual emitter independently of the complete-source audit.
// Its IR is executed against the raw C oracle; generating it is not a semantic
// PASS, nor a public native-entry or source-frame authorization.
func TestX86LinuxSyscallEmitterArtifact(t *testing.T) {
	registers := []Reg{AX, DI, SI, DX, "R10", "R8", "R9"}
	fn := Func{}
	for _, register := range registers {
		fn.Instrs = append(fn.Instrs, Instr{Op: "MOVQ", Args: []Operand{{Kind: OpReg, Reg: register}, {Kind: OpReg, Reg: register}}})
	}
	c, body := newAMD64CtxWithFuncForTest(t, fn, FuncSig{Name: "Raw", Ret: Void}, nil)
	c.targetTriple = "x86_64-unknown-linux-gnu"
	parameters := []string{"number", "a1", "a2", "a3", "a4", "a5", "a6"}
	for index, register := range registers {
		if err := c.storeReg(register, "%"+parameters[index]); err != nil {
			t.Fatal(err)
		}
	}
	if accepted, terminated, err := c.lowerSyscall("SYSCALL", Instr{Op: "SYSCALL", Raw: "SYSCALL"}); !accepted || terminated || err != nil {
		t.Fatal("isolated actual emitter", accepted, terminated, err)
	}
	ax, err := c.loadReg(AX)
	if err != nil {
		t.Fatal(err)
	}
	dx, err := c.loadReg(DX)
	if err != nil {
		t.Fatal(err)
	}
	first, second := c.newTmp(), c.newTmp()
	fmt.Fprintf(body, "  %%%s = insertvalue { i64, i64 } poison, i64 %s, 0\n", first, ax)
	fmt.Fprintf(body, "  %%%s = insertvalue { i64, i64 } %%%s, i64 %s, 1\n  ret { i64, i64 } %%%s\n", second, first, dx, second)
	declarations := make([]string, len(parameters))
	for index, name := range parameters {
		declarations[index] = "i64 %" + name
	}
	ir := "target triple = \"x86_64-unknown-linux-gnu\"\ndeclare i64 @syscall(i64,i64,i64,i64,i64,i64,i64)\ndeclare i32 @cliteErrno()\n" +
		"define { i64, i64 } @Raw(" + strings.Join(declarations, ", ") + ") {\n" + body.String() + "}\n"
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := parseIRModuleInContext(ctx, ir)
	if err != nil {
		t.Fatal("actual emitter artifact is invalid LLVM", err, ir)
	}
	defer module.Dispose()
	if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
		t.Fatal(err)
	}
	t.Log("RAW_SYSCALL_EMITTER_IR_BASE64=" + base64.StdEncoding.EncodeToString([]byte(ir)))
}

func TestX86LinuxSyscallFormAndTarget(t *testing.T) {
	for _, target := range []string{"x86_64-unknown-linux-gnu", "x86_64-linux-gnu"} {
		effect, known, err := x86LinuxSyscallByteEffect(Instr{Op: "SYSCALL", Raw: "SYSCALL"}, "amd64", target)
		if !known || err != nil || !effect.requiresResultProof || len(effect.operands) != 8 || effect.flagsKilled != x86ByteFlagsAll || effect.flagsDefined != 0 {
			t.Fatal("complete target-aware raw effect", target, known, err, effect)
		}
		for index, register := range []Reg{AX, DI, SI, DX, "R10", "R8", "R9"} {
			operand := effect.operands[index]
			if !operand.read || operand.write || operand.width != 8 || operand.operand.Kind != OpReg || operand.operand.Reg != register {
				t.Fatal("kernel input role changed", index, operand)
			}
		}
	}
	for _, target := range []string{"", "x86_64-apple-darwin", "x86_64-pc-windows-msvc", "x86_64-linux-windows-msvc", "i386-unknown-linux-gnu", "wasm32-unknown-unknown"} {
		if _, _, err := x86LinuxSyscallByteEffect(Instr{Op: "SYSCALL", Raw: "SYSCALL"}, "amd64", target); err == nil {
			t.Fatal("unclosed target accepted", target)
		}
	}
}

func TestX86LinuxSyscallInputAndClobberGuards(t *testing.T) {
	for _, row := range []struct{ name, old, replacement string }{
		{"undefined SI", "MOVQ a2+16(FP), SI", "NOP"},
		{"partial SI", "MOVQ a2+16(FP), SI", "MOVB a2+16(FP), SI"},
		{"CX clobbered", "SYSCALL\nMOVQ AX", "MOVQ $7,CX\nSYSCALL\nMOVQ CX,AX\nMOVQ AX"},
		{"R11 clobbered", "SYSCALL\nMOVQ AX", "MOVQ $7,R11\nSYSCALL\nMOVQ R11,AX\nMOVQ AX"},
		{"logical frame escape", "MOVQ a2+16(FP), SI", "LEAQ r1+56(FP), SI"},
		{"flags unknown", "SYSCALL\nMOVQ AX", "CMPQ DI,SI\nSYSCALL\nJEQ 2(PC)\nNOP\nMOVQ AX"},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := strings.Replace(x86LinuxSyscallAssembly, row.old, row.replacement, 1)
			for _, api := range []string{"text", "module", "Go"} {
				_, err := x86ScalarFPBitViewAPI(t, source, x86LinuxSyscallDeclaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("unclosed input, physical result or private frame accepted", api, err)
				}
			}
		})
	}
	// A Void result cannot suppress the kernel's complete source-input proof.
	for _, api := range []string{"text", "module", "Go"} {
		_, err := x86ScalarFPBitViewAPI(t, "TEXT ·Raw(SB),4,$0-0\nSYSCALL\nRET\n", "func Raw()", "amd64", "x86_64-unknown-linux-gnu", api)
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("dead raw kernel effect acquired uninitialized inputs", api, err)
		}
	}
}
