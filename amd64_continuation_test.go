package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The empty helper declarations describe Go entries, not the register/frame
// contract of a JMP from another TEXT. This fixture borrows the root frame.
const x86ContinuationSource = `
TEXT ·initTable(SB),$0-0
 LEAQ ·step(SB),AX
 MOVQ AX,table<>(SB)
 RET
GLOBL table<>(SB),16,$8
TEXT ·run(SB),$0-24
 MOVQ out+0(FP),DI
 MOVQ n+8(FP),BX
 MOVQ $7,R15
 MOVQ R15,X13
 LEAQ table<>(SB),R14
 XORQ R15,R15
 TESTQ BX,BX
 JEQ done
dispatch:
 MOVQ (R14),AX
 JMP AX
done:
 JMP ·exit(SB)
TEXT ·step(SB),$0-0
 MOVQ X13,DX
 ADDQ DX,R15
 SUBQ $1,BX
 JMP ·check(SB)
TEXT ·check(SB),$0-0
 JEQ done
 MOVQ (R14),AX
 JMP AX
done:
 JMP ·exit(SB)
TEXT ·exit(SB),$0-0
 MOVQ R15,(DI)
 MOVQ R15,result+16(FP)
 RET
`

func x86ContinuationOptions(triple string) Options {
	return Options{
		Goarch: "amd64", TargetTriple: triple,
		X86TailGroups: []X86TailGroup{{Root: "·run", Helpers: []string{"·step", "·check", "·exit"}}},
		ResolveSym:    func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"initTable": {Ret: Void},
			"run": {
				Args: []LLVMType{Ptr, I64}, Ret: I64,
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: -1},
						{Offset: 8, Type: I64, Index: 1, Field: -1},
					},
					Results: []FrameSlot{{Offset: 16, Type: I64, Index: 0, Field: -1}},
				},
			},
			"step": {Ret: Void}, "check": {Ret: Void}, "exit": {Ret: Void},
		},
	}
}

func TestX86ContinuationBorrowedFrame(t *testing.T) {
	requireX86GoAssemblerResult(t, "amd64", x86ContinuationSource, true)
	ir := x86ContinuationIR(t, "x86_64-unknown-linux-gnu", x86ContinuationSource)
	if !strings.Contains(ir, "indirectbr") || !strings.Contains(ir, "blockaddress") {
		t.Fatal("continuations must branch within the root CFG")
	}
	if strings.Contains(ir, "define void @step") || strings.Contains(ir, "call i64 %") {
		t.Fatal("a continuation must not be emitted as a fresh function invocation")
	}
}

func x86ContinuationIR(t *testing.T, triple, source string) string {
	t.Helper()
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, x86ContinuationOptions(triple))
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func TestX86ContinuationLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH == "amd64" || crossRosetta {
		runX86ContinuationGo(t)
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			for _, memoryJump := range []bool{false, true} {
				source := x86ContinuationSource
				if memoryJump {
					source = strings.ReplaceAll(source, " MOVQ (R14),AX\n JMP AX", " JMP (R14)")
				}
				ir := x86ContinuationIR(t, triple, source)
				compileLLVMToObject(t, llc, triple, "continuation.ll", "continuation.o", ir)
				if (runtime.GOARCH == "amd64" && runtime.GOOS == "linux" && triple == "x86_64-unknown-linux-gnu") ||
					((runtime.GOARCH == "amd64" || crossRosetta) && runtime.GOOS == "darwin" && triple == "x86_64-apple-darwin") {
					clang := findLLVM22Tool("clang")
					if clang == "" {
						t.Fatal("LLVM 22 clang not found")
					}
					runX86Continuation(t, llc, clang, triple, ir)
				}
			}
		})
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir := x86Continuation386IR(t, triple)
			compileLLVMToObject(t, llc, triple, "continuation386.ll", "continuation386.o", ir)
		})
	}
}

func x86Continuation386IR(t *testing.T, triple string) string {
	t.Helper()
	source := strings.NewReplacer(
		" MOVQ R15,X13\n", "", " MOVQ X13,DX\n ADDQ DX,R15", " ADDL $7,DX",
		"R15", "DX", "R14", "SI", "MOVQ", "MOVL", "LEAQ", "LEAL",
		"XORQ", "XORL", "TESTQ", "TESTL", "SUBQ", "SUBL",
		"n+8(FP)", "n+4(FP)", "result+16(FP)", "result+8(FP)",
		"$0-24", "$0-12", "GLOBL table<>(SB),16,$8", "GLOBL table<>(SB),16,$4",
	).Replace(x86ContinuationSource)
	requireX86GoAssemblerResult(t, "386", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	opt := x86ContinuationOptions(triple)
	opt.Goarch = "386"
	sig := opt.Sigs["run"]
	sig.Args[1], sig.Ret = I32, I32
	sig.Frame.Params[1].Offset, sig.Frame.Params[1].Type = 4, I32
	sig.Frame.Results[0].Offset, sig.Frame.Results[0].Type = 8, I32
	opt.Sigs["run"] = sig
	ir, err := Translate(file, opt)
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func runX86Continuation(t *testing.T, llc, clang, triple, ir string) {
	t.Helper()
	if dir := os.Getenv("PLAN9ASM_RUNTIME_ARTIFACT_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string]string{"continuation.ll": ir, "main.c": x86ContinuationMain} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	compiler := []string{clang}
	var runner []string
	if runtime.GOARCH != "amd64" && strings.Contains(triple, "darwin") {
		compiler = append(compiler, "-target", triple)
		runner = []string{"/usr/bin/arch", "-x86_64"}
	}
	if strings.Contains(triple, "linux") {
		// The shared harness invokes llc with its default static relocation
		// model. Match that object when linking a native executable.
		compiler = append(compiler, "-no-pie")
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "continuation", triple, ir, x86ContinuationMain, runner)
}

func runX86ContinuationGo(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod":               "module example.com/continuation\n\ngo 1.20\n",
		"continuation_amd64.s": strings.ReplaceAll(x86ContinuationSource, "(SB),$0-", "(SB),4,$0-"),
		"continuation.go":      "package p\nfunc initTable()\nfunc run(out *uint64, n uint64) (result uint64)\nfunc step()\nfunc check()\nfunc exit()\n",
		"continuation_test.go": `package p
import "testing"
func TestState(t *testing.T) {
  initTable()
  for _, n := range []uint64{0, 1, 2, 19, 100000} {
    out := [3]uint64{0x1234, ^uint64(0), 0x5678}
    result := run(&out[1], n)
    if result != n*7 || out[1] != result || out[0] != 0x1234 || out[2] != 0x5678 {
      t.Fatalf("n=%d result=%d out=%v", n, result, out)
    }
  }
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// asmdecl describes callable entries, not the helpers' borrowed frame.
	// This oracle tests Go's actual assembler/linker/runtime semantics.
	cmd := exec.Command("go", "test", "-vet=off", "-count=1", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native Go continuation oracle: %v\n%s", err, out)
	}
}

func TestX86ContinuationRejectsInvalidGroups(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*File, *Options)
	}{
		{"other_arch", func(f *File, o *Options) { f.Arch = ArchWASM; o.Goarch = "wasm" }},
		{"missing_root", func(f *File, o *Options) { o.X86TailGroups[0].Root = "absent" }},
		{"missing_helper", func(f *File, o *Options) { o.X86TailGroups[0].Helpers[0] = "absent" }},
		{"duplicate", func(f *File, o *Options) { o.X86TailGroups = append(o.X86TailGroups, o.X86TailGroups[0]) }},
		{"empty", func(f *File, o *Options) { o.X86TailGroups[0].Helpers = nil }},
		{"local_frame", func(f *File, o *Options) { f.Funcs[2].FrameSize = 8 }},
		{"root_frame", func(f *File, o *Options) { f.Funcs[1].FrameSize = 8 }},
		{"fallthrough", func(f *File, o *Options) { f.Funcs[2].Instrs = append(f.Funcs[2].Instrs, Instr{Op: "NOP"}) }},
		{"code_read", func(f *File, o *Options) { f.Funcs[0].Instrs[1].Op = "MOVQ" }},
		{"arg_frame", func(f *File, o *Options) { f.Funcs[2].ArgSize = 8 }},
		{"typed_entry", func(f *File, o *Options) { o.Sigs["step"] = FuncSig{Args: []LLVMType{I64}, Ret: Void} }},
		{"callable", func(f *File, o *Options) {
			f.Funcs[0].Instrs[0] = Instr{Op: "CALL", Args: []Operand{{Kind: OpSym, Sym: "·step(SB)"}}}
		}},
		{"offset", func(f *File, o *Options) { f.Funcs[0].Instrs[1].Args[0].Sym = "·step+1(SB)" }},
		{"data", func(f *File, o *Options) { f.Data = []DataStmt{{Sym: "table<>", Width: 8, Addr: "·step(SB)"}} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, x86ContinuationSource)
			if err != nil {
				t.Fatal(err)
			}
			opt := x86ContinuationOptions("x86_64-unknown-linux-gnu")
			test.change(file, &opt)
			if _, err := coalesceX86Continuations(file, opt); err == nil {
				t.Fatal("invalid continuation proof accepted")
			}
		})
	}
}

const x86ContinuationMain = `
#include <stdint.h>
extern void initTable(void);
extern uint64_t run(uint64_t *, uint64_t);
int main(void) {
  initTable();
  const uint64_t counts[] = {0, 1, 2, 19, 100000};
  for (unsigned i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
    uint64_t out[3] = {0x1234, UINT64_MAX, 0x5678};
    uint64_t result = run(out + 1, counts[i]);
    if (result != counts[i] * 7 || out[1] != result ||
        out[0] != 0x1234 || out[2] != 0x5678) return 1;
  }
  return 0;
}
`
