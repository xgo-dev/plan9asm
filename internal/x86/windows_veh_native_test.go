package x86

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// Exercise the foreign entry point as Windows calls it. A freestanding PE32
// needs neither a 32-bit CRT nor a matching host Go ABI.
func TestWindows386VEHNativeEntry(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE32 execution requires Windows")
	}
	exe, err := buildVEHExecutable(t, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(exe).CombinedOutput(); err != nil {
		t.Fatalf("PE32 callback returned failure: %v\n%s", err, out)
	}
}

func buildVEHExecutable(t *testing.T, dir string) (string, error) {
	t.Helper()
	const triple = "i686-pc-windows-msvc"
	opt := asm.Options{Goarch: "386", TargetTriple: triple, ResolveSym: func(s string) string {
		return strings.NewReplacer("runtime·", "", "<>", "").Replace(s)
	}, Sigs: map[string]asm.FuncSig{
		"sigtrampgo": {Name: "sigtrampgo", Args: []asm.LLVMType{asm.Ptr, asm.I32}, Ret: asm.I32},
	}}
	file, err := asm.Parse(asm.ArchAMD64, `TEXT runtime·lastcontinuetramp(SB),4,$0
MOVL argframe+0(FP),AX
MOVL $2,CX
JMP sigtramp<>(SB)`)
	if err != nil {
		return "", err
	}
	dispatch := asm.Func{Sym: "sigtramp<>", Instrs: append([]asm.Instr{{Op: asm.OpTEXT}}, vehDispatchBody...)}
	var ir strings.Builder
	ir.WriteString("target triple = \"" + triple + "\"\n")
	for _, fn := range []asm.Func{dispatch, file.Funcs[0]} {
		sig := asm.FuncSig{Name: opt.ResolveSym(fn.Sym), Ret: asm.Void}
		ok, err := translateWindows386Entry(&ir, fn, sig, opt)
		if !ok || err != nil {
			t.Fatalf("missing foreign adapter for %s: %v", fn.Sym, err)
		}
	}
	ir.WriteString(`
define i32 @sigtrampgo(ptr, i32) naked {
  call void asm sideeffect "leal 4(%esp), %eax; testl $$15, %eax; jnz 1f; movl 4(%esp), %eax; addl 8(%esp), %eax; retl; 1: ud2", ""()
  unreachable
}
define i32 @start() naked {
  call void asm sideeffect "pushl %esi; movl %esp,%esi; pushl $$500; calll ${0:c}; cmpl $$502,%eax; jne 1f; cmpl %esp,%esi; jne 1f; xorl %eax,%eax; jmp 2f; 1: movl $$1,%eax; 2: movl %esi,%esp; popl %esi; retl", "i"(ptr @lastcontinuetramp)
  unreachable
}`)
	src := filepath.Join(dir, "veh.ll")
	exe := filepath.Join(dir, "veh.exe")
	if err := os.WriteFile(src, []byte(ir.String()), 0600); err != nil {
		return "", err
	}
	clang, err := exec.LookPath("clang")
	if err != nil {
		return "", err
	}
	ver, err := exec.Command(clang, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(ver), "clang version 22.") {
		t.Fatalf("LLVM 22 clang required: %v, %s", err, ver)
	}
	cmd := exec.Command(clang, "--target="+triple, "-O2", "-nostdlib", "-fuse-ld=lld", "-Wl,/entry:start,/subsystem:console,/nodefaultlib,/safeseh:no", src, "-o", exe)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("link PE32: %v\n%s", err, out)
	}
	return exe, nil
}
