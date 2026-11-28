package plan9asm

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64NativeSystemCalls(t *testing.T) {
	const src = `TEXT raw(SB),NOSPLIT,$0-24
	MOVQ n+0(FP), AX
	MOVQ fd+8(FP), DI
	MOVQ $0,DX
	SYSCALL
	JCC ok
	NEGQ AX
ok:
	MOVQ AX,ret+16(FP)
	RET
TEXT ninth(SB),NOSPLIT,$0-8
	SUBQ $32,SP
	MOVQ $17,8(SP)
	MOVQ $23,16(SP)
	MOVQ $41,24(SP)
	MOVQ $0x2000014,AX
	SYSCALL
	ADDQ $32,SP
	MOVQ AX,ret+0(FP)
	RET
`
	f, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	sig := crossAddSig("amd64")
	sig.Name = "raw"
	opts := Options{Goarch: "amd64", Sigs: map[string]FuncSig{"raw": sig, "ninth": {Name: "ninth", Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Type: I64, Field: -1}}}}}}
	for _, target := range []string{"x86_64-apple-macosx", "x86_64-unknown-freebsd", "x86_64-unknown-netbsd", "x86_64-unknown-dragonfly"} {
		opts.TargetTriple = target
		ll, err := Translate(f, opts)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(ll, "@syscall(") || !strings.Contains(ll, "={@ccc}") {
			t.Fatalf("%s missing native carry and errno ABI", target)
		}
		ll = runOptO2(t, ll)
		verifyLLVMWithTargetLLC(t, ll, target)
		if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && target == "x86_64-unknown-freebsd" {
			// A native user-mode oracle inspects the syscall stack exactly at the
			// kernel boundary. Weight each argument to detect offset swaps.
			const gate = "syscall; leaq 160(%rsp), %rsp"
			const oracle = "imulq $$10000, 8(%rsp), %rax; imulq $$100, 16(%rsp), %r11; addq %r11, %rax; addq 24(%rsp), %rax; clc; leaq 160(%rsp), %rsp"
			if strings.Count(ll, gate) != 1 {
				t.Fatal("expected exactly one stack-argument syscall")
			}
			compileAndRunRuntimeTestWithCompiler(t, findLLVM22Tool("llc"), []string{"cc"}, "bsd-stack", "x86_64-unknown-linux-gnu", strings.Replace(ll, gate, oracle, 1), `
extern long ninth(void);
int main(void){return ninth() != 172341;}
`, nil)
		}
		if runtime.GOOS == "darwin" && runtime.GOARCH == "amd64" && target == "x86_64-apple-macosx" {
			compileAndRunRuntimeTestWithCompiler(t, findLLVM22Tool("llc"), []string{"cc"}, "bsd", target, ll, `
#include <unistd.h>
extern long raw(long,long);
int main(void){ return raw(0x2000014,0)!=getpid() || raw(0x2000006,-1)!=-9; }
`, nil)
		}
	}
	for _, target := range []string{"", "x86_64-pc-windows-msvc", "aarch64-unknown-linux-gnu", "i386-unknown-linux-gnu"} {
		opts.TargetTriple = target
		if _, err := Translate(f, opts); !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%q: want explicit syscall target error, got %v", target, err)
		}
	}
}

func TestX86ResumableBreakpoint(t *testing.T) {
	for _, tc := range []struct{ arch, triple string }{{"amd64", "x86_64-unknown-linux-gnu"}, {"386", "i386-unknown-linux-gnu"}} {
		f, err := Parse(ArchAMD64, "TEXT probe(SB),4,$0-4\nINT $3\nMOVL $42,AX\nMOVL AX,ret+0(FP)\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		opt := Options{TargetTriple: tc.triple, Goarch: tc.arch, Sigs: map[string]FuncSig{"probe": {Name: "probe", Ret: I32, Frame: FrameLayout{Results: []FrameSlot{{Type: I32, Field: -1}}}}}}
		ll, err := Translate(f, opt)
		if err != nil {
			t.Fatal(err)
		}
		ll = runOptO2(t, ll)
		body := extractLLVMFuncBody(t, ll, "probe")
		if !strings.Contains(body, `asm sideeffect "int3"`) || !strings.Contains(body, "ret i32 42") {
			t.Fatalf("lost breakpoint or continuation: %s", body)
		}
		verifyLLVMWithTargetLLC(t, ll, tc.triple)
		if runtime.GOOS == "linux" && runtime.GOARCH == tc.arch {
			compileAndRunRuntimeTestWithCompiler(t, findLLVM22Tool("llc"), []string{"cc"}, "breakpoint", tc.triple, ll, `
#include <signal.h>
static volatile sig_atomic_t seen;
static void hit(int sig){ if (sig == SIGTRAP) ++seen; }
extern int probe(void);
int main(void){signal(SIGTRAP, hit); return probe()!=42 || seen!=1;}
`, nil)
		}
		for _, invalid := range []string{"INT", "INT $4", "INT $256", "INT AX"} {
			f, err := Parse(ArchAMD64, "TEXT probe(SB),4,$0-4\n"+invalid+"\nRET\n")
			if err != nil {
				continue
			}
			if _, err = Translate(f, opt); err == nil {
				t.Fatalf("%s accepted %q", tc.arch, invalid)
			}
		}
	}
}
