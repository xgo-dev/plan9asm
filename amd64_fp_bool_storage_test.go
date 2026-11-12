package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// A Go bool occupies one canonical byte in ABI0 memory, even though its LLVM
// argument and result have type i1. These sources exercise the actual byte
// backing, including indirect writes through LEA, not just the SSA value.
func x86BoolFrameSource(arch string) string {
	lea, word := "LEAQ", 8
	if arch == "386" {
		lea, word = "LEAL", 4
	}
	source := fmt.Sprintf(`TEXT ·ReadByte(SB),4,$0-%d
%s x+0(FP),AX
MOVB (AX),BX
MOVB BX,ret+%d(FP)
RET
TEXT ·WriteParam(SB),4,$0-%d
%s x+0(FP),AX
MOVB $1,(AX)
MOVB x+0(FP),BX
MOVB BX,ret+%d(FP)
RET
TEXT ·WriteResult(SB),4,$0-%d
MOVB x+0(FP),BX
%s ret+%d(FP),AX
MOVB BX,(AX)
RET
TEXT ·WriteDirect(SB),4,$0-%d
MOVB $0,x+0(FP)
MOVB x+0(FP),BX
MOVB BX,ret+%d(FP)
RET
`, word+1, lea, word, word+1, lea, word, word+1, lea, word, word+1, word)
	source += fmt.Sprintf(`TEXT ·BoolCallee(SB),4,$0-%d
%s x+0(FP),AX
MOVB (AX),BX
MOVB BX,ret+%d(FP)
RET
TEXT ·BoolCaller(SB),4,$16-%d
MOVB x+0(FP),AX
MOVB AX,0(SP)
CALL ·BoolCallee(SB)
MOVB %d(SP),AX
MOVB AX,ret+%d(FP)
RET
TEXT ·BoolField(SB),4,$0-%d
%s p_flag+1(FP),AX
MOVB (AX),BX
MOVB BX,ret+%d(FP)
RET
`, word+1, lea, word, word+1, word, word, word+1, lea, word)
	return source
}

func x86BoolFrameIR(t *testing.T, arch, triple string) string {
	t.Helper()
	source := x86BoolFrameSource(arch)
	requireX86GoAssemblerResult(t, arch, source, true)
	pkg := mustGoPackage(t, "example.com/boolframe", `package boolframe
func ReadByte(x bool) uint8
func WriteParam(x bool) bool
func WriteResult(x bool) bool
func WriteDirect(x bool) bool
func BoolCallee(x bool) bool
func BoolCaller(x bool) bool
func BoolField(p struct { Pad uint8; Flag bool }) bool
`)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	translation, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
		GOARCH: arch, TargetTriple: triple,
		ResolveSym: func(s string) string { return strings.TrimPrefix(s, "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer translation.Module.Dispose()
	ir := translation.Module.String()
	for _, unsafeBacking := range []string{
		"%fp_arg_0 = alloca i1", "%fp_ret_0 = alloca i1",
	} {
		if strings.Contains(ir, unsafeBacking) {
			t.Fatalf("Go bool uses a sub-byte backing store: %s", unsafeBacking)
		}
	}
	// This LLVM caller keeps the exact aggregate type. A C struct parameter
	// would use C's ABI coercions and is not an oracle for this LLVM boundary.
	return ir + `
define i1 @BoolFieldWrapper(i1 %flag) {
entry:
  %pad = insertvalue { i8, i1 } undef, i8 17, 0
  %input = insertvalue { i8, i1 } %pad, i1 %flag, 1
  %result = call i1 @BoolField({ i8, i1 } %input)
  ret i1 %result
}
`
}

func TestX86BoolFrameCanonicalByteObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			ir := x86BoolFrameIR(t, target.arch, target.triple)
			compileLLVMToObject(t, llc, target.triple, "bool-frame.ll", "bool-frame.o", ir)
		})
	}
}

func x86BoolFrameGoOracle(t *testing.T, arch string, runPrefix []string) {
	t.Helper()
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod":              "module example.com/boolframe\n\ngo 1.20\n",
		"bool_" + arch + ".s": x86BoolFrameSource(arch),
		"bool_test.go": `package boolframe
import "testing"
func ReadByte(x bool) uint8
func WriteParam(x bool) bool
func WriteResult(x bool) bool
func WriteDirect(x bool) bool
func BoolCallee(x bool) bool
func BoolCaller(x bool) bool
func BoolField(p struct { Pad uint8; Flag bool }) bool
func TestCanonicalBytes(t *testing.T) {
  for i := 0; i < 1024; i++ {
    for _, x := range []bool{false, true} {
      want := uint8(0)
      if x { want = 1 }
      if ReadByte(x) != want || !WriteParam(x) || WriteResult(x) != x || WriteDirect(x) {
        t.Fatalf("canonical Go bool frame failed for %v", x)
      }
      if BoolCallee(x) != x || BoolCaller(x) != x || BoolField(struct { Pad uint8; Flag bool }{17, x}) != x {
        t.Fatalf("canonical Go bool call/aggregate failed for %v", x)
      }
    }
  }
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"test", "-vet=off", "-count=1"}
	if len(runPrefix) != 0 {
		args = append(args, "-exec", strings.Join(runPrefix, " "))
	}
	cmd := exec.Command("go", append(args, ".")...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOARCH="+arch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Go %s bool byte oracle: %v\n%s", arch, err, out)
	}
}

func TestCrossLinuxRuntimeMatrixX86BoolFrameCanonicalBytes(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("x86 byte ABI oracle runs in the required Linux/amd64 cross-runtime gate")
	}
	x86BoolFrameGoOracle(t, "amd64", nil)
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	var runPrefix []string
	if crossRosetta {
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	const main = `#include <stdbool.h>
#include <stdint.h>
extern uint8_t ReadByte(bool);
extern bool WriteParam(bool), WriteResult(bool), WriteDirect(bool);
extern bool BoolCallee(bool), BoolCaller(bool), BoolFieldWrapper(bool);
int main(void) {
  for (unsigned i = 0; i < 1024; i++) {
    for (unsigned x = 0; x < 2; x++) {
      volatile uint64_t canary = UINT64_C(0x123456789abcdef0);
      if (ReadByte(x) != x || !WriteParam(x) || WriteResult(x) != x || WriteDirect(x)) return 1;
      if (canary != UINT64_C(0x123456789abcdef0)) return 2;
      if (BoolCallee(x) != x || BoolCaller(x) != x || BoolFieldWrapper(x) != x) return 3;
    }
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "bool_frame", triple,
		x86BoolFrameIR(t, "amd64", triple), main, runPrefix)
	if os.Getenv("PLAN9ASM_CROSS_EXEC") == "1" {
		if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
			t.Fatal("PLAN9ASM_CROSS_EXEC bool matrix requires Linux/amd64")
		}
		prefix := []string{"qemu-i386", "-L", "/usr/i686-linux-gnu"}
		x86BoolFrameGoOracle(t, "386", prefix)
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{"i686-linux-gnu-gcc", "-no-pie"},
			"bool_frame386", "i386-unknown-linux-gnu", x86BoolFrameIR(t, "386", "i386-unknown-linux-gnu"), main, prefix)
	}
}
