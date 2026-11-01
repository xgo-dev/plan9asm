package plan9asm

import (
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// These wrappers exercise the public Go binding, not only hand-built FuncSigs
// or the command's independent signature inference. See issue #44.
var issue44Cases = []struct {
	name, declarations, assembly, main string
}{
	{
		name: "scalar",
		declarations: `func Y(a, b uint64) uint64
func X(a, b uint64) uint64`,
		assembly: `TEXT ·Y(SB),$24-24
	MOVQ a+0(FP), AX
	MOVQ AX, 0(SP)
	MOVQ b+8(FP), AX
	MOVQ AX, 8(SP)
	CALL ·X(SB)
	MOVQ 16(SP), AX
	MOVQ AX, ret+16(FP)
	RET
`,
		main: `extern uint64_t Y(uint64_t, uint64_t);
uint64_t X(uint64_t a, uint64_t b) { return a * 11 + b * 3; }
int main(void) { return Y(17, 29) == 274 ? 0 : 1; }
`,
	},
	{
		name: "result_only",
		declarations: `func Y() uint64
func X() uint64`,
		assembly: `TEXT ·Y(SB),$8-8
	CALL ·X(SB)
	MOVQ 0(SP), AX
	MOVQ AX, ret+0(FP)
	RET
`,
		main: `extern uint64_t Y(void);
uint64_t X(void) { return UINT64_C(0x123456789abcdef0); }
int main(void) { return Y() == X() ? 0 : 2; }
`,
	},
	{
		name: "frame_pointer_local",
		declarations: `func Y(a uint64) uint64
func X(a uint64) uint64`,
		assembly: `TEXT ·Y(SB),$24-16
	MOVQ a+0(FP), AX
	MOVQ AX, -8(BP)
	MOVQ AX, 0(SP)
	CALL ·X(SB)
	MOVQ -8(BP), BX
	MOVQ 8(SP), AX
	ADDQ BX, AX
	MOVQ AX, ret+8(FP)
	RET
`,
		main: `extern uint64_t Y(uint64_t);
uint64_t X(uint64_t a) { return a * 7; }
int main(void) { return Y(19) == 152 ? 0 : 3; }
`,
	},
	{
		name:         "callback",
		declarations: `func Y(a, b uint64, code uintptr) uint64`,
		assembly: `TEXT ·Y(SB),$24-32
	MOVQ a+0(FP), AX
	MOVQ AX, 0(SP)
	MOVQ b+8(FP), AX
	MOVQ AX, 8(SP)
	MOVQ code+16(FP), AX
	CALL *AX
	MOVQ 16(SP), AX
	MOVQ AX, ret+24(FP)
	RET
`,
		main: `extern uint64_t Y(uint64_t, uint64_t, uintptr_t);
uint64_t callback(uint64_t a, uint64_t b) { return a * 11 + b * 3; }
int main(void) { return Y(17, 29, (uintptr_t)callback) == 274 ? 0 : 4; }
`,
	},
	{
		name: "uint128",
		declarations: `type Uint128 struct { Lo, Hi uint64 }
func Y(t *byte, a, b Uint128, out uintptr) int32
func X(t *byte, a, b Uint128, out uintptr) int32`,
		assembly: `TEXT ·Y(SB),$56-52
	MOVQ t+0(FP), AX
	MOVQ AX, 0(SP)
	MOVQ a_Lo+8(FP), AX
	MOVQ AX, 8(SP)
	MOVQ a_Hi+16(FP), AX
	MOVQ AX, 16(SP)
	MOVQ b_Lo+24(FP), AX
	MOVQ AX, 24(SP)
	MOVQ b_Hi+32(FP), AX
	MOVQ AX, 32(SP)
	MOVQ out+40(FP), AX
	MOVQ AX, 40(SP)
	CALL ·X(SB)
	MOVL 48(SP), AX
	MOVL AX, ret+48(FP)
	RET
`,
		// LLVM literal structs and C structs have different physical ABI rules
		// on some targets. A scalar LLVM harness below avoids conflating them.
		main: `extern int32_t check_uint128(void);
int main(void) { return check_uint128() == 1 ? 0 : 5; }
`,
	},
}

func issue44IR(t *testing.T, index int, triple string) string {
	t.Helper()
	tc := issue44Cases[index]
	pkg := mustGoPackage(t, "test/issue44", "package issue44\n"+tc.declarations)
	tr, err := TranslateGoModule(pkg, []byte(tc.assembly), GoModuleOptions{
		GOARCH: "amd64", TargetTriple: triple,
		ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Module.Dispose()
	if err := llvm.VerifyModule(tr.Module, llvm.ReturnStatusAction); err != nil {
		t.Fatal(err)
	}
	ir := tr.Module.String()
	if tc.name == "uint128" {
		// Replace only the external declaration with an independent value oracle.
		start := strings.Index(ir, "declare i32 @X(")
		if start < 0 {
			t.Fatal("missing X declaration")
		}
		end := start + strings.IndexByte(ir[start:], '\n')
		ir = ir[:start] + ir[end:] + issue44Uint128Oracle
	}
	return ir
}

func TestIssue44ABI0Objects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for i, tc := range issue44Cases {
		for _, triple := range []string{
			"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc",
		} {
			t.Run(tc.name+"/"+triple, func(t *testing.T) {
				requireX86GoAssemblerResult(t, "amd64", tc.assembly, true)
				ir := issue44IR(t, i, triple)
				compileLLVMToObject(t, llc, triple, "issue44.ll", "issue44.o", ir)
			})
		}
	}
}

func TestIssue44ABI0Runtime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var prefix []string
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable() {
		triple = "x86_64-apple-macosx"
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	} else if runtime.GOARCH != "amd64" {
		t.Skip("executed by the required amd64 CI jobs; all target objects are checked separately")
	}
	for i, tc := range issue44Cases {
		t.Run(tc.name, func(t *testing.T) {
			ir := issue44IR(t, i, triple)
			compileAndRunRuntimeTestForTarget(t, llc, clang, "issue44", triple,
				ir, "#include <stdint.h>\n"+tc.main, prefix)
		})
	}
}

const issue44Uint128Oracle = `
define i32 @X(ptr %t, { i64, i64 } %a, { i64, i64 } %b, i64 %out) {
  %a0 = extractvalue { i64, i64 } %a, 0
  %a1 = extractvalue { i64, i64 } %a, 1
  %b0 = extractvalue { i64, i64 } %b, 0
  %b1 = extractvalue { i64, i64 } %b, 1
  %c0 = icmp eq i64 %a0, 11
  %c1 = icmp eq i64 %a1, 13
  %c2 = icmp eq i64 %b0, 17
  %c3 = icmp eq i64 %b1, 19
  %c4 = icmp eq i64 %out, 23
  %c5 = icmp eq ptr %t, null
  %v0 = and i1 %c0, %c1
  %v1 = and i1 %c2, %c3
  %v2 = and i1 %c4, %c5
  %v3 = and i1 %v0, %v1
  %v4 = and i1 %v2, %v3
  %result = zext i1 %v4 to i32
  ret i32 %result
}
define i32 @check_uint128() {
  %r = call i32 @Y(ptr null, { i64, i64 } { i64 11, i64 13 },
                  { i64, i64 } { i64 17, i64 19 }, i64 23)
  ret i32 %r
}
`
