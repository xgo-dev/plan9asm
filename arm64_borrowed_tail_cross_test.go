package plan9asm

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

const arm64BorrowedTailOracleC = "#include <stdint.h>\nextern void caller(uint64_t *out);\nint main(void) { uint64_t observed = 0; caller(&observed); return observed == 7 ? 0 : 1; }\n"

func TestARM64BorrowedTailFrameNativeRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("native execution requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir := arm64BorrowedTailFrameFixtureIR(t, triple)
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_borrowed_tail_frame_native", triple, ir, arm64BorrowedTailOracleC, nil)
}

func TestCrossLinuxRuntimeMatrixARM64BorrowedTailFrame(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("borrowed-frame execution belongs to the required Linux cross-runtime matrix")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("cross-runtime driver requires linux/amd64")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, tool := range []string{"aarch64-linux-gnu-gcc", "qemu-aarch64"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("required cross-runtime tool %s: %v", tool, err)
		}
	}
	const triple = "aarch64-unknown-linux-gnu"
	ir := arm64BorrowedTailFrameFixtureIR(t, triple)
	compileAndRunRuntimeTestWithCompiler(t, llc,
		[]string{"aarch64-linux-gnu-gcc"}, "arm64_borrowed_tail_frame", triple, ir,
		arm64BorrowedTailOracleC,
		[]string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"})
}

func TestARM64BorrowedTailFrameFixtureLLVM22Object(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	const triple = "aarch64-unknown-linux-gnu"
	ir := arm64BorrowedTailFrameFixtureIR(t, triple)
	compileLLVMToObject(t, llc, triple, "arm64-borrowed-tail.ll", "arm64-borrowed-tail.o", ir)
}

func arm64BorrowedTailFrameFixtureIR(t *testing.T, triple string) string {
	t.Helper()
	const source = `TEXT caller(SB),4,$24-8
	MOVD out+0(FP), R4
	MOVD $7, R3
	MOVD R3, 8(RSP)
	MOVD R4, 16(RSP)
	B helper(SB)
TEXT helper(SB),4,$0-0
	MOVD vector+0(FP), R3
	MOVD out+8(FP), R4
	MOVD R3, (R4)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"caller": {
				Name: "caller", Args: []LLVMType{Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1, Name: "out"},
				}},
			},
			"helper": {
				Name: "helper", Args: []LLVMType{I64, I64}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: I64, Index: 0, Field: -1, Name: "vector"},
					{Offset: 8, Type: I64, Index: 1, Field: -1, Name: "out"},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"call void @helper(i64 %", "define void @helper(i64 %arg0, i64 %arg1)"} {
		if !strings.Contains(ir, want) {
			t.Fatalf("borrowed-frame IR omitted %q", want)
		}
	}
	return ir
}
