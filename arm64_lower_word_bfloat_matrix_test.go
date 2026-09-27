package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestARM64RawBFloatMatrixReportedWord(t *testing.T) {
	const source = `TEXT bfloatMatrix(SB), $0-0
	WORD $0x6e40ec00 // BFMMLA V0.4S, V0.8H, V0.8H
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"bfloatMatrix": {Name: "bfloatMatrix", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestARM64RawBFloatMatrixCompleteFormat(t *testing.T) {
	// LLVM 22 accepts one 128-bit Advanced SIMD BFMMLA encoding, with three
	// independent five-bit register fields. The 64-bit arrangement is absent.
	const base = uint32(0x6e40ec00)
	for _, shift := range []uint{0, 5, 16} {
		for register := uint32(0); register < 32; register++ {
			word := base | register<<shift
			form, ok := decodeARM64RawBFloatMatrix(word)
			if !ok {
				t.Fatalf("decoder rejected %#08x", word)
			}
			got := map[uint]int{0: form.destination, 5: form.left, 16: form.right}[shift]
			if got != int(register) {
				t.Fatalf("register in %#08x decoded as %d", word, got)
			}
		}
	}
	var source strings.Builder
	source.WriteString("TEXT bfloatMatrixForms(SB), $0-0\n")
	for _, registers := range [][3]uint32{{0, 0, 0}, {31, 30, 29}, {1, 2, 3}} {
		word := base | registers[0] | registers[1]<<5 | registers[2]<<16
		fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"bfloatMatrixForms": {Name: "bfloatMatrixForms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+bf16"`, "@llvm.aarch64.neon.bfmmla("} {
				if !strings.Contains(ir, want) {
					t.Fatalf("%s BFMMLA lowering omitted %q:\n%s", triple, want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-bfloat-matrix.ll", "arm64-raw-bfloat-matrix.o", ir)
		})
	}
}

func TestARM64RawBFloatMatrixRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x2e40ec00, // BFMMLA has no Q=0 form.
		0x6e40e800, // Distinct adjacent opcode.
		0x6e00ec00, // Distinct size field.
	} {
		if form, ok := decodeARM64RawBFloatMatrix(word); ok {
			t.Fatalf("accepted adjacent encoding %#08x as %+v", word, form)
		}
	}
}

func TestARM64RawBFloatMatrixNativeRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("native execution requires Darwin arm64")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir := arm64RawBFloatMatrixRuntimeIR(t, triple)
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_bfloat_matrix", triple, ir, arm64RawBFloatMatrixOracleC, nil)
}

func TestCrossLinuxRuntimeMatrixARM64RawBFloatMatrix(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("BF16 execution belongs to the required Linux cross-runtime matrix")
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
	ir := arm64RawBFloatMatrixRuntimeIR(t, triple)
	compileAndRunRuntimeTestWithCompiler(t, llc,
		[]string{"aarch64-linux-gnu-gcc"}, "arm64_raw_bfloat_matrix", triple, ir,
		arm64RawBFloatMatrixOracleC,
		[]string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"})
}

func arm64RawBFloatMatrixRuntimeIR(t *testing.T, triple string) string {
	t.Helper()
	const source = `TEXT bfloatMatrixRuntime(SB), $0-32
	MOVD accumulator+0(FP), R0
	MOVD lhs+8(FP), R1
	MOVD rhs+16(FP), R2
	MOVD output+24(FP), R3
	VLD1 (R0), [V0.S4]
	VLD1 (R1), [V1.H8]
	VLD1 (R2), [V2.H8]
	WORD $0x6e42ec20 // BFMMLA V0.4S, V1.8H, V2.8H
	VST1 [V0.S4], (R3)
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
			"bfloatMatrixRuntime": {
				Name: "bfloatMatrixRuntime", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
					{Offset: 24, Type: Ptr, Index: 3, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

const arm64RawBFloatMatrixOracleC = `
#include <stdint.h>
extern void bfloatMatrixRuntime(const float *, const uint16_t *, const uint16_t *, float *);
int main(void) {
    const float accumulator[4] = {10, 20, 30, 40};
    const uint16_t lhs[8] = {0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80};
    const uint16_t rhs[8] = {0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80, 0x3f80};
    const float want[4] = {14, 24, 34, 44};
    float got[4] = {0};
    bfloatMatrixRuntime(accumulator, lhs, rhs, got);
    for (int i = 0; i < 4; i++) if (got[i] != want[i]) return i + 1;
    return 0;
}
`
