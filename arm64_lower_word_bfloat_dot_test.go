package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestARM64RawBFloatDotReportedWord(t *testing.T) {
	const source = `TEXT bfloatDot(SB), $0-0
	WORD $0x2e40fc00 // BFDOT V0.2S, V0.4H, V0.4H
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		Goarch:       "arm64",
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"bfloatDot": {Name: "bfloatDot", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestARM64RawBFloatDotCompleteFormats(t *testing.T) {
	// LLVM 22's AArch64 encoder has vector and indexed-element BFDOT forms.
	// Both use Q=0/1; the indexed form has four pair positions and 32 Rm values.
	formats := []struct {
		base    uint32
		indexed bool
	}{
		{base: 0x2e40fc00},
		{base: 0x0f40f000, indexed: true},
	}
	var source strings.Builder
	source.WriteString("TEXT bfloatDotForms(SB), $0-0\n")
	for _, format := range formats {
		for _, q := range []uint32{0, 1 << 30} {
			lanes := 1
			if format.indexed {
				lanes = 4
			}
			for lane := 0; lane < lanes; lane++ {
				for _, reg := range []uint32{0, 15, 31} {
					word := format.base | q | reg<<16 | reg<<5 | reg
					if format.indexed {
						word |= uint32(lane&1)<<21 | uint32(lane&2)<<10
					}
					form, ok := decodeARM64RawBFloatDot(word)
					if !ok || form.indexed != format.indexed || form.lane != lane ||
						form.destination != int(reg) || form.left != int(reg) || form.right != int(reg) {
						t.Fatalf("decode %#08x = %+v, valid=%v", word, form, ok)
					}
					wantLanes := 2
					if q != 0 {
						wantLanes = 4
					}
					if form.lanes != wantLanes {
						t.Fatalf("decode %#08x has %d lanes, want %d", word, form.lanes, wantLanes)
					}
					fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
				}
			}
		}
	}
	// Each five-bit register field is independent, including V31.
	for _, format := range formats {
		for register := uint32(0); register < 32; register++ {
			for field, shift := range []uint{0, 5, 16} {
				word := format.base | 1<<30
				word |= register << shift
				form, ok := decodeARM64RawBFloatDot(word)
				if !ok {
					t.Fatalf("decoder rejected register field %d in %#08x", field, word)
				}
				got := []int{form.destination, form.left, form.right}[field]
				if got != int(register) {
					t.Fatalf("register field %d in %#08x decoded as %d", field, word, got)
				}
			}
		}
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
				Sigs: map[string]FuncSig{"bfloatDotForms": {Name: "bfloatDotForms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+bf16"`,
				"@llvm.aarch64.neon.bfdot.v2f32.v4bf16",
				"@llvm.aarch64.neon.bfdot.v4f32.v8bf16",
				"shufflevector <8 x bfloat>",
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("%s BFDOT lowering omitted %q:\n%s", triple, want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-bfloat-dot.ll", "arm64-raw-bfloat-dot.o", ir)
		})
	}
}

func TestARM64RawBFloatDotRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x2e40f800, // Distinct BF16 opcode.
		0x0f40e000, // Distinct indexed opcode.
		0x0f40f400, // Reserved bit 10.
		0x0f00f000, // Different size field.
	} {
		if form, ok := decodeARM64RawBFloatDot(word); ok {
			t.Fatalf("accepted adjacent encoding %#08x as %+v", word, form)
		}
	}
}

func TestARM64RawBFloatDotNativeRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("native execution requires Darwin arm64")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir := arm64RawBFloatDotRuntimeIR(t, triple)
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_bfloat_dot", triple, ir, arm64RawBFloatDotOracleC, nil)
}

func TestCrossLinuxRuntimeMatrixARM64RawBFloatDot(t *testing.T) {
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
	ir := arm64RawBFloatDotRuntimeIR(t, triple)
	compileAndRunRuntimeTestWithCompiler(t, llc,
		[]string{"aarch64-linux-gnu-gcc"}, "arm64_raw_bfloat_dot", triple, ir,
		arm64RawBFloatDotOracleC,
		[]string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"})
}

func arm64RawBFloatDotRuntimeIR(t *testing.T, triple string) string {
	t.Helper()
	const source = `TEXT bfloatDotRuntime(SB), $0-32
	MOVD accumulator+0(FP), R0
	MOVD lhs+8(FP), R1
	MOVD rhs+16(FP), R2
	MOVD output+24(FP), R3
	VLD1 (R0), [V0.S4]
	VLD1 (R1), [V1.H8]
	VLD1 (R2), [V2.H8]
	WORD $0x6e42fc20 // BFDOT V0.4S, V1.8H, V2.8H
	VST1 [V0.S4], (R3)
	VLD1 (R0), [V0.S4]
	WORD $0x4f42f820 // BFDOT V0.4S, V1.8H, V2.2H[2]
	ADD $16, R3
	VST1 [V0.S4], (R3)
	VLD1 (R0), [V0.S4]
	WORD $0x2e42fc20 // BFDOT V0.2S, V1.4H, V2.4H
	ADD $16, R3
	VST1 [V0.S4], (R3)
	VLD1 (R0), [V0.S4]
	WORD $0x0f42f820 // BFDOT V0.2S, V1.4H, V2.2H[2]
	ADD $16, R3
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
			"bfloatDotRuntime": {
				Name: "bfloatDotRuntime", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
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

const arm64RawBFloatDotOracleC = `
#include <stdint.h>
extern void bfloatDotRuntime(const float *, const uint16_t *, const uint16_t *, float *);
int main(void) {
    const float accumulator[4] = {10, 20, 30, 40};
    const uint16_t lhs[8] = {0x3f80, 0x4000, 0x4040, 0x4080, 0x40a0, 0x40c0, 0x40e0, 0x4100};
    const uint16_t rhs[8] = {0x4100, 0x40e0, 0x40c0, 0x40a0, 0x4080, 0x4040, 0x4000, 0x3f80};
    const float want[16] = {
        32, 58, 68, 62,
        20, 44, 68, 92,
        32, 58, 0, 0,
        20, 44, 0, 0,
    };
    float got[16] = {0};
    bfloatDotRuntime(accumulator, lhs, rhs, got);
    for (int i = 0; i < 16; i++) if (got[i] != want[i]) return i + 1;
    return 0;
}
`
