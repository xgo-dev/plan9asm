package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestARM64RawHalfFMAReportedWord(t *testing.T) {
	const source = `TEXT halfFMA(SB), $0-0
	WORD $0x1fc10800 // FMADD H0, H0, H1, H2
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"halfFMA": {Name: "halfFMA", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestARM64RawHalfFMACompleteFormats(t *testing.T) {
	// Go's named FMA family has S/D formats. LLVM 22's A64 encoder also has
	// four half-precision formats, each with four independent V0..V31 fields.
	var source strings.Builder
	source.WriteString("TEXT halfFMAForms(SB), $0-0\n")
	for _, base := range []uint32{
		0x1fc00000, // FMADD.
		0x1fc08000, // FMSUB.
		0x1fe00000, // FNMADD.
		0x1fe08000, // FNMSUB.
	} {
		for field, shift := range []uint{0, 5, 10, 16} {
			for register := uint32(0); register < 32; register++ {
				word := base | register<<shift
				form, ok := decodeARM64RawHalfFMA(word)
				if !ok {
					t.Fatalf("decoder rejected %#08x", word)
				}
				got := []int{form.destination, form.first, form.addend, form.second}[field]
				if got != int(register) {
					t.Fatalf("field %d in %#08x decoded as %d", field, word, got)
				}
			}
		}
		word := base | 31<<16 | 30<<10 | 29<<5 | 28
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
				Sigs: map[string]FuncSig{"halfFMAForms": {Name: "halfFMAForms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"target-features"="+fullfp16"`, "@llvm.fma.f16", "fneg half"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("%s half FMA lowering omitted %q:\n%s", triple, want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-half-fma.ll", "arm64-raw-half-fma.o", ir)
		})
	}
}

func TestARM64RawHalfFMARejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x1f000000, // FMADD single precision belongs to the named Go family.
		0x1f400000, // FMADD double precision belongs to the named Go family.
		0x1f800000, // Reserved floating-point source type.
	} {
		if form, ok := decodeARM64RawHalfFMA(word); ok {
			t.Fatalf("accepted adjacent encoding %#08x as %+v", word, form)
		}
	}
}

func TestARM64RawHalfFMANativeRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("native execution requires Darwin arm64")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir := arm64RawHalfFMARuntimeIR(t, triple)
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_half_fma", triple, ir, arm64RawHalfFMAOracleC, nil)
}

func TestCrossLinuxRuntimeMatrixARM64RawHalfFMA(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("FP16 execution belongs to the required Linux cross-runtime matrix")
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
	ir := arm64RawHalfFMARuntimeIR(t, triple)
	compileAndRunRuntimeTestWithCompiler(t, llc,
		[]string{"aarch64-linux-gnu-gcc"}, "arm64_raw_half_fma", triple, ir,
		arm64RawHalfFMAOracleC,
		[]string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"})
}

func arm64RawHalfFMARuntimeIR(t *testing.T, triple string) string {
	t.Helper()
	const source = `TEXT halfFMARuntime(SB), $0-32
	MOVD first+0(FP), R0
	MOVD second+8(FP), R1
	MOVD addend+16(FP), R2
	MOVD output+24(FP), R3
	VLD1 (R0), [V1.H8]
	VLD1 (R1), [V2.H8]
	VLD1 (R2), [V4.H8]
	WORD $0x1fc21020 // FMADD H0, H1, H2, H4
	VST1 [V0.H8], (R3)
	WORD $0x1fc29020 // FMSUB H0, H1, H2, H4
	ADD $16, R3
	VST1 [V0.H8], (R3)
	WORD $0x1fe21020 // FNMADD H0, H1, H2, H4
	ADD $16, R3
	VST1 [V0.H8], (R3)
	WORD $0x1fe29020 // FNMSUB H0, H1, H2, H4
	ADD $16, R3
	VST1 [V0.H8], (R3)
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
			"halfFMARuntime": {
				Name: "halfFMARuntime", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
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

const arm64RawHalfFMAOracleC = `
#include <stdint.h>
extern void halfFMARuntime(const uint16_t *, const uint16_t *, const uint16_t *, uint16_t *);
int main(void) {
    const uint16_t first[8] = {0x4000};
    const uint16_t second[8] = {0x4200};
    const uint16_t addend[8] = {0x4400};
    const uint16_t want[4] = {0x4900, 0xc000, 0xc900, 0x4000};
    uint16_t output[32] = {0};
    halfFMARuntime(first, second, addend, output);
    for (int i = 0; i < 4; i++) if (output[i * 8] != want[i]) return i + 1;
    return 0;
}
`
