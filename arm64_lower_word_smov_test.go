package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestARM64RawSignedLaneExtractReportedWord(t *testing.T) {
	const source = `TEXT signedLane(SB), $0-0
	WORD $0x4e042c00 // SMOV V0.S[0], R0
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
			"signedLane": {Name: "signedLane", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestARM64RawSignedLaneExtractCompleteArchitecturalFormats(t *testing.T) {
	// x/arch/arm64asm/inst.json has two SMOV encodings: Wd accepts B/H
	// lanes, while Xd accepts B/H/S lanes. Go's named assembler has no SMOV
	// spelling, but WORD in Go source can encode every one of these forms.
	var source strings.Builder
	source.WriteString("TEXT signedLanes(SB), $0-0\n")
	for _, form := range []struct {
		wide      bool
		kind      byte
		lanes     int
		elemBytes int
	}{
		{false, 'B', 16, 1},
		{false, 'H', 8, 2},
		{true, 'B', 16, 1},
		{true, 'H', 8, 2},
		{true, 'S', 4, 4},
	} {
		base := uint32(0x0e002c00)
		if form.wide {
			base = 0x4e002c00
		}
		for lane := 0; lane < form.lanes; lane++ {
			for _, src := range []int{0, 17, 31} {
				dst := (lane*11 + src) % 31
				imm5 := lane*form.elemBytes*2 + form.elemBytes
				word := base | uint32(imm5)<<16 | uint32(src)<<5 | uint32(dst)
				fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
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
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch:       "arm64",
				TargetTriple: triple,
				Sigs: map[string]FuncSig{
					"signedLanes": {Name: "signedLanes", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"sext i8", "sext i16", "sext i32", "zext i32",
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("missing %q in signed lane extraction:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-smov.ll", "arm64-raw-smov.o", ir)
		})
	}
}

func TestARM64SignedLaneExtractRejectsInvalidFormats(t *testing.T) {
	for _, instruction := range []string{
		"SMOV V0.D[0], R0",
		"SMOVW V0.S[0], R0",
		"SMOV V0.S[4], R0",
		"SMOVW V0.H[8], R0",
		"SMOV R0, V0.S[0]",
	} {
		t.Run(instruction, func(t *testing.T) {
			file, err := Parse(ArchARM64, "TEXT signedLane(SB), $0-0\n"+instruction+"\nRET\n")
			if err != nil {
				return
			}
			_, err = Translate(file, Options{
				Goarch:       "arm64",
				TargetTriple: "aarch64-unknown-linux-gnu",
				Sigs: map[string]FuncSig{
					"signedLane": {Name: "signedLane", Ret: Void},
				},
			})
			if err == nil {
				t.Fatal("accepted invalid signed lane extract")
			}
		})
	}
}

func TestARM64RawSignedLaneExtractRejectsReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x0e002c00, // No element-size bit.
		0x0e042c00, // A 32-bit destination cannot extract an S lane.
		0x4e082c00, // SMOV has no D-lane encoding.
		0x4e102c00, // Nor a wider element-size encoding.
	} {
		ins := Instr{
			Op:   "WORD",
			Args: []Operand{{Kind: OpImm, Imm: int64(word)}},
			Raw:  fmt.Sprintf("WORD $%#08x", word),
		}
		decoded, err := decodeARM64RawWordInstruction(ins)
		if err == nil && (decoded.Op == "SMOV" || decoded.Op == "SMOVW") {
			t.Fatalf("reserved encoding %#08x decoded as %s", word, decoded.Op)
		}
	}
}

func TestARM64SignedLaneExtractNativeRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("native execution requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir := arm64SignedLaneExtractRuntimeIR(t, triple)
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_smov", triple, ir, arm64SignedLaneExtractOracleC, nil)
}

func TestCrossLinuxRuntimeMatrixARM64SignedLaneExtract(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("signed lane extraction belongs to the required Linux cross-runtime matrix")
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
	ir := arm64SignedLaneExtractRuntimeIR(t, triple)
	compileAndRunRuntimeTestWithCompiler(t, llc,
		[]string{"aarch64-linux-gnu-gcc"}, "arm64_raw_smov", triple, ir,
		arm64SignedLaneExtractOracleC,
		[]string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"})
}

func arm64SignedLaneExtractRuntimeIR(t *testing.T, triple string) string {
	t.Helper()
	const source = `TEXT signedLanes(SB), $0-16
	MOVD in+0(FP), R0
	MOVD out+8(FP), R1
	VLD1 (R0), [V0.B16]
	WORD $0x0e012c02 // SMOVW V0.B[0], R2
	WORD $0x0e0e2c03 // SMOVW V0.H[3], R3
	WORD $0x4e1f2c04 // SMOV V0.B[15], R4
	WORD $0x4e0e2c05 // SMOV V0.H[3], R5
	WORD $0x4e142c06 // SMOV V0.S[2], R6
	MOVD R2, 0(R1)
	MOVD R3, 8(R1)
	MOVD R4, 16(R1)
	MOVD R5, 24(R1)
	MOVD R6, 32(R1)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "arm64",
		TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"signedLanes": {
				Name: "signedLanes", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

const arm64SignedLaneExtractOracleC = `
#include <stdint.h>
extern void signedLanes(const uint8_t input[16], uint64_t output[5]);
int main(void) {
    const uint8_t input[16] = {
        0x80, 0, 0, 0, 0, 0, 0, 0x80,
        0, 0, 0, 0x80, 0, 0, 0, 0xff
    };
    uint64_t output[5] = {0};
    signedLanes(input, output);
    if (output[0] != UINT64_C(0x00000000ffffff80)) return 1;
    if (output[1] != UINT64_C(0x00000000ffff8000)) return 2;
    if (output[2] != UINT64_MAX) return 3;
    if (output[3] != UINT64_C(0xffffffffffff8000)) return 4;
    if (output[4] != UINT64_C(0xffffffff80000000)) return 5;
    return 0;
}
`
