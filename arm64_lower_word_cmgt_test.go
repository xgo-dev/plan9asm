package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64RawIntegerCompareCompleteAdvancedSIMDFamily(t *testing.T) {
	forms := []struct {
		name       string
		vectorBase uint32
		scalarBase uint32
		predicate  string
		zero       bool
		testBits   bool
	}{
		{"CMEQ register", 0x2e208c00, 0x7e208c00, "eq", false, false},
		{"CMGE register", 0x0e203c00, 0x5e203c00, "sge", false, false},
		{"CMGT register", 0x0e203400, 0x5e203400, "sgt", false, false},
		{"CMHI register", 0x2e203400, 0x7e203400, "ugt", false, false},
		{"CMHS register", 0x2e203c00, 0x7e203c00, "uge", false, false},
		{"CMTST register", 0x0e208c00, 0x5e208c00, "ne", false, true},
		{"CMEQ zero", 0x0e209800, 0x5e209800, "eq", true, false},
		{"CMGE zero", 0x2e208800, 0x7e208800, "sge", true, false},
		{"CMGT zero", 0x0e208800, 0x5e208800, "sgt", true, false},
		{"CMLE zero", 0x2e209800, 0x7e209800, "sle", true, false},
		{"CMLT zero", 0x0e20a800, 0x5e20a800, "slt", true, false},
	}

	var source strings.Builder
	source.WriteString("TEXT rawIntegerCompareFamily(SB),$0-0\n")
	for _, form := range forms {
		for size := 0; size < 4; size++ {
			for q := 0; q < 2; q++ {
				if size == 3 && q == 0 {
					continue
				}
				word := form.vectorBase | uint32(size)<<22 | uint32(q)<<30 | 1<<5
				if !form.zero {
					word |= 2 << 16
				}
				fmt.Fprintf(&source, "\tWORD $%#08x // %s size=%d q=%d\n", word, form.name, size, q)
			}
		}
		word := form.scalarBase | 1<<5
		if !form.zero {
			word |= 2 << 16
		}
		fmt.Fprintf(&source, "\tWORD $%#08x // %s scalar D\n", word, form.name)
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)

	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawIntegerCompareFamily": {Name: "rawIntegerCompareFamily", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, predicate := range []string{"eq", "sge", "sgt", "ugt", "uge", "ne", "sle", "slt"} {
				if !strings.Contains(ir, "icmp "+predicate+" ") {
					t.Fatalf("raw integer compare IR omitted %q:\n%s", predicate, ir)
				}
			}
			if !strings.Contains(ir, " and ") {
				t.Fatalf("raw CMTST lowering omitted bitwise and:\n%s", ir)
			}

			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-integer-compare.ll", "arm64-raw-integer-compare.o", ir)
		})
	}
}

// CMGT has register and compare-with-zero encodings. Each has all seven legal
// vector arrangements plus the scalar D form.
const arm64RawCMGTForms = `
TEXT rawcmgtforms(SB),$0-0
	WORD $0x0e223420 // CMGT V0.8B, V1.8B, V2.8B
	WORD $0x4e223420 // CMGT V0.16B, V1.16B, V2.16B
	WORD $0x0e623420 // CMGT V0.4H, V1.4H, V2.4H
	WORD $0x4e623420 // CMGT V0.8H, V1.8H, V2.8H
	WORD $0x0ea23420 // CMGT V0.2S, V1.2S, V2.2S
	WORD $0x4ea23420 // CMGT V0.4S, V1.4S, V2.4S
	WORD $0x4ee23420 // CMGT V0.2D, V1.2D, V2.2D
	WORD $0x5ee23420 // CMGT D0, D1, D2
	WORD $0x0e208820 // CMGT V0.8B, V1.8B, #0
	WORD $0x4e208820 // CMGT V0.16B, V1.16B, #0
	WORD $0x0e608820 // CMGT V0.4H, V1.4H, #0
	WORD $0x4e608820 // CMGT V0.8H, V1.8H, #0
	WORD $0x0ea08820 // CMGT V0.2S, V1.2S, #0
	WORD $0x4ea08820 // CMGT V0.4S, V1.4S, #0
	WORD $0x4ee08820 // CMGT V0.2D, V1.2D, #0
	WORD $0x5ee08820 // CMGT D0, D1, #0
	RET
`

func TestTranslateARM64RawCMGTCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawCMGTForms, true)
	file, err := Parse(ArchARM64, arm64RawCMGTForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawcmgtforms": {Name: "rawcmgtforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"icmp sgt <8 x i8>", "icmp sgt <16 x i8>",
				"icmp sgt <4 x i16>", "icmp sgt <8 x i16>",
				"icmp sgt <2 x i32>", "icmp sgt <4 x i32>",
				"icmp sgt <2 x i64>", "icmp sgt <1 x i64>",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw CMGT lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-cmgt.ll", "arm64-raw-cmgt.o", ll)
		})
	}
}

func TestARM64RawCMGTRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawcmgt(SB),$0-24
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD out+16(FP), R2
	VLD1 (R0), [V4.S4]
	VLD1 (R1), [V2.S4]
	WORD $0x4ea23488 // CMGT V8.4S, V4.4S, V2.4S
	VST1 [V8.S4], (R2)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple, Goarch: "arm64",
		Sigs: map[string]FuncSig{
			"rawcmgt": {
				Name: "rawcmgt", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <limits.h>
extern void rawcmgt(const int32_t *, const int32_t *, uint32_t *);
int main(void) {
  const int32_t a[4] = {INT32_MIN, -1, 0, INT32_MAX};
  const int32_t b[4] = {INT32_MAX, -2, 0, INT32_MIN};
  const uint32_t want[4] = {0, 0xffffffffu, 0, 0xffffffffu};
  uint32_t got[4] = {0};
  rawcmgt(a, b, got);
  for (int i = 0; i < 4; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_cmgt", triple, ll, mainC, nil)
}

func TestARM64RawIntegerCompareDecoderRejectsAdjacentEncoding(t *testing.T) {
	if _, ok := decodeARM64RawIntegerCompare(0x6e202c20); ok {
		t.Fatal("integer compare decoder claimed adjacent vector opcode")
	}
}
