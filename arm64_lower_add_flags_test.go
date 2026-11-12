package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64AddFlagsCompleteGo127Forms(t *testing.T) {
	const source = `TEXT addFlagsForms(SB), $0-0
	ADDS R0, R1
	ADDS R2, R3, R4
	ADDS $4095, R5, R6
	ADDS R7>>8, R8, R9
	ADDS R10.UXTX<<4, R11, R12
	ADDS $1, RSP, R13
	ADDS R1<<1, RSP, R4
	ADDS R2<<4, RSP, R5
	ADDSW R14, R15
	ADDSW R16, R17, R19
	ADDSW $(3525<<12), R20, R21
	ADDSW R22->7, R23, R24
	ADDSW R25.SXTX<<1, R29, R26
	ADDSW $1, RSP, R27
	ADDSW R3<<4, RSP, R6
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
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
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"addFlagsForms": {Name: "addFlagsForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"add i64", "add i32", "icmp ult i64", "icmp ult i32", "icmp slt i64", "icmp slt i32"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("add-with-flags lowering omitted %q:\n%s", want, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-add-flags.ll", "arm64-add-flags.o", ir)
		})
	}
}

func TestTranslateARM64AddFlagsRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, instruction := range []string{
		"ADDS R0",
		"ADDS R0, R1, R2, R3",
		"ADDS (R0), R1",
		"ADDS R0, R1, RSP",
		"ADDS R0>>64, R1, R2",
		"ADDS R0>>1, RSP, R2",
		"ADDS R0->1, RSP, R2",
		"ADDS R0<<5, RSP, R2",
		"ADDSW R0<<32, R1, R2",
		"ADDSW R0>>1, RSP, R2",
		"ADDSW R0.UXTB<<5, R1, R2",
		"ADDSW.P R0, R1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badAddFlags(SB), $0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badAddFlags": {Name: "badAddFlags", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ADDS optab", instruction)
			}
		})
	}
}

func TestARM64AddFlagsRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT addFlagsRuntime(SB), $0-24
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD out+16(FP), R2
	ADDS R0, R1, R3
	MOVD R3, 0(R2)
	CSET MI, R4
	MOVD R4, 8(R2)
	CSET EQ, R4
	MOVD R4, 16(R2)
	CSET CS, R4
	MOVD R4, 24(R2)
	CSET VS, R4
	MOVD R4, 32(R2)
	ADDSW R0, R1, R3
	MOVD R3, 40(R2)
	CSET MI, R4
	MOVD R4, 48(R2)
	CSET EQ, R4
	MOVD R4, 56(R2)
	CSET CS, R4
	MOVD R4, 64(R2)
	CSET VS, R4
	MOVD R4, 72(R2)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"addFlagsRuntime": {
				Name: "addFlagsRuntime", Args: []LLVMType{I64, I64, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: I64, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
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
extern void addFlagsRuntime(uint64_t, uint64_t, uint64_t *);
int main(void) {
  const uint64_t a = UINT64_C(0x8000000000000001);
  const uint64_t b = UINT64_C(0x8000000000000002);
  uint64_t got[10] = {0};
  addFlagsRuntime(a, b, got);
  const uint64_t r = a + b;
  const uint32_t aw = (uint32_t)a, bw = (uint32_t)b, rw = aw + bw;
  const uint64_t want[10] = {
    r, r >> 63, r == 0, r < a, ((~(a ^ b) & (a ^ r)) >> 63),
    rw, rw >> 31, rw == 0, rw < aw, ((~(aw ^ bw) & (aw ^ rw)) >> 31),
  };
  for (int i = 0; i < 10; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_add_flags", triple, ir, mainC, nil)
}
