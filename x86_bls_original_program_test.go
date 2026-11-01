package plan9asm

import "testing"

const x86BLSOriginalRuntimeSource = `TEXT blssemantics(SB),$0-8
	MOVQ out+0(FP), DI
	MOVQ $0, AX
	BLSIQ AX, BX
	MOVQ BX, 0(DI)
	SETCS 48(DI)
	SETEQ 49(DI)
	SETMI 50(DI)
	SETOS 51(DI)
	MOVQ $0x8000000000000000, AX
	BLSIQ AX, BX
	MOVQ BX, 8(DI)
	MOVQ $0, AX
	BLSMSKQ AX, BX
	MOVQ BX, 16(DI)
	SETCS 52(DI)
	SETEQ 53(DI)
	SETMI 54(DI)
	SETOS 55(DI)
	MOVQ $10, AX
	BLSRQ AX, BX
	MOVQ BX, 24(DI)
	SETCS 56(DI)
	SETEQ 57(DI)
	SETMI 58(DI)
	SETOS 59(DI)
	MOVL $0x80000000, AX
	BLSIL AX, BX
	MOVQ BX, 32(DI)
	MOVL $0, AX
	BLSMSKL AX, BX
	MOVQ BX, 40(DI)
	RET
`

const x86BLSOriginalRuntimeDriver = `
#include <stdint.h>
#include <string.h>
extern void blssemantics(uint8_t *);
int main(void) {
  uint8_t out[64] = {0};
  blssemantics(out);
  const uint64_t want[6] = {0, UINT64_C(0x8000000000000000), UINT64_MAX, 8, UINT64_C(0x80000000), UINT64_C(0xffffffff)};
  for (int i = 0; i < 6; i++) {
    uint64_t got;
    memcpy(&got, out + i * 8, sizeof(got));
    if (got != want[i]) return 10 + i;
  }
  const uint8_t flags[12] = {0,1,0,0, 1,0,1,0, 0,0,0,0};
  for (int i = 0; i < 12; i++) if (out[48+i] != flags[i]) return 30+i;
  return 0;
}
`

func TestX86BLSOriginalProgramPortableAndObjects(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	const declaration = "func blssemantics(out *[64]byte)"
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-macosx", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, x86BLSOriginalRuntimeSource)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, x86BLSOriginalRuntimeSource, declaration, "amd64", triple, api)
				if err != nil {
					t.Fatal("unchanged original CI source", api, err)
				}
				for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, execution.llc, triple, text, level)
					}
				}
			}
		})
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run("portable/"+api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, x86BLSOriginalRuntimeSource, declaration, "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					execution.compileAndRunLLVM(t, "original-bls", text, x86BLSOriginalRuntimeDriver, level)
				}
			}
		})
	}
	t.Log("original Go/LLVM objects and actual-host portable values/FLAGS; not native x86 execution")
}
