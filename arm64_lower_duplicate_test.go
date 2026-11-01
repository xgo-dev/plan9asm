package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64VectorDuplicateForms = `
TEXT vectorduplicateforms(SB),$0-0
	VDUP V0.B[15], V1.B8
	VDUP V0.B[15], V2.B16
	VDUP V0.H[7], V3.H4
	VDUP V0.H[7], V4.H8
	VDUP V0.S[3], V5.S2
	VDUP V0.S[3], V6.S4
	VDUP V0.D[1], V7.D2
	VDUP V0.B[15], V8
	VDUP V0.H[7], V9
	VDUP V0.S[3], V10
	VDUP V0.D[1], V11
	VDUP R1, V12.B8
	VDUP R2, V13.B16
	VDUP R3, V14.H4
	VDUP R4, V15.H8
	VDUP R5, V16.S2
	VDUP R6, V17.S4
	VDUP R7, V18.D2
	// Go's case-79 encoder takes the source width from the arranged
	// destination, so these mixed source suffixes are intentionally accepted.
	VDUP V0.B[0], V19.D2
	VDUP V0.D[1], V20.B16
	VDUP ZR, V21.S4
	RET
`

func TestTranslateARM64VectorDuplicateCompleteGoAssemblerForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64VectorDuplicateForms, true)
	file, err := Parse(ArchARM64, arm64VectorDuplicateForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"vectorduplicateforms": {Name: "vectorduplicateforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"extractelement", "shufflevector", "insertelement"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 VDUP lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-vector-duplicate.ll", "arm64-vector-duplicate.o", ll)
		})
	}
}

func TestTranslateARM64VectorDuplicateRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VDUP V0.B[16], V1.B16",
		"VDUP V0.B[0], V1.D1",
		"VDUP V0.S4, V1.S4",
		"VDUP R1, V2",
		"VDUP R1, V2.D1",
		"VDUP R1, V2.S4, V3.S4",
		"VDUP.P R1, V2.S4",
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badvectorduplicate(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badvectorduplicate": {Name: "badvectorduplicate", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's VDUP table", instruction)
			}
		})
	}
}

func TestARM64VectorDuplicateRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT vectorduplicate(SB),$0-8
	MOVD out+0(FP), R0
	VMOVQ $0x0706050403020100, $0x0f0e0d0c0b0a0908, V1
	VDUP V1.B[13], V2.B16
	VMOV V2.D[0], R1
	VMOV V2.D[1], R2
	MOVD R1, 0(R0)
	MOVD R2, 8(R0)
	VDUP V1.S[2], V3
	VMOV V3.D[0], R3
	VMOV V3.D[1], R4
	MOVD R3, 16(R0)
	MOVD R4, 24(R0)
	MOVD $0x123456789abcdef0, R5
	VDUP R5, V4.H4
	VMOV V4.D[0], R6
	VMOV V4.D[1], R7
	MOVD R6, 32(R0)
	MOVD R7, 40(R0)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"vectorduplicate": {
				Name: "vectorduplicate", Args: []LLVMType{Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void vectorduplicate(uint64_t *);
int main(void) {
  uint64_t got[6] = {0};
  vectorduplicate(got);
  if (got[0] != UINT64_C(0x0d0d0d0d0d0d0d0d) || got[1] != UINT64_C(0x0d0d0d0d0d0d0d0d)) return 1;
  if (got[2] != UINT64_C(0x000000000b0a0908) || got[3] != 0) return 2;
  if (got[4] != UINT64_C(0xdef0def0def0def0) || got[5] != 0) return 3;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_vector_duplicate", triple, ll, mainC, nil)
}
