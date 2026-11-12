package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64SHA3Forms = `
TEXT sha3forms(SB),$0-0
	VEOR3 V0.B16, V1.B16, V2.B16, V3.B16
	VBCAX V4.B16, V5.B16, V6.B16, V7.B16
	VRAX1 V8.D2, V9.D2, V10.D2
	VXAR $0, V11.D2, V12.D2, V13.D2
	VXAR $63, V14.D2, V15.D2, V16.D2
	RET
`

func TestTranslateARM64SHA3CompleteGoAssemblerForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64SHA3Forms, true)
	file, err := Parse(ArchARM64, arm64SHA3Forms)
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
					"sha3forms": {Name: "sha3forms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"xor <16 x i8>", "and <16 x i8>", "shl <2 x i64>", "lshr <2 x i64>"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 SHA3 lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sha3.ll", "arm64-sha3.o", ll)
		})
	}
}

func TestTranslateARM64SHA3RejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VEOR3 V0.B8, V1.B8, V2.B8, V3.B8",
		"VEOR3 V0.B16, V1.B16, V2.B16",
		"VBCAX V0.D2, V1.D2, V2.D2, V3.D2",
		"VRAX1 V0.B16, V1.B16, V2.B16",
		"VXAR $64, V0.D2, V1.D2, V2.D2",
		"VXAR $1, V0.S4, V1.S4, V2.S4",
		"VXAR.P $1, V0.D2, V1.D2, V2.D2",
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsha3(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badsha3": {Name: "badsha3", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SHA3 optab", instruction)
			}
		})
	}
}

func TestARM64SHA3RuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT sha3semantics(SB),$0-8
	MOVD out+0(FP), R0
	VMOVQ $0x0123456789abcdef, $0xfedcba9876543210, V1
	VMOVQ $0x1111222233334444, $0xaaaabbbbccccdddd, V2
	VMOVQ $0x0f0f0f0f0f0f0f0f, $0x5555555555555555, V3
	VEOR3 V1.B16, V2.B16, V3.B16, V4.B16
	VBCAX V1.B16, V2.B16, V3.B16, V5.B16
	VRAX1 V1.D2, V2.D2, V6.D2
	VXAR $13, V1.D2, V2.D2, V7.D2
	VMOV V4.D[0], R1
	VMOV V4.D[1], R2
	VMOV V5.D[0], R3
	VMOV V5.D[1], R4
	VMOV V6.D[0], R5
	VMOV V6.D[1], R6
	VMOV V7.D[0], R7
	VMOV V7.D[1], R8
	MOVD R1, 0(R0)
	MOVD R2, 8(R0)
	MOVD R3, 16(R0)
	MOVD R4, 24(R0)
	MOVD R5, 32(R0)
	MOVD R6, 40(R0)
	MOVD R7, 48(R0)
	MOVD R8, 56(R0)
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
			"sha3semantics": {
				Name: "sha3semantics", Args: []LLVMType{Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void sha3semantics(uint64_t *);
static uint64_t rotl1(uint64_t x) { return (x << 1) | (x >> 63); }
static uint64_t rotr13(uint64_t x) { return (x >> 13) | (x << 51); }
int main(void) {
  uint64_t got[8] = {0};
  const uint64_t a[2] = {UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210)};
  const uint64_t m[2] = {UINT64_C(0x1111222233334444), UINT64_C(0xaaaabbbbccccdddd)};
  const uint64_t n[2] = {UINT64_C(0x0f0f0f0f0f0f0f0f), UINT64_C(0x5555555555555555)};
  sha3semantics(got);
  for (int i = 0; i < 2; i++) {
    if (got[i] != (a[i] ^ m[i] ^ n[i])) return 1;
    if (got[2+i] != (n[i] ^ (m[i] & ~a[i]))) return 2;
    if (got[4+i] != (m[i] ^ rotl1(a[i]))) return 3;
    if (got[6+i] != rotr13(a[i] ^ m[i])) return 4;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_sha3", triple, ll, mainC, nil)
}
