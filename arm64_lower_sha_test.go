package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64SHAForms = `
TEXT shaforms(SB),$0-0
	SHA1C V0, V1, V2
	SHA1C V3.S4, V4, V5
	SHA1P V6, V7, V8
	SHA1P V9.S4, V10, V11
	SHA1M V12, V13, V14
	SHA1M V15.S4, V16, V17
	SHA1H V18, V19
	SHA1SU0 V20.S4, V21.S4, V22.S4
	SHA1SU1 V23.S4, V24.S4
	SHA256H V25, V26, V27
	SHA256H V28.S4, V29, V30
	SHA256H2 V0, V1, V2
	SHA256H2 V3.S4, V4, V5
	SHA256SU0 V6.S4, V7.S4
	SHA256SU1 V8.S4, V9.S4, V10.S4
	SHA512H V11, V12, V13
	SHA512H V14.D2, V15, V16
	SHA512H2 V17, V18, V19
	SHA512H2 V20.D2, V21, V22
	SHA512SU0 V23.D2, V24.D2
	SHA512SU1 V25.D2, V26.D2, V27.D2
	RET
`

func TestTranslateARM64SHACompleteGoAssemblerForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64SHAForms, true)
	file, err := Parse(ArchARM64, arm64SHAForms)
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
					"shaforms": {Name: "shaforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"@llvm.aarch64.crypto.sha1c",
				"@llvm.aarch64.crypto.sha1p",
				"@llvm.aarch64.crypto.sha1m",
				"@llvm.aarch64.crypto.sha1h",
				"@llvm.aarch64.crypto.sha1su0",
				"@llvm.aarch64.crypto.sha1su1",
				"@llvm.aarch64.crypto.sha256h",
				"@llvm.aarch64.crypto.sha256h2",
				"@llvm.aarch64.crypto.sha256su0",
				"@llvm.aarch64.crypto.sha256su1",
				"@llvm.aarch64.crypto.sha512h",
				"@llvm.aarch64.crypto.sha512h2",
				"@llvm.aarch64.crypto.sha512su0",
				"@llvm.aarch64.crypto.sha512su1",
				`"target-features"="+sha2,+sha3"`,
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 SHA lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sha.ll", "arm64-sha.o", ll)
		})
	}
}

func TestTranslateARM64SHARejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"SHA1C V0.B16, V1, V2",
		"SHA1C V0.S4, V1.S4, V2",
		"SHA1C V0.S4, V1, V2.S4",
		"SHA1H V0.S4, V1",
		"SHA1SU0 V0.S4, V1.S4, V2.D2",
		"SHA1SU1 V0.B16, V1.B16",
		"SHA256H V0.D2, V1, V2",
		"SHA256SU0 V0.S4, V1",
		"SHA256SU1 V0.S4, V1.D2, V2.S4",
		"SHA512H V0.S4, V1, V2",
		"SHA512SU0 V0.D2, V1.S4",
		"SHA512SU1 V0.D2, V1.D2, V2.S4",
		"SHA1C.P V0.S4, V1, V2",
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsha(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badsha": {Name: "badsha", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SHA optab", instruction)
			}
		})
	}
}

func TestARM64SHARuntimeOperandOrderAndResults(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT shasemantics(SB),$0-16
	MOVD out+0(FP), R1
	MOVD in+8(FP), R0
	VLD1 (R0), [V0.B16, V1.B16, V2.B16]
	SHA1C V0.S4, V1, V2
	VST1.P [V2.B16], 16(R1)
	MOVD in+8(FP), R0
	VLD1 (R0), [V0.B16, V1.B16, V2.B16]
	SHA1P V0.S4, V1, V2
	VST1.P [V2.B16], 16(R1)
	MOVD in+8(FP), R0
	VLD1 (R0), [V0.B16, V1.B16, V2.B16]
	SHA1M V0.S4, V1, V2
	VST1.P [V2.B16], 16(R1)
	MOVD in+8(FP), R0
	VLD1 (R0), [V0.B16]
	SHA1H V0, V2
	VST1.P [V2.B16], 16(R1)
	MOVD in+8(FP), R0
	VLD1 (R0), [V0.B16, V1.B16, V2.B16]
	SHA1SU0 V0.S4, V1.S4, V2.S4
	VST1.P [V2.B16], 16(R1)
	MOVD in+8(FP), R0
	VLD1 (R0), [V0.B16, V1.B16, V2.B16]
	SHA1SU1 V0.S4, V2.S4
	VST1.P [V2.B16], 16(R1)
	MOVD in+8(FP), R0
	VLD1 (R0), [V0.B16, V1.B16, V2.B16]
	SHA256H V0.S4, V1, V2
	VST1.P [V2.B16], 16(R1)
	MOVD in+8(FP), R0
	VLD1 (R0), [V0.B16, V1.B16, V2.B16]
	SHA256H2 V0.S4, V1, V2
	VST1.P [V2.B16], 16(R1)
	MOVD in+8(FP), R0
	VLD1 (R0), [V0.B16, V1.B16, V2.B16]
	SHA256SU0 V0.S4, V2.S4
	VST1.P [V2.B16], 16(R1)
	MOVD in+8(FP), R0
	VLD1 (R0), [V0.B16, V1.B16, V2.B16]
	SHA256SU1 V0.S4, V1.S4, V2.S4
	VST1.P [V2.B16], 16(R1)
	MOVD in+8(FP), R0
	VLD1 (R0), [V0.B16, V1.B16, V2.B16]
	SHA512H V0.D2, V1, V2
	VST1.P [V2.B16], 16(R1)
	MOVD in+8(FP), R0
	VLD1 (R0), [V0.B16, V1.B16, V2.B16]
	SHA512H2 V0.D2, V1, V2
	VST1.P [V2.B16], 16(R1)
	MOVD in+8(FP), R0
	VLD1 (R0), [V0.B16, V1.B16, V2.B16]
	SHA512SU0 V0.D2, V2.D2
	VST1.P [V2.B16], 16(R1)
	MOVD in+8(FP), R0
	VLD1 (R0), [V0.B16, V1.B16, V2.B16]
	SHA512SU1 V0.D2, V1.D2, V2.D2
	VST1 [V2.B16], (R1)
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
			"shasemantics": {
				Name: "shasemantics", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void shasemantics(uint8_t *, const uint8_t *);

static void oracle(uint8_t *out, const uint8_t *in) {
  uint8_t *o = out;
  __asm__ volatile(
    ".arch armv8.4-a+sha3\n\t"
    "ldp q0, q1, [%1]\n\tldr q2, [%1, #32]\n\tsha1c q2, s1, v0.4s\n\tstr q2, [%0], #16\n\t"
    "ldp q0, q1, [%1]\n\tldr q2, [%1, #32]\n\tsha1p q2, s1, v0.4s\n\tstr q2, [%0], #16\n\t"
    "ldp q0, q1, [%1]\n\tldr q2, [%1, #32]\n\tsha1m q2, s1, v0.4s\n\tstr q2, [%0], #16\n\t"
    "ldr q0, [%1]\n\tsha1h s2, s0\n\tstr q2, [%0], #16\n\t"
    "ldp q0, q1, [%1]\n\tldr q2, [%1, #32]\n\tsha1su0 v2.4s, v1.4s, v0.4s\n\tstr q2, [%0], #16\n\t"
    "ldp q0, q1, [%1]\n\tldr q2, [%1, #32]\n\tsha1su1 v2.4s, v0.4s\n\tstr q2, [%0], #16\n\t"
    "ldp q0, q1, [%1]\n\tldr q2, [%1, #32]\n\tsha256h q2, q1, v0.4s\n\tstr q2, [%0], #16\n\t"
    "ldp q0, q1, [%1]\n\tldr q2, [%1, #32]\n\tsha256h2 q2, q1, v0.4s\n\tstr q2, [%0], #16\n\t"
    "ldp q0, q1, [%1]\n\tldr q2, [%1, #32]\n\tsha256su0 v2.4s, v0.4s\n\tstr q2, [%0], #16\n\t"
    "ldp q0, q1, [%1]\n\tldr q2, [%1, #32]\n\tsha256su1 v2.4s, v1.4s, v0.4s\n\tstr q2, [%0], #16\n\t"
    "ldp q0, q1, [%1]\n\tldr q2, [%1, #32]\n\tsha512h q2, q1, v0.2d\n\tstr q2, [%0], #16\n\t"
    "ldp q0, q1, [%1]\n\tldr q2, [%1, #32]\n\tsha512h2 q2, q1, v0.2d\n\tstr q2, [%0], #16\n\t"
    "ldp q0, q1, [%1]\n\tldr q2, [%1, #32]\n\tsha512su0 v2.2d, v0.2d\n\tstr q2, [%0], #16\n\t"
    "ldp q0, q1, [%1]\n\tldr q2, [%1, #32]\n\tsha512su1 v2.2d, v1.2d, v0.2d\n\tstr q2, [%0]"
    : "+r"(o) : "r"(in) : "v0", "v1", "v2", "memory");
}

int main(void) {
  uint8_t in[48];
  uint8_t got[14 * 16] = {0};
  uint8_t want[14 * 16] = {0};
  for (unsigned i = 0; i < sizeof(in); ++i) in[i] = (uint8_t)(i * 37u + 11u);
  shasemantics(got, in);
  oracle(want, in);
  return memcmp(got, want, sizeof(got)) != 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_sha", triple, ll, mainC, nil)
}
