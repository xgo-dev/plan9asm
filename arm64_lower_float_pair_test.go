package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64FloatPairLoadStoreCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 defines one six-op family: FLDPS/FLDPD/FLDPQ and
	// FSTPS/FSTPD/FSTPQ. Each precision accepts register- or SP-relative
	// memory, pre/post indexing, and SB symbols. Cover every shape here rather
	// than teaching the translator only the FSTPQ form first seen in Wago.
	const source = `
TEXT floatPairForms(SB),$0-0
	FLDPS (R0), (F0, F1)
	FSTPS (F0, F1), 4(R0)
	FLDPS.P 8(R1), (F2, F3)
	FSTPS.W (F2, F3), -8(R1)
	FLDPS pairData(SB), (F4, F5)
	FSTPS (F4, F5), pairData+8(SB)
	FLDPD -16(R2), (F6, F7)
	FSTPD (F6, F7), (R2)
	FLDPD.P 16(R3), (F8, F9)
	FSTPD.W (F8, F9), -16(R3)
	FLDPD pairData(SB), (F10, F11)
	FSTPD (F10, F11), pairData+16(SB)
	FLDPQ -32(R4), (F12, F13)
	FSTPQ (F12, F13), (R4)
	FLDPQ.P 32(R5), (F14, F15)
	FSTPQ.W (F14, F15), -32(R5)
	FLDPQ pairData(SB), (F16, F17)
	FSTPQ (F16, F17), pairData+32(SB)
	FLDPQ (RSP), (F30, F31)
	FSTPQ (F30, F31), 64(RSP)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)

	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "darwin-arm64", triple: "arm64-apple-darwin"},
		{name: "linux-arm64", triple: "aarch64-unknown-linux-gnu"},
		{name: "windows-arm64", triple: "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "arm64",
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs: map[string]FuncSig{
					"floatPairForms": {Name: "floatPairForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"load i32", "store i32", "load i64", "store i64", "load <16 x i8>", "store <16 x i8>"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s did not lower %q:\n%s", target.name, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "arm64-float-pair-"+target.name+".ll", "arm64-float-pair-"+target.name+".o", ll)
		})
	}
}

func TestTranslateARM64FloatPairLoadStoreRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"FLDPQ (R0), (R1, R2)",
		"FSTPQ (R1, R2), (R0)",
		"FLDPD (R0), (F2, F2)",
		"FLDPS (R0)(R1), (F0, F1)",
		"FSTPS (F0, F1), (R0)(R1)",
		"FLDPQ.P pairData(SB), (F0, F1)",
		"FSTPQ.W (F0, F1), pairData(SB)",
		"FLDPQ.X (R0), (F0, F1)",
		"FSTPD (F0), (R0)",
		"FLDPS (R0)",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badFloatPair(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badFloatPair": {Name: "badFloatPair", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 floating pair table", instruction)
			}
		})
	}
}

func TestARM64FloatPairLoadStoreRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT floatPairRoundTrip(SB),$0-0
	FLDPS.P 8(R0), (F0, F1)
	FSTPS.P (F0, F1), 8(R1)
	FLDPD.W -16(R2), (F2, F3)
	FSTPD.W (F2, F3), 16(R3)
	FLDPQ (R4), (F4, F5)
	FSTPQ (F4, F5), (R5)
	MOVD R0, 0(R6)
	MOVD R1, 8(R6)
	MOVD R2, 16(R6)
	MOVD R3, 24(R6)
	RET
`
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	frame := FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: Ptr, Index: 1, Field: -1},
		{Offset: 16, Type: Ptr, Index: 2, Field: -1},
		{Offset: 24, Type: Ptr, Index: 3, Field: -1},
		{Offset: 32, Type: Ptr, Index: 4, Field: -1},
		{Offset: 40, Type: Ptr, Index: 5, Field: -1},
		{Offset: 48, Type: Ptr, Index: 6, Field: -1},
	}}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"floatPairRoundTrip": {Name: "floatPairRoundTrip", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
#include <string.h>
extern void floatPairRoundTrip(const uint32_t *, uint32_t *, const uint64_t *, uint64_t *, const unsigned char *, unsigned char *, uintptr_t *);
int main(void) {
  const uint32_t s[2] = {0x11223344u, 0xaabbccddu}; uint32_t so[2] = {0};
	const uint64_t dbuf[4] = {0, 0, 0x0102030405060708ull, 0x8877665544332211ull}; uint64_t doutbuf[4] = {0};
  const unsigned char q[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32}; unsigned char qout[32] = {0};
  uintptr_t advanced[4] = {0};
	floatPairRoundTrip(s, so, dbuf + 4, doutbuf, q, qout, advanced);
  if (memcmp(s, so, sizeof(s)) != 0) return 1;
	if (memcmp(dbuf + 2, doutbuf + 2, 2 * sizeof(uint64_t)) != 0) return 2;
  if (memcmp(q, qout, sizeof(q)) != 0) return 3;
  if (advanced[0] != (uintptr_t)(s + 2) || advanced[1] != (uintptr_t)(so + 2)) return 4;
	if (advanced[2] != (uintptr_t)(dbuf + 2) || advanced[3] != (uintptr_t)(doutbuf + 2)) return 5;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_float_pair", triple, ll, mainC, nil)
}
