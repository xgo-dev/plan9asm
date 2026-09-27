package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86PackedAbsSignCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 uses yxm_q4 for the legacy PABS*/PSIGN* rows,
	// _yvmovddup for VPABSB/W/D, _yvexpandpd for VPABSQ, and
	// _yvaddsubpd for the VEX-only VPSIGN* rows.
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT packedabssignforms(SB),NOSPLIT,$0-0\n")
			for index, suffix := range []string{"B", "W", "D"} {
				fmt.Fprintf(&source, "\tPABS%s X0, X1\n", suffix)
				fmt.Fprintf(&source, "\tPABS%s %d(AX), X2\n", suffix, 16*index)
				fmt.Fprintf(&source, "\tPSIGN%s X3, X4\n", suffix)
				fmt.Fprintf(&source, "\tPSIGN%s %d(AX), X5\n", suffix, 48+16*index)
				fmt.Fprintf(&source, "\tVPABS%s X6, X7\n", suffix)
				fmt.Fprintf(&source, "\tVPABS%s %d(AX), Y1\n", suffix, 96+32*index)
				fmt.Fprintf(&source, "\tVPABS%s X20, X21\n", suffix)
				fmt.Fprintf(&source, "\tVPABS%s X8, K1, X9\n", suffix)
				fmt.Fprintf(&source, "\tVPABS%s.Z %d(AX), K2, Y3\n", suffix, 192+32*index)
				fmt.Fprintf(&source, "\tVPABS%s Z4, K3, Z5\n", suffix)
				fmt.Fprintf(&source, "\tVPSIGN%s X8, X9, X10\n", suffix)
				fmt.Fprintf(&source, "\tVPSIGN%s %d(AX), Y11, Y12\n", suffix, 288+32*index)
			}
			source.WriteString(`	VPABSD.BCST 384(AX), Y11
	VPABSD.BCST.Z 388(AX), K4, Z6
	VPABSQ X0, X1
	VPABSQ 400(AX), Y2
	VPABSQ Z3, K5, Z4
	VPABSQ.Z 464(AX), K6, Z5
	VPABSQ.BCST 472(AX), X6
	VPABSQ.BCST.Z 480(AX), K7, Y7
	RET
`)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"packedabssignforms": {Name: "packedabssignforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"icmp slt <", "icmp sgt <", "sub <", "select <"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("packed abs/sign IR is missing %q:\n%s", want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-abs-sign-"+target.name+".ll", "packed-abs-sign-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedAbsSignRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PABSB Y0, X1",
		"PABSQ X0, X1",
		"PABSD.Z X0, X1",
		"VPABSB X0, Y1",
		"VPABSW Y0, X1",
		"VPABSD Z0, Y1",
		"VPABSQ X0, Y1",
		"VPABSQ X0, K0, X1",
		"VPABSB.Z X0, X1",
		"VPABSW.BCST (AX), X1",
		"VPABSQ.BCST X0, X1",
		"PSIGNB Y0, X1",
		"PSIGNQ X0, X1",
		"VPSIGNB X0, X1",
		"VPSIGNW Z0, Z1, Z2",
		"VPSIGND X0, K1, X1, X2",
		"VPSIGNB.Z X0, X1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedAbsSignRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"PABSB X8, X0",
		"PABSW X0, X8",
		"PSIGND X8, X0",
	} {
		assertX86PackedAbsSignRejected(t, "386", "i386-unknown-linux-gnu", instruction)
	}
}

func assertX86PackedAbsSignRejected(t *testing.T, goarch, triple, instruction string) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
	if err != nil {
		return
	}
	if _, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       goarch,
		Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
	}); err == nil {
		t.Fatalf("Translate accepted %q outside Go 1.27's packed abs/sign tables", instruction)
	}
}

func TestAMD64PackedAbsSignRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := `
TEXT packedabssign(SB),NOSPLIT,$0-40
	MOVQ out+0(FP), AX
	MOVQ source+8(FP), BX
	MOVQ control+16(FP), CX
	MOVQ old+24(FP), DX
	MOVQ mask+32(FP), SI
	KMOVQ SI, K1

	MOVOU (BX), X0
	PABSB X0, X0
	MOVOU X0, 0(AX)

	MOVOU (BX), X0
	PSIGNW (CX), X0
	MOVOU X0, 16(AX)

	VMOVDQU (DX), Y1
	VPABSD.BCST (BX), K1, Y1
	VMOVDQU Y1, 32(AX)

	VMOVDQU (BX), Y0
	VPSIGND (CX), Y0, Y2
	VMOVDQU Y2, 64(AX)

	VMOVDQU64 (BX), Z0
	VPABSQ.Z Z0, K1, Z1
	VMOVDQU64 Z1, 96(AX)
	VZEROUPPER
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	frame := FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: Ptr, Index: 1, Field: -1},
		{Offset: 16, Type: Ptr, Index: 2, Field: -1},
		{Offset: 24, Type: Ptr, Index: 3, Field: -1},
		{Offset: 32, Type: I64, Index: 4, Field: -1},
	}}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"packedabssign": {
				Name: "packedabssign", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: frame,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
#include <string.h>
#include <limits.h>
extern void packedabssign(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, uint64_t);
static uint8_t abs8(uint8_t v) { return (v & 0x80) ? (uint8_t)(0-v) : v; }
static int16_t sign16(int16_t value, int16_t control) {
  return control > 0 ? value : control < 0 ? (int16_t)(0-(uint16_t)value) : 0;
}
static int32_t sign32(int32_t value, int32_t control) {
  return control > 0 ? value : control < 0 ? (int32_t)(0-(uint32_t)value) : 0;
}
static int32_t abs32(int32_t value) { return value < 0 ? (int32_t)(0-(uint32_t)value) : value; }
static int64_t abs64(int64_t value) { return value < 0 ? (int64_t)(0-(uint64_t)value) : value; }
int main(void) {
  union { uint8_t b[64]; int16_t w[32]; int32_t d[16]; int64_t q[8]; } source, control, old;
  uint8_t out[160];
  for (int i = 0; i < 64; i++) {
    source.b[i] = (uint8_t)(i * 29 + 0x80);
    control.b[i] = (uint8_t)(i * 17 - 71);
    old.b[i] = (uint8_t)(0xf0 - i);
  }
  control.w[0] = 1; control.w[1] = 0; control.w[2] = -1; control.w[3] = INT16_MIN;
  control.d[0] = 1; control.d[1] = 0; control.d[2] = -1; control.d[3] = INT32_MIN;
  memset(out, 0xcc, sizeof(out));
  const uint64_t mask = 0xa5;
  packedabssign(out, source.b, control.b, old.b, mask);
  for (int i = 0; i < 16; i++) if (out[i] != abs8(source.b[i])) return 10+i;
  const int16_t *got16 = (const int16_t *)(out+16);
  for (int i = 0; i < 8; i++) if (got16[i] != sign16(source.w[i], control.w[i])) return 40+i;
  const int32_t *gotAbs32 = (const int32_t *)(out+32);
  int32_t broadcast = abs32(source.d[0]);
  for (int i = 0; i < 8; i++) {
    int32_t want = (mask >> i) & 1 ? broadcast : old.d[i];
    if (gotAbs32[i] != want) return 60+i;
  }
  const int32_t *gotSign32 = (const int32_t *)(out+64);
  for (int i = 0; i < 8; i++) if (gotSign32[i] != sign32(source.d[i], control.d[i])) return 80+i;
  const int64_t *gotAbs64 = (const int64_t *)(out+96);
  for (int i = 0; i < 8; i++) {
    int64_t want = (mask >> i) & 1 ? abs64(source.q[i]) : 0;
    if (gotAbs64[i] != want) return 100+i;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_abs_sign", triple, ll, mainC, runPrefix)
}
