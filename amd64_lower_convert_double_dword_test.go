package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedDoubleDwordCompleteGoAssemblerForms(t *testing.T) {
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
			high := 20
			conversionHigh, conversionBroadcast := 20, 9
			zBroadcast, zRound, zRoundMask := 8, 9, 11
			if target.goarch == "386" {
				high = 4
				zBroadcast, zRound, zRoundMask = 0, 1, 3
				conversionHigh, conversionBroadcast = 4, 6
			}
			source := fmt.Sprintf(`
TEXT packeddoubledwordforms(SB),$0-0
	CVTPD2PL X0, X1
	CVTTPD2PL 16(AX), X2
	VCVTDQ2PD X0, X1
	VCVTDQ2PD 32(AX), Y2
	VCVTDQ2PD Y3, Z4
	VCVTDQ2PD X%d, K1, X%d
	VCVTDQ2PD.Z 64(AX), K2, Y7
	VCVTDQ2PD.BCST 80(AX), Z%d
	VCVTDQ2PD.BCST.Z 84(AX), K3, X%d
	VCVTPD2DQX X0, X1
	VCVTPD2DQX 88(AX), X2
	VCVTPD2DQX X%d, K1, X%d
	VCVTPD2DQX 96(AX), K1, X2
	VCVTPD2DQX.Z 104(AX), K2, X3
	VCVTPD2DQX.BCST 112(AX), X4
	VCVTPD2DQX.BCST.Z 120(AX), K3, X5
	VCVTPD2DQY Y%d, X%d
	VCVTPD2DQY 128(AX), X4
	VCVTPD2DQY Y3, K1, X4
	VCVTPD2DQY.Z 128(AX), K2, X5
	VCVTPD2DQY.BCST 136(AX), X6
	VCVTPD2DQY.BCST.Z 144(AX), K3, X7
	VCVTPD2DQ Z6, Y7
	VCVTPD2DQ 160(AX), K1, Y8
	VCVTPD2DQ.Z 168(AX), K2, Y9
	VCVTPD2DQ.BCST 176(AX), Y10
	VCVTPD2DQ.BCST.Z 184(AX), K3, Y11
	VCVTPD2DQ.RN_SAE Z%d, Y10
	VCVTPD2DQ.RD_SAE.Z Z%d, K3, Y12
	VCVTPD2DQ.RU_SAE Z%d, Y13
	VCVTPD2DQ.RZ_SAE.Z Z%d, K4, Y14
	VCVTTPD2DQX X0, X1
	VCVTTPD2DQX 216(AX), X2
	VCVTTPD2DQX X%d, K1, X%d
	VCVTTPD2DQX 224(AX), K1, X2
	VCVTTPD2DQX.Z 232(AX), K2, X3
	VCVTTPD2DQX.BCST 240(AX), X4
	VCVTTPD2DQX.BCST.Z 248(AX), K3, X5
	VCVTTPD2DQY Y%d, X%d
	VCVTTPD2DQY 256(AX), X4
	VCVTTPD2DQY Y3, K1, X4
	VCVTTPD2DQY.Z 256(AX), K2, X5
	VCVTTPD2DQY.BCST 264(AX), X6
	VCVTTPD2DQY.BCST.Z 272(AX), K3, X7
	VCVTTPD2DQ Z6, Y7
	VCVTTPD2DQ 288(AX), K1, Y8
	VCVTTPD2DQ.Z 296(AX), K2, Y9
	VCVTTPD2DQ.BCST 304(AX), Y10
	VCVTTPD2DQ.BCST.Z 312(AX), K3, Y11
	VCVTTPD2DQ.SAE Z%d, Y10
	VCVTTPD2DQ.SAE.Z Z%d, K3, Y12
	RET
`, conversionHigh, conversionHigh+1, zBroadcast, conversionBroadcast,
				high, high+1, high, high+1, zRound, zRoundMask, zRound, zRoundMask,
				high, high+1, high, high+1, zRound, zRoundMask)
			if target.goarch == "386" {
				for n := 8; n <= 14; n++ {
					source = strings.ReplaceAll(source, fmt.Sprintf("Y%d", n), fmt.Sprintf("Y%d", n%8))
				}
			}
			ll := x86UnboundVoidScalarFormatObject(t, source, "packeddoubledwordforms", target.goarch, target.triple)
			for _, want := range []string{"vcvtdq2pd", "cvtpd2dq", "vcvttpd2dq"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("packed double/dword IR is missing %q:\n%s", want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-double-dword-"+target.name+".ll", "packed-double-dword-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedDoubleDwordRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"CVTPD2PL Y0, X1",
		"CVTTPD2PL X0, Y1",
		"CVTTPD2PL.Z X0, X1",
		"VCVTDQ2PD Y0, X1",
		"VCVTDQ2PD X0, Z1",
		"VCVTDQ2PD.BCST X0, X1",
		"VCVTDQ2PD.RN_SAE Y0, Z1",
		"VCVTPD2DQ X0, X1",
		"VCVTPD2DQY X0, X1",
		"VCVTPD2DQX Y0, X1",
		"VCVTPD2DQY.BCST X0, X1",
		"VCVTPD2DQ.RN_SAE 0(AX), Y1",
		"VCVTTPD2DQX.SAE X0, X1",
		"VCVTTPD2DQ.SAE 0(AX), Y1",
		"VCVTTPD2DQ.Z Z0, Y1",
		"VCVTTPD2DQ Z0, K0, Y1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedDoubleDwordRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	assertX86PackedDoubleDwordRejected(t, "386", "i386-unknown-linux-gnu", "VCVTPD2DQ Z8, Y1")
}

func assertX86PackedDoubleDwordRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's packed double/dword tables", instruction)
	}
}

func TestAMD64PackedDoubleDwordRuntimeSemantics(t *testing.T) {
	amd64PackedDoubleDwordRuntime(t, x86FloatCompareRuntimeTools(t, x86FloatCompareSSE), false)
}

func x86PackedDoubleDwordOriginalAssembly() string {
	return `
TEXT packeddoubledword(SB),NOSPLIT,$0-40
	MOVQ out+0(FP), AX
	MOVQ doubles+8(FP), BX
	MOVQ dwords+16(FP), CX
	MOVQ old+24(FP), DX
	MOVQ mask+32(FP), SI
	KMOVQ SI, K1

	VMOVDQU64 (DX), Z1
	VCVTDQ2PD (CX), K1, Z1
	VMOVDQU64 Z1, 0(AX)

	VCVTTPD2DQY (BX), X2
	VMOVDQU X2, 64(AX)

	VMOVDQU64 (BX), Z0
	VCVTPD2DQ.RD_SAE.Z Z0, K1, Y3
	VMOVDQU Y3, 80(AX)

	MOVOU (BX), X4
	CVTPD2PL X4, X0
	MOVQ X0, 112(AX)
	VZEROUPPER
	RET
`
}

func x86PackedDoubleDwordRawAssembly(source string) string {
	return strings.NewReplacer(
		"TEXT packeddoubledword(SB),NOSPLIT,$0-40", "TEXT packeddoubledword(SB),4,$0-40",
		"VCVTDQ2PD (CX), K1, Z1", "BYTE $0x62; BYTE $0xf1; BYTE $0x7e; BYTE $0x49; BYTE $0xe6; BYTE $0x09",
		"VCVTTPD2DQY (BX), X2", "BYTE $0xc5; BYTE $0xfd; BYTE $0xe6; BYTE $0x13",
		"VCVTPD2DQ.RD_SAE.Z Z0, K1, Y3", "BYTE $0x62; BYTE $0xf1; BYTE $0xff; BYTE $0xb9; BYTE $0xe6; BYTE $0xd8",
		"CVTPD2PL X4, X0", "BYTE $0xf2; BYTE $0x0f; BYTE $0xe6; BYTE $0xc4",
	).Replace(source)
}

func x86PackedDoubleDwordSSEAssembly(t *testing.T) string {
	t.Helper()
	source := x86PackedDoubleDwordOriginalAssembly()
	preamble := strings.Index(source, "\tKMOVQ SI, K1")
	legacy := strings.Index(source, "\tMOVOU (BX), X4")
	wideExit := strings.Index(source, "\tVZEROUPPER")
	if preamble < 0 || legacy <= preamble || wideExit <= legacy {
		t.Fatal("original complete double/dword fixture lost its explicit SSE block")
	}
	return source[:preamble] + source[legacy:wideExit] + "\tRET\n"
}

func amd64PackedDoubleDwordRuntime(t *testing.T, execution x86FloatCompareExecution, nativeWide bool) {
	t.Helper()
	source := x86PackedDoubleDwordOriginalAssembly()
	if !nativeWide {
		source = x86PackedDoubleDwordSSEAssembly(t)
	}
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
	triple := execution.triple
	translationOptions := Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"packeddoubledword": {
				Name: "packeddoubledword", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: frame,
			},
		},
	}
	ll, err := Translate(file, translationOptions)
	if err != nil {
		t.Fatal(err)
	}
	// The entire original named and raw functions still reach Go and LLVM
	// objects in the portable lane. Only their execution requires native ISA.
	for _, complete := range []string{x86PackedDoubleDwordOriginalAssembly(), x86PackedDoubleDwordRawAssembly(x86PackedDoubleDwordOriginalAssembly())} {
		goAssemblerOracleOutput(t, "amd64", x86PackedDoubleDwordGoAssemblerSource(complete), "", true)
		parsed, err := Parse(ArchAMD64, complete)
		if err != nil {
			t.Fatal(err)
		}
		objectIR, err := Translate(parsed, translationOptions)
		if err != nil {
			t.Fatal(err)
		}
		compileLLVMToObject(t, execution.llc, triple, "complete-double-dword.ll", "complete-double-dword.o", objectIR)
	}
	mainC := fmt.Sprintf("#define NATIVE_WIDE %d\n", x86FloatAddSubBoolInt(nativeWide)) + `
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <limits.h>
extern void packeddoubledword(uint8_t *, const double *, const int32_t *, const double *, uint64_t);
int main(void) {
  const double doubles[8] = {1.75, -2.75, 2147483648.0, NAN, -2147483648.0, -2147483649.0, 3.0, -0.0};
  const int32_t dwords[8] = {0, 1, -1, INT32_MAX, INT32_MIN, 123456789, -987654321, 42};
  const double old[8] = {100.5, 101.5, 102.5, 103.5, 104.5, 105.5, 106.5, 107.5};
  const uint64_t mask = 0xa5;
  uint8_t out[120]; memset(out, 0xcc, sizeof(out));
  packeddoubledword(out, doubles, dwords, old, mask);

#if NATIVE_WIDE
  const double *widened = (const double *)(out+0);
  for (int i = 0; i < 8; i++) {
    double want = (mask >> i) & 1 ? (double)dwords[i] : old[i];
    if (widened[i] != want) return 10+i;
  }
  const int32_t *truncated = (const int32_t *)(out+64);
  const int32_t wantTruncated[4] = {1, -2, INT32_MIN, INT32_MIN};
  for (int i = 0; i < 4; i++) if (truncated[i] != wantTruncated[i]) return 30+i;

  const int32_t *roundedDown = (const int32_t *)(out+80);
  const int32_t wantRoundedDown[8] = {1, 0, INT32_MIN, 0, 0, INT32_MIN, 0, 0};
  for (int i = 0; i < 8; i++) if (roundedDown[i] != wantRoundedDown[i]) return 50+i;
#endif

  const int32_t *legacy = (const int32_t *)(out+112);
  if (legacy[0] != 2 || legacy[1] != -3) return 70;
  return 0;
}
`
	execution.compileAndRunLLVM(t, "packed_double_dword", ll, mainC, "-O2")

	rawSource := x86PackedDoubleDwordRawAssembly(source)
	goAssemblerOracleOutput(t, "amd64", x86PackedDoubleDwordGoAssemblerSource(rawSource), "", true)
	rawFile, err := Parse(ArchAMD64, rawSource)
	if err != nil {
		t.Fatal(err)
	}
	rawIR, err := Translate(rawFile, translationOptions)
	if err != nil {
		t.Fatal(err)
	}
	execution.compileAndRunLLVM(t, "raw_packed_double_dword", rawIR, mainC, "-O2")
	t.Logf("complete named/raw objects; SSE legacy output executed; full 120-byte native-wide assertions=%v", nativeWide)
}
