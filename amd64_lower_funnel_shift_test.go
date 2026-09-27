package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86FunnelShiftCompleteGo127Forms(t *testing.T) {
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
			source.WriteString("TEXT funnel_shift_forms(SB),$0-0\n")
			if target.goarch == "amd64" {
				for _, op := range []string{"VPSHLDW", "VPSHLDD", "VPSHLDQ", "VPSHRDW", "VPSHRDD", "VPSHRDQ"} {
					broadcast := !strings.HasSuffix(op, "W")
					for _, width := range []string{"X", "Y", "Z"} {
						fmt.Fprintf(&source, "\t%s $0, %s0, %s1, %s2\n", op, width, width, width)
						fmt.Fprintf(&source, "\t%s $255, 8(BX), %s3, %s4\n", op, width, width)
						fmt.Fprintf(&source, "\t%s $1, %s20, %s21, K1, %s22\n", op, width, width, width)
						fmt.Fprintf(&source, "\t%s.Z $2, 16(BX), %s23, K7, %s24\n", op, width, width)
						if broadcast {
							fmt.Fprintf(&source, "\t%s.BCST $3, 24(BX), %s25, %s26\n", op, width, width)
							fmt.Fprintf(&source, "\t%s.BCST.Z $4, 32(BX), %s27, K2, %s28\n", op, width, width)
						}
					}
				}
			}
			for _, op := range []string{"VPSHLDVW", "VPSHLDVD", "VPSHLDVQ", "VPSHRDVW", "VPSHRDVD", "VPSHRDVQ"} {
				broadcast := !strings.HasSuffix(op, "VW")
				for _, width := range []string{"X", "Y", "Z"} {
					fmt.Fprintf(&source, "\t%s %s0, %s1, %s2\n", op, width, width, width)
					fmt.Fprintf(&source, "\t%s 8(BX), %s3, %s4\n", op, width, width)
					if broadcast {
						fmt.Fprintf(&source, "\t%s.BCST 16(BX), %s5, %s6\n", op, width, width)
					}
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s %s20, %s21, K1, %s22\n", op, width, width, width)
						fmt.Fprintf(&source, "\t%s.Z 24(BX), %s23, K7, %s24\n", op, width, width)
						if broadcast {
							fmt.Fprintf(&source, "\t%s.BCST.Z 32(BX), %s25, K2, %s26\n", op, width, width)
						}
					}
				}
			}
			source.WriteString("\tRET\n")

			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs: map[string]FuncSig{
					"funnel_shift_forms": {Name: "funnel_shift_forms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "funnel-shift-"+target.name+".ll", "funnel-shift-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86FunnelShiftRejectsFormsOutsideGo127Tables(t *testing.T) {
	for _, instruction := range []string{
		"VPSHRDQ $0, X0, X1",
		"VPSHLDW $-1, X0, X1, X2",
		"VPSHRDD $256, X0, X1, X2",
		"VPSHLDQ AX, X0, X1, X2",
		"VPSHRDW $0, Y0, X1, X2",
		"VPSHLDVD Y0, X1, X2",
		"VPSHRDVQ X0, Y1, X2",
		"VPSHLDVW X0, X1, Y2",
		"VPSHRDQ $0, X0, 8(BX), X2",
		"VPSHLDVD X0, 8(BX), X2",
		"VPSHRDVQ X0, X1, 8(BX)",
		"VPSHLDQ $0, X0, X1, K0, X2",
		"VPSHRDVD X0, K1, X1, X2",
		"VPSHLDW.Z $0, X0, X1, X2",
		"VPSHRDVW.Z X0, X1, X2",
		"VPSHLDW.BCST $0, 8(BX), X1, X2",
		"VPSHRDVW.BCST 8(BX), X1, X2",
		"VPSHLDQ.BCST X0, X1, X2",
		"VPSHRDVD.BCST X0, X1, X2",
		"VPSHLDQ.Z.BCST $0, 8(BX), X1, K1, X2",
		"VPSHRDVQ.SAE X0, X1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, "amd64", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				Goarch:       "amd64",
				TargetTriple: "x86_64-unknown-linux-gnu",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's funnel-shift tables", instruction)
			}
		})
	}
	for _, instruction := range []string{
		"VPSHRDQ $0, X0, X1, X2",
		"VPSHLDW $0, 8(BX), Y1, Y2",
		"VPSHRDVD X0, X1, K1, X2",
		"VPSHLDVQ.Z 8(BX), Y1, K7, Y2",
		"VPSHRDVD.BCST.Z 16(BX), Z1, K2, Z2",
		"VPSHLDVW Z8, Z0, Z1",
		"VPSHRDVQ Z0, Z8, Z1",
		"VPSHLDVD Z0, Z1, Z8",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, "386", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				Goarch:       "386",
				TargetTriple: "i386-unknown-linux-gnu",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted 386 %q outside Go 1.27's frontend boundary", instruction)
			}
		})
	}
}

func TestAMD64FunnelShiftRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT funnelShiftSemantics(SB),$0-64
	MOVQ out+0(FP), AX
	MOVQ first+8(FP), BX
	MOVQ second+16(FP), CX
	MOVQ old+24(FP), DX
	MOVQ counts+32(FP), SI
	MOVQ scalarCount+40(FP), R8
	MOVQ scalarData+48(FP), R9
	VMOVDQU64 (BX), X0
	VMOVDQU64 (CX), X1
	VMOVDQU64 (SI), X3
	VPSHLDW $4, X0, X1, X4
	VMOVDQU64 X4, 0(AX)
	VPSHRDW $4, X0, X1, X5
	VMOVDQU64 X5, 16(AX)
	VPSHLDD $8, X0, X1, X6
	VMOVDQU64 X6, 32(AX)
	VPSHRDD $8, X0, X1, X7
	VMOVDQU64 X7, 48(AX)
	VPSHLDQ $13, X0, X1, X8
	VMOVDQU64 X8, 64(AX)
	VPSHRDQ $32, X0, X1, X9
	VMOVDQU64 X9, 80(AX)
	VMOVDQU64 (DX), X10
	VPSHLDVW X3, X1, X10
	VMOVDQU64 X10, 96(AX)
	VMOVDQU64 (DX), X11
	VPSHRDVD X3, X1, X11
	VMOVDQU64 X11, 112(AX)
	VMOVDQU64 (DX), X12
	VPSHLDVQ X3, X1, X12
	VMOVDQU64 X12, 128(AX)
	KMOVQ mask+56(FP), K1
	VMOVDQU64 (DX), X13
	VPSHRDQ $32, X0, X1, K1, X13
	VMOVDQU64 X13, 144(AX)
	VMOVDQU64 (DX), X14
	VPSHRDQ.Z $32, X0, X1, K1, X14
	VMOVDQU64 X14, 160(AX)
	VMOVDQU64 (DX), X15
	VPSHLDVD.BCST (R8), X1, X15
	VMOVDQU64 X15, 176(AX)
	VPSHRDD.BCST $8, (R9), X1, X16
	VMOVDQU64 X16, 192(AX)
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
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
		{Offset: 56, Type: I64, Index: 7, Field: -1},
	}}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"funnelShiftSemantics": {
				Name:  "funnelShiftSemantics",
				Args:  []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, I64},
				Ret:   Void,
				Frame: frame,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
typedef union { uint8_t b[16]; uint16_t w[8]; uint32_t d[4]; uint64_t q[2]; } V;
extern void funnelShiftSemantics(V *, const V *, const V *, const V *, const V *, const uint32_t *, const uint32_t *, uint64_t);
static uint16_t shl16(uint16_t a, uint16_t b, unsigned c) { c &= 15; return c ? (uint16_t)((a << c) | (b >> (16-c))) : a; }
static uint16_t shr16(uint16_t a, uint16_t b, unsigned c) { c &= 15; return c ? (uint16_t)((a >> c) | (b << (16-c))) : a; }
static uint32_t shl32(uint32_t a, uint32_t b, unsigned c) { c &= 31; return c ? (a << c) | (b >> (32-c)) : a; }
static uint32_t shr32(uint32_t a, uint32_t b, unsigned c) { c &= 31; return c ? (a >> c) | (b << (32-c)) : a; }
static uint64_t shl64(uint64_t a, uint64_t b, unsigned c) { c &= 63; return c ? (a << c) | (b >> (64-c)) : a; }
static uint64_t shr64(uint64_t a, uint64_t b, unsigned c) { c &= 63; return c ? (a >> c) | (b << (64-c)) : a; }
int main(void) {
  V first = {.q = {UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210)}};
  V second = {.q = {UINT64_C(0x8877665544332211), UINT64_C(0x1020304050607080)}};
  V old = {.q = {UINT64_C(0x0f1e2d3c4b5a6978), UINT64_C(0x8796a5b4c3d2e1f0)}};
  V counts = {.q = {UINT64_C(0x001f000800030000), UINT64_C(0x0041002000110004)}};
  uint32_t scalarCount = 37;
  uint32_t scalarData = UINT32_C(0xa1b2c3d4);
  V out[13] = {0}, want[13] = {0};
  for (int i = 0; i < 8; i++) {
    want[0].w[i] = shl16(second.w[i], first.w[i], 4);
    want[1].w[i] = shr16(second.w[i], first.w[i], 4);
    want[6].w[i] = shl16(old.w[i], second.w[i], counts.w[i]);
  }
  for (int i = 0; i < 4; i++) {
    want[2].d[i] = shl32(second.d[i], first.d[i], 8);
    want[3].d[i] = shr32(second.d[i], first.d[i], 8);
    want[7].d[i] = shr32(old.d[i], second.d[i], counts.d[i]);
    want[11].d[i] = shl32(old.d[i], second.d[i], scalarCount);
    want[12].d[i] = shr32(second.d[i], scalarData, 8);
  }
  for (int i = 0; i < 2; i++) {
    want[4].q[i] = shl64(second.q[i], first.q[i], 13);
    want[5].q[i] = shr64(second.q[i], first.q[i], 32);
    want[8].q[i] = shl64(old.q[i], second.q[i], counts.q[i]);
  }
  want[9].q[0] = want[5].q[0]; want[9].q[1] = old.q[1];
  want[10].q[0] = want[5].q[0]; want[10].q[1] = 0;
  funnelShiftSemantics(out, &first, &second, &old, &counts, &scalarCount, &scalarData, 1);
  return memcmp(out, want, sizeof(out)) == 0 ? 0 : 1;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "funnel_shift", triple, ir, mainC, runPrefix)
}
