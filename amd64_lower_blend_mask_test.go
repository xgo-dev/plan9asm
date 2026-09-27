package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64MaskBlendGrammarCoversCompleteGoFamilies(t *testing.T) {
	expected := map[Op]amd64MaskBlendSpec{
		"VBLENDMPS": {laneBits: 32, broadcast: true},
		"VBLENDMPD": {laneBits: 64, broadcast: true},
		"VPBLENDMB": {laneBits: 8},
		"VPBLENDMW": {laneBits: 16},
		"VPBLENDMD": {laneBits: 32, broadcast: true},
		"VPBLENDMQ": {laneBits: 64, broadcast: true},
	}
	if len(amd64MaskBlendSpecs) != len(expected) {
		t.Fatalf("mask-blend grammar has %d entries, want %d", len(amd64MaskBlendSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64MaskBlendSpecs[op]; !ok {
			t.Errorf("mask-blend grammar omitted %s", op)
		} else if got != want {
			t.Errorf("mask-blend grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86MaskBlendCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 shares _yvblendmpd across VBLENDM{PS,PD} and
	// VPBLENDM{B,W,D,Q}: matching X/Y/Z sources and destination, optional
	// K1-K7 selection mask, and .Z. PS/PD/D/Q additionally enable
	// scalar-memory broadcast on the first Plan 9 source.
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
			lastZ := 20
			if target.goarch == "386" {
				lastZ = 7
			}
			var source strings.Builder
			source.WriteString("TEXT maskblendforms(SB),$0-0\n")
			for _, family := range []struct {
				op        string
				broadcast bool
			}{
				{op: "VBLENDMPS", broadcast: true},
				{op: "VBLENDMPD", broadcast: true},
				{op: "VPBLENDMB"},
				{op: "VPBLENDMW"},
				{op: "VPBLENDMD", broadcast: true},
				{op: "VPBLENDMQ", broadcast: true},
			} {
				op := family.op
				fmt.Fprintf(&source, "\t%s X1, X20, X21\n", op)
				fmt.Fprintf(&source, "\t%s 8(AX), Y20, Y21\n", op)
				fmt.Fprintf(&source, "\t%s Z1, Z2, Z%d\n", op, lastZ)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s X1, X20, K1, X21\n", op)
					fmt.Fprintf(&source, "\t%s.Z Y1, Y20, K2, Y21\n", op)
					fmt.Fprintf(&source, "\t%s.Z 40(AX), Z20, K3, Z21\n", op)
				}
				if family.broadcast {
					fmt.Fprintf(&source, "\t%s.BCST 104(AX), X20, X21\n", op)
					fmt.Fprintf(&source, "\t%s.BCST 112(AX), Y20, Y21\n", op)
					fmt.Fprintf(&source, "\t%s.BCST 120(AX), Z2, Z%d\n", op, lastZ)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s.BCST.Z 128(AX), Z20, K4, Z21\n", op)
					}
				}
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)

			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs:         map[string]FuncSig{"maskblendforms": {Name: "maskblendforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "mask-blend-"+target.name+".ll", "mask-blend-"+target.name+".o", ll)
		})
	}
}

func TestAMD64FloatingMaskBlendRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT floatingmaskblendsemantics(SB),$0-32
	MOVQ out+0(FP), AX
	MOVQ first+8(FP), BX
	MOVQ second+16(FP), CX
	MOVQ mask+24(FP), DX
	KMOVQ DX, K1
	VMOVDQU64 0(BX), Z0
	VMOVDQU64 0(CX), Z1
	VBLENDMPS Z0, Z1, K1, Z2
	VMOVDQU64 Z2, 0(AX)
	VBLENDMPD.Z Z0, Z1, K1, Z2
	VMOVDQU64 Z2, 64(AX)
	VBLENDMPS.BCST 0(BX), Z1, K1, Z2
	VMOVDQU64 Z2, 128(AX)
	VBLENDMPD.BCST.Z 0(BX), Z1, K1, Z2
	VMOVDQU64 Z2, 192(AX)
	STC
	VBLENDMPS Z0, Z1, K1, Z2
	SETCS 256(AX)
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{
		Goarch: "amd64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"floatingmaskblendsemantics": {
			Name: "floatingmaskblendsemantics", Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: I64, Index: 3, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void floatingmaskblendsemantics(uint8_t *, const uint8_t *, const uint8_t *, uint64_t);
int main(void) {
  uint32_t first32[16], second32[16]; uint8_t out[257] = {0};
  const uint64_t mask = UINT64_C(0xa55a);
  for (int i=0;i<16;i++) { first32[i]=UINT32_C(0x7f000000)+i; second32[i]=UINT32_C(0x3f000000)+i; }
  floatingmaskblendsemantics(out,(const uint8_t *)first32,(const uint8_t *)second32,mask);
  uint32_t *ps=(uint32_t *)(out+0), *psbcst=(uint32_t *)(out+128);
  for (int i=0;i<16;i++) {
    uint32_t want=(mask>>i)&1 ? first32[i] : second32[i]; if (ps[i]!=want) return 10+i;
    want=(mask>>i)&1 ? first32[0] : second32[i]; if (psbcst[i]!=want) return 30+i;
  }
  uint64_t first64[8], second64[8], pdzero[8], pdbczero[8];
  memcpy(first64,first32,64); memcpy(second64,second32,64);
  memcpy(pdzero,out+64,64); memcpy(pdbczero,out+192,64);
  for (int i=0;i<8;i++) {
    uint64_t want=(mask>>i)&1 ? first64[i] : 0; if (pdzero[i]!=want) return 50+i;
    want=(mask>>i)&1 ? first64[0] : 0; if (pdbczero[i]!=want) return 70+i;
  }
  if (out[256]!=1) return 90;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "floating_mask_blend_semantics", triple, ir, mainC, runPrefix)
}

func TestTranslateX86MaskBlendRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VBLENDMPS X0, Y1, Y2",
		"VBLENDMPD X0, X1, K0, X2",
		"VBLENDMPS.BCST X0, X1, X2",
		"VBLENDMPD.RN_SAE X0, X1, X2",
		"VPBLENDMQ X0, X1",
		"VPBLENDMQ X0, Y1, Y2",
		"VPBLENDMQ X0, (AX), X2",
		"VPBLENDMQ X0, X1, K0, X2",
		"VPBLENDMQ X0, X1, AX",
		"VPBLENDMQ.Z X0, X1, X2",
		"VPBLENDMQ.BCST X0, X1, X2",
		"VPBLENDMB.BCST (AX), X1, X2",
		"VPBLENDMW.BCST (AX), X1, X2",
		"VPBLENDMQ.Z.BCST (AX), X1, K1, X2",
		"VPBLENDMQ.RN_SAE X0, X1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			requireX86GoAssemblerResult(t, "amd64", "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n", false)
			assertX86MaskBlendRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	requireX86GoAssemblerResult(t, "386", "TEXT bad(SB),$0-0\n\tVPBLENDMQ X0, X1, K1, X2\n\tRET\n", false)
	assertX86MaskBlendRejected(t, "386", "i386-unknown-linux-gnu", "VPBLENDMQ X0, X1, K1, X2")
	requireX86GoAssemblerResult(t, "386", "TEXT bad(SB),$0-0\n\tVPBLENDMQ Z0, Z1, Z8\n\tRET\n", false)
	assertX86MaskBlendRejected(t, "386", "i386-unknown-linux-gnu", "VPBLENDMQ Z0, Z1, Z8")
}

func assertX86MaskBlendRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's VPBLENDM forms", instruction)
	}
}
