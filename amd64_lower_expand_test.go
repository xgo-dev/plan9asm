package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64PackedExpandGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := map[Op]amd64PackedExpandSpec{
		"VEXPANDPD": {laneBits: 64},
		"VEXPANDPS": {laneBits: 32},
		"VPEXPANDB": {laneBits: 8},
		"VPEXPANDW": {laneBits: 16},
		"VPEXPANDD": {laneBits: 32},
		"VPEXPANDQ": {laneBits: 64},
	}
	if len(amd64PackedExpandSpecs) != len(expected) {
		t.Fatalf("packed-expand grammar has %d entries, want %d", len(amd64PackedExpandSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64PackedExpandSpecs[op]; !ok {
			t.Errorf("packed-expand grammar omitted %s", op)
		} else if got != want {
			t.Errorf("packed-expand grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86PackedExpandCompleteGoFormsAcrossTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
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
			source.WriteString("TEXT packedexpandforms(SB),$0-0\n")
			for _, op := range []string{"VEXPANDPD", "VEXPANDPS", "VPEXPANDB", "VPEXPANDW", "VPEXPANDD", "VPEXPANDQ"} {
				for _, width := range []string{"X", "Y", "Z"} {
					sourceReg, destinationReg := 29, 31
					if target.goarch == "386" && width == "Z" {
						sourceReg, destinationReg = 6, 7
					}
					fmt.Fprintf(&source, "\t%s %s%d, %s%d\n", op, width, sourceReg, width, destinationReg)
					fmt.Fprintf(&source, "\t%s 8(R9), %s%d\n", op, width, destinationReg)
					fmt.Fprintf(&source, "\t%s %s%d, K1, %s%d\n", op, width, sourceReg, width, destinationReg)
					fmt.Fprintf(&source, "\t%s.Z 16(R9), K7, %s%d\n", op, width, destinationReg)
				}
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)

			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"packedexpandforms": {Name: "packedexpandforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"@llvm.masked.expandload.v", "extractelement", "select i1"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("packed-expand lowering omitted %q:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "packed-expand-"+target.name+".ll", "packed-expand-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86PackedExpandRejectsFormsOutsideGoTable(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VPEXPANDB X0, Y1"},
		{goarch: "amd64", instruction: "VPEXPANDW Y0, Z1"},
		{goarch: "amd64", instruction: "VPEXPANDD X0, K0, X1"},
		{goarch: "amd64", instruction: "VPEXPANDQ.Z X0, X1"},
		{goarch: "amd64", instruction: "VEXPANDPS.BCST 0(AX), X1"},
		{goarch: "amd64", instruction: "VEXPANDPD.SAE X0, X1"},
		{goarch: "amd64", instruction: "VPEXPANDB X0, 0(AX)"},
		{goarch: "amd64", instruction: "VPEXPANDW AX, X1"},
		{goarch: "amd64", instruction: "VPEXPANDD X0, K1, K2, X1"},
		{goarch: "386", instruction: "VPEXPANDB Z8, Z0"},
		{goarch: "386", instruction: "VEXPANDPD Z0, K1, Z8"},
	} {
		t.Run(test.goarch+"/"+strings.NewReplacer(" ", "_", ",", "", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + test.instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, test.goarch, source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			triple := "x86_64-unknown-linux-gnu"
			if test.goarch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			if _, err := Translate(file, Options{
				Goarch: test.goarch, TargetTriple: triple,
				Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's _yvexpandpd table", test.instruction)
			}
		})
	}
}

func TestAMD64PackedExpandRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT packedexpandsemantics(SB),$0-32
	MOVQ out+0(FP), AX
	MOVQ source+8(FP), BX
	MOVQ old+16(FP), CX
	MOVQ mask+24(FP), DX
	KMOVQ DX, K1
	VMOVDQU64 0(BX), Z0
	VMOVDQU64 0(CX), Z1
	VPEXPANDB Z0, K1, Z1
	VMOVDQU64 Z1, 0(AX)
	VMOVDQU64 0(CX), Z1
	VPEXPANDW.Z Z0, K1, Z1
	VMOVDQU64 Z1, 64(AX)
	VMOVDQU64 0(CX), Z1
	VPEXPANDD 0(BX), K1, Z1
	VMOVDQU64 Z1, 128(AX)
	VMOVDQU64 0(CX), Z1
	VPEXPANDQ.Z Z0, K1, Z1
	VMOVDQU64 Z1, 192(AX)
	VMOVDQU64 0(CX), Z1
	VEXPANDPS Z0, K1, Z1
	VMOVDQU64 Z1, 256(AX)
	VMOVDQU64 0(CX), Z1
	VEXPANDPD.Z 0(BX), K1, Z1
	VMOVDQU64 Z1, 320(AX)
	VMOVDQU64 0(BX), Z1
	VPEXPANDD Z1, K1, Z1
	VMOVDQU64 Z1, 384(AX)
	XORQ DX, DX
	KMOVQ DX, K2
	VMOVDQU64 0(CX), Z1
	STC
	VPEXPANDB 0(DX), K2, Z1
	VMOVDQU64 Z1, 448(AX)
	SETCS 512(AX)
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
		Sigs: map[string]FuncSig{"packedexpandsemantics": {
			Name: "packedexpandsemantics", Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void,
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
extern void packedexpandsemantics(uint8_t *, const uint8_t *, const uint8_t *, uint64_t);
static int check(const uint8_t *got, const uint8_t *source, const uint8_t *old,
                 int lane_bytes, uint64_t mask, int zeroing) {
  int lanes = 64 / lane_bytes, packed = 0;
  for (int lane = 0; lane < lanes; lane++) {
    const uint8_t *want = zeroing ? (const uint8_t[8]){0} : old + lane*lane_bytes;
    if ((mask >> lane) & 1) want = source + packed++*lane_bytes;
    if (memcmp(got + lane*lane_bytes, want, lane_bytes)) return 10 + lane;
  }
  return 0;
}
int main(void) {
  uint8_t source[64], old[64], out[513];
  const uint64_t mask = UINT64_C(0xa55aa55aa55aa55a);
  for (int i = 0; i < 64; i++) { source[i] = (uint8_t)(i*37 + 9); old[i] = (uint8_t)(0xe0 - i); }
  memset(out, 0xcc, sizeof(out));
  packedexpandsemantics(out, source, old, mask);
  int r;
  if ((r = check(out+0, source, old, 1, mask, 0))) return 100+r;
  if ((r = check(out+64, source, old, 2, mask, 1))) return 200+r;
  if ((r = check(out+128, source, old, 4, mask, 0))) return 300+r;
  if ((r = check(out+192, source, old, 8, mask, 1))) return 400+r;
  if ((r = check(out+256, source, old, 4, mask, 0))) return 500+r;
  if ((r = check(out+320, source, old, 8, mask, 1))) return 600+r;
  if ((r = check(out+384, source, source, 4, mask, 0))) return 700+r;
  if (memcmp(out+448, old, 64)) return 800;
  if (out[512] != 1) return 801;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_expand_semantics", triple, ir, mainC, runPrefix)
}
