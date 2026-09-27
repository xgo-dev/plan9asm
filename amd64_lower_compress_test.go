package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86PackedCompressCompleteGoAssemblerForms(t *testing.T) {
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
			source.WriteString("TEXT packedcompressforms(SB),$0-0\n")
			for _, op := range []string{"VCOMPRESSPS", "VCOMPRESSPD", "VPCOMPRESSB", "VPCOMPRESSW", "VPCOMPRESSD", "VPCOMPRESSQ"} {
				for _, width := range []string{"X", "Y", "Z"} {
					sourceReg, destinationReg := 20, 22
					if target.goarch == "386" && width == "Z" {
						sourceReg, destinationReg = 6, 7
					}
					fmt.Fprintf(&source, "\t%s %s%d, %s%d\n", op, width, sourceReg, width, destinationReg)
					fmt.Fprintf(&source, "\t%s %s%d, 8(AX)\n", op, width, sourceReg)
					fmt.Fprintf(&source, "\t%s %s%d, K1, %s%d\n", op, width, sourceReg, width, destinationReg)
					fmt.Fprintf(&source, "\t%s.Z %s%d, K7, %s%d\n", op, width, sourceReg, width, destinationReg)
					fmt.Fprintf(&source, "\t%s %s%d, K2, 8(AX)\n", op, width, sourceReg)
					fmt.Fprintf(&source, "\t%s.Z %s%d, K3, 8(AX)\n", op, width, sourceReg)
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
				Sigs: map[string]FuncSig{
					"packedcompressforms": {Name: "packedcompressforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-compress-"+target.name+".ll", "packed-compress-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedCompressRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VCOMPRESSPS 8(AX), X1",
		"VCOMPRESSPD X0, Y1",
		"VCOMPRESSPS X0, K0, X1",
		"VCOMPRESSPD.Z Z0, Z1",
		"VPCOMPRESSB 8(AX), X1",
		"VPCOMPRESSW X0, Y1",
		"VPCOMPRESSD X0, K0, X1",
		"VPCOMPRESSQ.Z Z0, Z1",
		"VPCOMPRESSB.BCST X0, X1",
		"VPCOMPRESSW X0, AX",
		"VPCOMPRESSD AX, X1",
		"VPCOMPRESSQ Z0, K1, K2, Z1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			if currentGoMinorAtLeast(27) {
				requireX86GoAssemblerResult(t, "amd64", "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n", false)
			}
			assertX86PackedCompressRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"VPCOMPRESSB Z8, Z0",
		"VPCOMPRESSW Z0, Z8",
		"VPCOMPRESSD Z8, K1, 8(AX)",
		"VPCOMPRESSQ Z0, K1, Z8",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			if currentGoMinorAtLeast(27) {
				requireX86GoAssemblerResult(t, "386", "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n", false)
			}
			assertX86PackedCompressRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86PackedCompressRejected(t *testing.T, goarch, triple, instruction string) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n")
	if err != nil {
		return
	}
	if _, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       goarch,
		Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
	}); err == nil {
		t.Fatalf("Translate accepted %q outside Go 1.27's _yvcompresspd forms for %s", instruction, goarch)
	}
}

func TestAMD64PackedCompressRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := `
TEXT packedcompress(SB),$0-32
	MOVQ out+0(FP), AX
	MOVQ source+8(FP), BX
	MOVQ old+16(FP), CX
	MOVQ mask+24(FP), DX
	KMOVQ DX, K1
	VMOVDQU64 (BX), Z0
	VMOVDQU64 (CX), Z1
	VPCOMPRESSB Z0, K1, Z1
	VMOVDQU64 Z1, 0(AX)
	VMOVDQU64 (CX), Z1
	VPCOMPRESSW.Z Z0, K1, Z1
	VMOVDQU64 Z1, 64(AX)
	VMOVDQU64 (CX), Z1
	VPCOMPRESSD Z0, K1, Z1
	VMOVDQU64 Z1, 128(AX)
	VMOVDQU64 (CX), Z1
	VPCOMPRESSQ.Z Z0, K1, Z1
	VMOVDQU64 Z1, 192(AX)
	VPCOMPRESSB Z0, K1, 256(AX)
	VPCOMPRESSW.Z Z0, K1, 320(AX)
	VPCOMPRESSD Z0, K1, 384(AX)
	VPCOMPRESSQ.Z Z0, K1, 448(AX)
	VMOVDQU64 (CX), Z1
	VCOMPRESSPS Z0, K1, Z1
	VMOVDQU64 Z1, 512(AX)
	VMOVDQU64 (CX), Z1
	VCOMPRESSPD.Z Z0, K1, Z1
	VMOVDQU64 Z1, 576(AX)
	VCOMPRESSPS Z0, K1, 640(AX)
	VCOMPRESSPD.Z Z0, K1, 704(AX)
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
		{Offset: 24, Type: I64, Index: 3, Field: -1},
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
			"packedcompress": {Name: "packedcompress", Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
#include <string.h>
extern void packedcompress(uint8_t *, const uint8_t *, const uint8_t *, uint64_t);
static int check_group(const uint8_t *got, const uint8_t *source, const uint8_t *old, int lane_bytes, uint64_t mask, int zero_tail, int memory) {
  int lanes = 64 / lane_bytes, packed = 0;
  for (int lane = 0; lane < lanes; lane++) if ((mask >> lane) & 1) {
    if (memcmp(got + packed*lane_bytes, source + lane*lane_bytes, lane_bytes)) return 10 + lane;
    packed++;
  }
  for (int lane = packed; lane < lanes; lane++) {
    const uint8_t *want = old + lane*lane_bytes;
    uint8_t zeros[8] = {0}, untouched[8]; memset(untouched, 0xcc, sizeof(untouched));
    if (memory) want = untouched; else if (zero_tail) want = zeros;
    if (memcmp(got + lane*lane_bytes, want, lane_bytes)) return 80 + lane;
  }
  return 0;
}
int main(void) {
  uint8_t source[64], old[64], out[768];
  const uint64_t mask = 0xa55aa55aa55aa55aULL;
  for (int i = 0; i < 64; i++) { source[i] = (uint8_t)(i * 29 + 7); old[i] = (uint8_t)(0xf0 - i); }
  memset(out, 0xcc, sizeof(out));
  packedcompress(out, source, old, mask);
  int r;
  if ((r = check_group(out+0, source, old, 1, mask, 0, 0))) return 100+r;
  if ((r = check_group(out+64, source, old, 2, mask, 1, 0))) return 200+r;
  if ((r = check_group(out+128, source, old, 4, mask, 0, 0))) return 300+r;
  if ((r = check_group(out+192, source, old, 8, mask, 1, 0))) return 400+r;
  if ((r = check_group(out+256, source, old, 1, mask, 0, 1))) return 500+r;
  if ((r = check_group(out+320, source, old, 2, mask, 0, 1))) return 600+r;
  if ((r = check_group(out+384, source, old, 4, mask, 0, 1))) return 700+r;
  if ((r = check_group(out+448, source, old, 8, mask, 0, 1))) return 800+r;
  if ((r = check_group(out+512, source, old, 4, mask, 0, 0))) return 900+r;
  if ((r = check_group(out+576, source, old, 8, mask, 1, 0))) return 1000+r;
  if ((r = check_group(out+640, source, old, 4, mask, 0, 1))) return 1100+r;
  if ((r = check_group(out+704, source, old, 8, mask, 0, 1))) return 1200+r;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_compress", triple, ll, mainC, runPrefix)
}
