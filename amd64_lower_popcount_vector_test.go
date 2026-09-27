package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86PackedPopcountCompleteGoAssemblerForms(t *testing.T) {
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
			source.WriteString("TEXT packedpopcountforms(SB),$0-0\n")
			for _, op := range []string{"VPOPCNTB", "VPOPCNTW", "VPOPCNTD", "VPOPCNTQ"} {
				for _, width := range []string{"X", "Y", "Z"} {
					last := 22
					if target.goarch == "386" && width == "Z" {
						last = 7
					}
					fmt.Fprintf(&source, "\t%s %s0, %s%d\n", op, width, width, last)
					fmt.Fprintf(&source, "\t%s 8(AX), %s%d\n", op, width, last)
					fmt.Fprintf(&source, "\t%s %s0, K1, %s%d\n", op, width, width, last)
					fmt.Fprintf(&source, "\t%s.Z 8(AX), K7, %s%d\n", op, width, last)
					if op == "VPOPCNTD" || op == "VPOPCNTQ" {
						fmt.Fprintf(&source, "\t%s.BCST 8(AX), %s%d\n", op, width, last)
						fmt.Fprintf(&source, "\t%s.BCST.Z 8(AX), K2, %s%d\n", op, width, last)
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
				Sigs: map[string]FuncSig{
					"packedpopcountforms": {Name: "packedpopcountforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-popcount-"+target.name+".ll", "packed-popcount-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedPopcountRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VPOPCNTB.BCST 8(AX), X1",
		"VPOPCNTW.BCST 8(AX), Z1",
		"VPOPCNTD.BCST X0, X1",
		"VPOPCNTQ X0, Y1",
		"VPOPCNTB X0, K0, X1",
		"VPOPCNTW.Z X0, X1",
		"VPOPCNTD.SAE X0, X1",
		"VPOPCNTQ X0, 8(AX)",
		"VPOPCNTB AX, X1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			if currentGoMinorAtLeast(27) {
				requireX86GoAssemblerResult(t, "amd64", "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n", false)
			}
			assertX86PackedPopcountRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"VPOPCNTD Z8, K1, Z0",
		"VPOPCNTQ Z0, Z8",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			if currentGoMinorAtLeast(27) {
				requireX86GoAssemblerResult(t, "386", "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n", false)
			}
			assertX86PackedPopcountRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86PackedPopcountRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's _yvexpandpd forms for %s", instruction, goarch)
	}
}

func TestAMD64PackedPopcountRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := `
TEXT packedpopcount(SB),$0-32
	MOVQ out+0(FP), AX
	MOVQ source+8(FP), BX
	MOVQ old+16(FP), CX
	MOVQ mask+24(FP), DX
	KMOVQ DX, K1
	VMOVDQU64 (BX), Z0
	VMOVDQU64 (CX), Z1
	VPOPCNTB Z0, Z2
	VMOVDQU64 Z2, 0(AX)
	VPOPCNTW Z0, K1, Z1
	VMOVDQU64 Z1, 64(AX)
	VPOPCNTD.Z Z0, K1, Z1
	VMOVDQU64 Z1, 128(AX)
	VPOPCNTQ (BX), Z2
	VMOVDQU64 Z2, 192(AX)
	VPOPCNTD.BCST (BX), Z2
	VMOVDQU64 Z2, 256(AX)
	VPOPCNTQ.BCST.Z (BX), K1, Z1
	VMOVDQU64 Z1, 320(AX)
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
			"packedpopcount": {Name: "packedpopcount", Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
#include <string.h>
extern void packedpopcount(uint8_t *, const uint8_t *, const uint8_t *, uint64_t);
static unsigned pop64(uint64_t v) {
  unsigned n = 0;
  while (v) { n += v & 1; v >>= 1; }
  return n;
}
int main(void) {
  uint8_t source[64], old[64], out[384];
  const uint64_t mask = 0xa55a5aa5ULL;
  for (int i = 0; i < 64; i++) { source[i] = (uint8_t)(i * 37 + 11); old[i] = (uint8_t)(0xe0 - i); }
  memset(out, 0xcc, sizeof(out));
  packedpopcount(out, source, old, mask);
  for (int i = 0; i < 64; i++) if (out[i] != pop64(source[i])) return 10 + i;
  for (int i = 0; i < 32; i++) {
    uint16_t src, prior, got; memcpy(&src, source+2*i, 2); memcpy(&prior, old+2*i, 2); memcpy(&got, out+64+2*i, 2);
    uint16_t want = (mask >> i) & 1 ? (uint16_t)pop64(src) : prior;
    if (got != want) return 80 + i;
  }
  for (int i = 0; i < 16; i++) {
    uint32_t src, got; memcpy(&src, source+4*i, 4); memcpy(&got, out+128+4*i, 4);
    uint32_t want = (mask >> i) & 1 ? pop64(src) : 0;
    if (got != want) return 120 + i;
  }
  for (int i = 0; i < 8; i++) {
    uint64_t src, got; memcpy(&src, source+8*i, 8); memcpy(&got, out+192+8*i, 8);
    if (got != pop64(src)) return 150 + i;
  }
  uint32_t first32; memcpy(&first32, source, 4);
  for (int i = 0; i < 16; i++) { uint32_t got; memcpy(&got, out+256+4*i, 4); if (got != pop64(first32)) return 170 + i; }
  uint64_t first64; memcpy(&first64, source, 8);
  for (int i = 0; i < 8; i++) { uint64_t got; memcpy(&got, out+320+8*i, 8); uint64_t want = (mask >> i) & 1 ? pop64(first64) : 0; if (got != want) return 190 + i; }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_popcount", triple, ll, mainC, runPrefix)
}
