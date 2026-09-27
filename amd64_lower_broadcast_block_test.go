package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86PackedBlockBroadcastCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 exposes the complete VEX/EVEX packed-block broadcast family as:
	//
	//   VBROADCASTF128   m128   -> Y
	//   VBROADCASTI128   m128   -> Y
	//   VBROADCASTF32X2  X/m64  -> Y/Z
	//   VBROADCASTI32X2  X/m64  -> X/Y/Z
	//   VBROADCASTF32X4  m128   -> Y/Z
	//   VBROADCASTF64X2  m128   -> Y/Z
	//   VBROADCASTI32X4  m128   -> Y/Z
	//   VBROADCASTI64X2  m128   -> Y/Z
	//   VBROADCASTF32X8  m256   -> Z
	//   VBROADCASTF64X4  m256   -> Z
	//   VBROADCASTI32X8  m256   -> Z
	//   VBROADCASTI64X4  m256   -> Z
	//
	// Every form also accepts K1-K7 merge masking and .Z zero masking.
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
			lastY := 15
			lastZ := 21
			if target.goarch == "386" {
				lastZ = 7
			}
			var src strings.Builder
			src.WriteString("TEXT packedblockbroadcastforms(SB),$0-0\n")
			fmt.Fprintf(&src, "\tVBROADCASTF128 0(AX), Y%d\n", lastY)
			fmt.Fprintf(&src, "\tVBROADCASTI128 16(AX), Y%d\n", lastY)
			src.WriteString("\tVBROADCASTF32X2 X20, Y21\n")
			src.WriteString("\tVBROADCASTF32X2 8(AX), K1, Y20\n")
			fmt.Fprintf(&src, "\tVBROADCASTF32X2.Z X20, K2, Z%d\n", lastZ)
			src.WriteString("\tVBROADCASTI32X2 X20, X21\n")
			src.WriteString("\tVBROADCASTI32X2 16(AX), K3, Y20\n")
			fmt.Fprintf(&src, "\tVBROADCASTI32X2.Z X20, K4, Z%d\n", lastZ)
			for _, op := range []string{
				"VBROADCASTF32X4", "VBROADCASTF64X2",
				"VBROADCASTI32X4", "VBROADCASTI64X2",
			} {
				fmt.Fprintf(&src, "\t%s 24(AX), Y20\n", op)
				fmt.Fprintf(&src, "\t%s 40(AX), K5, Y21\n", op)
				fmt.Fprintf(&src, "\t%s.Z 56(AX), K6, Z%d\n", op, lastZ)
			}
			for _, op := range []string{
				"VBROADCASTF32X8", "VBROADCASTF64X4",
				"VBROADCASTI32X8", "VBROADCASTI64X4",
			} {
				fmt.Fprintf(&src, "\t%s 72(AX), Z%d\n", op, lastZ)
				fmt.Fprintf(&src, "\t%s.Z 104(AX), K7, Z%d\n", op, lastZ)
			}
			src.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, src.String(), true)

			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"packedblockbroadcastforms": {Name: "packedblockbroadcastforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-block-broadcast-"+target.name+".ll", "packed-block-broadcast-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedBlockBroadcastRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"VBROADCASTF128 (AX), Y16",
		"VBROADCASTI128 (AX), Y16",
		"VBROADCASTF128 X0, Y1",
		"VBROADCASTI128 X0, Y1",
		"VBROADCASTF128 (AX), X1",
		"VBROADCASTI128 (AX), Z1",
		"VBROADCASTF128 (AX), K1, Y1",
		"VBROADCASTI128.Z (AX), K1, Y1",
		"VBROADCASTF32X2 X0, X1",
		"VBROADCASTF32X2 Y0, Y1",
		"VBROADCASTI32X2 Y0, Y1",
		"VBROADCASTF32X4 X0, Y1",
		"VBROADCASTF64X2 X0, Y1",
		"VBROADCASTI32X4 X0, Y1",
		"VBROADCASTI64X2 X0, Y1",
		"VBROADCASTF32X4 (AX), X1",
		"VBROADCASTF32X8 (AX), Y1",
		"VBROADCASTF64X4 Y0, Z1",
		"VBROADCASTI32X8 Y0, Z1",
		"VBROADCASTI64X4 (AX), Y1",
		"VBROADCASTI32X4 (AX), K0, Y1",
		"VBROADCASTI32X4.Z (AX), Y1",
		"VBROADCASTI32X4.BCST (AX), Y1",
		"VBROADCASTI32X4 (AX), K1, K2, Y1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			requireX86GoAssemblerResult(t, "amd64", "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n", false)
			assertX86PackedBlockBroadcastRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"VBROADCASTF128 (AX), Y16",
		"VBROADCASTI128 (AX), Y16",
		"VBROADCASTI32X2 X20, Z8",
		"VBROADCASTI32X4 (AX), Z20",
	} {
		requireX86GoAssemblerResult(t, "386", "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n", false)
		assertX86PackedBlockBroadcastRejected(t, "386", "i386-unknown-linux-gnu", instruction)
	}
}

func assertX86PackedBlockBroadcastRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's packed-block broadcast forms", instruction)
	}
}

func TestAMD64LegacyBlockBroadcastRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := `
TEXT legacyblockbroadcast(SB),$0-16
	MOVQ out+0(FP), AX
	MOVQ source+8(FP), BX
	VBROADCASTF128 (BX), Y0
	VMOVDQU Y0, 0(AX)
	VBROADCASTI128 (BX), Y1
	VMOVDQU Y1, 32(AX)
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
			"legacyblockbroadcast": {Name: "legacyblockbroadcast", Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
#include <string.h>
extern void legacyblockbroadcast(uint8_t *, const uint8_t *);
int main(void) {
  const uint8_t source[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  uint8_t out[64] = {0};
  legacyblockbroadcast(out, source);
  for (int block = 0; block < 2; block++) {
    if (memcmp(out + 32*block, source, 16) || memcmp(out + 32*block + 16, source, 16)) return block + 1;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "legacy_block_broadcast", triple, ll, mainC, runPrefix)
}
