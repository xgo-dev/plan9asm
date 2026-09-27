package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86PackedAlignRightCompleteGoAssemblerForms(t *testing.T) {
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
			last := 15
			if target.goarch == "386" {
				last = 7
			}
			var source strings.Builder
			fmt.Fprintf(&source, "TEXT packedalignrightforms(SB),$0-0\n\tPALIGNR $0, X0, X%d\n\tPALIGNR $255, 8(AX), X%d\n", last, last)
			if target.goarch == "amd64" {
				source.WriteString("\tVPALIGNR $0, X0, X1, X2\n")
				source.WriteString("\tVPALIGNR $1, 8(AX), X1, X2\n")
				source.WriteString("\tVPALIGNR $2, Y0, Y1, Y2\n")
				source.WriteString("\tVPALIGNR $3, 8(AX), Y1, Y2\n")
				source.WriteString("\tVPALIGNR $4, Z0, Z1, Z2\n")
				source.WriteString("\tVPALIGNR $5, 8(AX), Z1, Z2\n")
				source.WriteString("\tVPALIGNR $6, X16, X31, X0\n")
				source.WriteString("\tVPALIGNR $7, X16, X31, K1, X0\n")
				source.WriteString("\tVPALIGNR.Z $8, 16(AX), Y31, K2, Y0\n")
				source.WriteString("\tVPALIGNR $9, Z16, Z31, K3, Z0\n")
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
					"packedalignrightforms": {Name: "packedalignrightforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-align-right-"+target.name+".ll", "packed-align-right-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedAlignRightRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PALIGNR $-1, X0, X1",
		"PALIGNR $256, X0, X1",
		"PALIGNR $1, M0, M1",
		"PALIGNR $1, X16, X1",
		"PALIGNR $1, Y0, Y1",
		"PALIGNR.Z $1, X0, X1",
		"PALIGNR $1, X0, (AX)",
		"VPALIGNR $-1, X0, X1, X2",
		"VPALIGNR $256, X0, X1, X2",
		"VPALIGNR $1, X0, Y1, Y2",
		"VPALIGNR $1, X0, X1, K0, X2",
		"VPALIGNR.Z $1, X0, X1, X2",
		"VPALIGNR.BCST $1, X0, X1, X2",
		"VPALIGNR $1, X0, (AX), X2",
		"VPALIGNR $1, X0, X1, (AX)",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedAlignRightRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"PALIGNR $1, X8, X0",
		"PALIGNR $1, X0, X8",
		"VPALIGNR $1, X0, X1, X2",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedAlignRightRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86PackedAlignRightRejected(t *testing.T, goarch, triple, instruction string) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
	if err == nil {
		_, err = Translate(file, Options{
			TargetTriple: triple,
			Goarch:       goarch,
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		})
	}
	if err == nil {
		t.Fatalf("Translate accepted %q outside Go 1.27's PALIGNR/VPALIGNR tables for %s", instruction, goarch)
	}
}

func TestAMD64PackedAlignRightRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := `
TEXT alignrightlegacy(SB),NOSPLIT,$0-24
	MOVQ out+0(FP), AX
	MOVQ low+8(FP), BX
	MOVQ high+16(FP), CX
	MOVOU (CX), X0
	PALIGNR $8, (BX), X0
	MOVOU X0, (AX)
	RET
TEXT alignrightvector(SB),NOSPLIT,$0-24
	MOVQ out+0(FP), AX
	MOVQ low+8(FP), BX
	MOVQ high+16(FP), CX
	VMOVDQU (BX), Y0
	VMOVDQU (CX), Y1
	VPALIGNR $8, Y0, Y1, Y2
	VMOVDQU Y2, (AX)
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
			"alignrightlegacy": {Name: "alignrightlegacy", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: frame},
			"alignrightvector": {Name: "alignrightvector", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
extern void alignrightlegacy(uint8_t *, const uint8_t *, const uint8_t *);
extern void alignrightvector(uint8_t *, const uint8_t *, const uint8_t *);
int main(void) {
  uint8_t low[32], high[32], out[32];
  for (int i = 0; i < 32; i++) { low[i] = (uint8_t)i; high[i] = (uint8_t)(100+i); out[i] = 0; }
  alignrightlegacy(out, low, high);
  for (int i = 0; i < 8; i++) if (out[i] != low[i+8]) return 10+i;
  for (int i = 8; i < 16; i++) if (out[i] != high[i-8]) return 30+i;
  for (int i = 0; i < 32; i++) out[i] = 0;
  alignrightvector(out, low, high);
  for (int lane = 0; lane < 2; lane++) {
    int base = lane*16;
    for (int i = 0; i < 8; i++) if (out[base+i] != low[base+i+8]) return 60+base+i;
    for (int i = 8; i < 16; i++) if (out[base+i] != high[base+i-8]) return 100+base+i;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_align_right", triple, ll, mainC, runPrefix)
}
