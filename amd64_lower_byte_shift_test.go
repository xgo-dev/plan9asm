package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86PackedByteShiftCompleteGoAssemblerForms(t *testing.T) {
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
			legacyLast := 15
			zSource, zDestination := 16, 31
			if target.goarch == "386" {
				legacyLast = 7
				zSource, zDestination = 6, 7
			}
			var source strings.Builder
			source.WriteString("TEXT packedbyteshiftforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{"PSLLO", "PSLLDQ", "PSRLO", "PSRLDQ"} {
				fmt.Fprintf(&source, "\t%s $-128, X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s $127, X%d\n", op, legacyLast)
			}
			for _, op := range []string{"VPSLLDQ", "VPSRLDQ"} {
				source.WriteString("\t" + op + " $-128, X0, X1\n")
				source.WriteString("\t" + op + " $255, Y0, Y1\n")
				source.WriteString("\t" + op + " $1, 8(AX), X2\n")
				source.WriteString("\t" + op + " $2, 16(AX), Y2\n")
				source.WriteString("\t" + op + " $3, X16, X31\n")
				fmt.Fprintf(&source, "\t%s $4, Z%d, Z%d\n", op, zSource, zDestination)
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"packedbyteshiftforms": {Name: "packedbyteshiftforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-byte-shift-"+target.name+".ll", "packed-byte-shift-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedByteShiftRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PSLLO $-129, X0",
		"PSLLDQ $128, X0",
		"PSRLO $1, X16",
		"PSRLDQ $1, Y0",
		"PSLLDQ.Z $1, X0",
		"VPSLLDQ $-129, X0, X1",
		"VPSRLDQ $256, X0, X1",
		"VPSLLDQ $-1, 8(AX), X1",
		"VPSRLDQ $-1, X16, X1",
		"VPSLLDQ $-1, Z0, Z1",
		"VPSRLDQ $1, X0, Y1",
		"VPSLLDQ $1, X0, K1, X1",
		"VPSRLDQ.Z $1, X0, X1",
		"VPSLLDQ $1, X0, (AX)",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedByteShiftRejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	for _, instruction := range []string{
		"PSLLO $1, X8",
		"PSRLO $1, X15",
	} {
		t.Run("386_"+strings.NewReplacer(" ", "_").Replace(instruction), func(t *testing.T) {
			assertX86PackedByteShiftRejected(t, "386", "i386-unknown-linux-gnu", instruction)
		})
	}
}

func assertX86PackedByteShiftRejected(t *testing.T, goarch, triple, instruction string) {
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
		t.Fatalf("Translate accepted %q outside Go 1.27's packed byte-shift tables for %s", instruction, goarch)
	}
}

func TestAMD64PackedByteShiftRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := `
TEXT packedbyteshift(SB),NOSPLIT,$0-16
	MOVQ out+0(FP), AX
	MOVQ in+8(FP), BX
	VMOVDQU (BX), Y0
	VPSLLDQ $3, Y0, Y1
	VMOVDQU Y1, 0(AX)
	VPSRLDQ $5, Y0, Y1
	VMOVDQU Y1, 32(AX)
	VPSLLDQ $-1, Y0, Y1
	VMOVDQU Y1, 64(AX)
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
			"packedbyteshift": {Name: "packedbyteshift", Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
extern void packedbyteshift(uint8_t *, const uint8_t *);
int main(void) {
  uint8_t in[32], out[96];
  for (int i = 0; i < 32; i++) in[i] = (uint8_t)(i+1);
  for (int i = 0; i < 96; i++) out[i] = 0xff;
  packedbyteshift(out, in);
  for (int lane = 0; lane < 2; lane++) for (int i = 0; i < 16; i++) {
    int base = lane*16;
    uint8_t left = i < 3 ? 0 : in[base+i-3];
    uint8_t right = i+5 >= 16 ? 0 : in[base+i+5];
    if (out[base+i] != left) return 10+base+i;
    if (out[32+base+i] != right) return 50+base+i;
    if (out[64+base+i] != 0) return 90+base+i;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_byte_shift", triple, ll, mainC, runPrefix)
}
