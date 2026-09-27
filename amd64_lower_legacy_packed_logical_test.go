package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86LegacyPackedLogicalCompleteGo127FormsAcrossTargets(t *testing.T) {
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
			lastX := 15
			if target.goarch == "386" {
				lastX = 7
			}
			var source strings.Builder
			source.WriteString("TEXT legacypackedlogicalforms(SB),$0-0\n")
			for _, op := range []string{"PAND", "PANDN", "POR", "PXOR"} {
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s M0, M7\n", op)
					fmt.Fprintf(&source, "\t%s 8(AX), M7\n", op)
				}
				fmt.Fprintf(&source, "\t%s X0, X%d\n", op, lastX)
				fmt.Fprintf(&source, "\t%s 16(AX), X%d\n", op, lastX)
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
				Sigs:         map[string]FuncSig{"legacypackedlogicalforms": {Name: "legacypackedlogicalforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			wantIR := []string{"and <16 x i8>", "or <16 x i8>", "xor <16 x i8>"}
			if target.goarch == "amd64" {
				wantIR = append(wantIR, "and i64", "or i64", "xor i64")
			}
			for _, want := range wantIR {
				if !strings.Contains(ir, want) {
					t.Fatalf("legacy packed logical lowering omitted %q:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "legacy-packed-logical-"+target.name+".ll", "legacy-packed-logical-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86LegacyPackedLogicalRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "PAND M0, X1"},
		{goarch: "amd64", instruction: "POR X0, M1"},
		{goarch: "amd64", instruction: "PXOR Y0, Y1"},
		{goarch: "amd64", instruction: "PAND.Z X0, X1"},
		{goarch: "amd64", instruction: "PAND M0"},
		{goarch: "amd64", instruction: "POR M0, M1, M2"},
		{goarch: "386", instruction: "PXOR X0, X8"},
		{goarch: "386", instruction: "PAND 8(R9), X0"},
		{goarch: "386", instruction: "PAND M0, M1"},
		{goarch: "386", instruction: "PANDN M0, M1"},
		{goarch: "386", instruction: "POR M0, M1"},
		{goarch: "386", instruction: "PXOR M0, M1"},
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
				Goarch:       test.goarch,
				TargetTriple: triple,
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's packed logical table for %s", test.instruction, test.goarch)
			}
		})
	}
}

func TestAMD64LegacyPackedLogicalMMXRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT legacypackedlogicalsemantics(SB),$0-24
	MOVQ out+0(FP), AX
	MOVQ a+8(FP), M0
	MOVQ b+16(FP), M1
	STC
	PAND M0, M1
	MOVQ M1, 0(AX)
	MOVQ a+8(FP), M0
	MOVQ b+16(FP), M1
	PANDN M0, M1
	MOVQ M1, 8(AX)
	MOVQ a+8(FP), M0
	MOVQ b+16(FP), M1
	POR M0, M1
	MOVQ M1, 16(AX)
	MOVQ a+8(FP), M0
	MOVQ b+16(FP), M1
	PXOR M0, M1
	MOVQ M1, 24(AX)
	SETCS 32(AX)
	EMMS
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
		Goarch:       "amd64",
		TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"legacypackedlogicalsemantics": {
				Name: "legacypackedlogicalsemantics", Args: []LLVMType{Ptr, I64, I64}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
					{Offset: 16, Type: I64, Index: 2, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void legacypackedlogicalsemantics(uint8_t *, uint64_t, uint64_t);
static uint64_t load64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
int main(void) {
  uint8_t out[33] = {0};
  uint64_t a = UINT64_C(0x0ff00ff0a55aa55a);
  uint64_t b = UINT64_C(0x33cc55aa5aa5f00f);
  legacypackedlogicalsemantics(out, a, b);
  if (load64(out+0) != (a & b)) return 10;
  if (load64(out+8) != ((~b) & a)) return 11;
  if (load64(out+16) != (a | b)) return 12;
  if (load64(out+24) != (a ^ b)) return 13;
  if (out[32] != 1) return 14;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "legacy_packed_logical_semantics", triple, ir, mainC, runPrefix)
}
