package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64MoveHalfGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := map[Op]amd64MoveHalfSpec{
		"MOVLPS":  {},
		"MOVHPS":  {high: true},
		"MOVLPD":  {},
		"MOVHPD":  {high: true},
		"VMOVLPS": {vector: true},
		"VMOVHPS": {high: true, vector: true},
		"VMOVLPD": {vector: true},
		"VMOVHPD": {high: true, vector: true},
	}
	if len(amd64MoveHalfSpecs) != len(expected) {
		t.Fatalf("move-half grammar has %d entries, want %d", len(amd64MoveHalfSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64MoveHalfSpecs[op]; !ok {
			t.Errorf("move-half grammar omitted %s", op)
		} else if got != want {
			t.Errorf("move-half grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86VEXMoveHalfCompleteFormsAcrossTargets(t *testing.T) {
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
			base, last := 30, 31
			if target.goarch == "386" {
				base, last = 6, 7
			}
			var source strings.Builder
			source.WriteString("TEXT vmovhalfforms(SB),$0-0\n")
			for _, op := range []string{"VMOVLPS", "VMOVHPS", "VMOVLPD", "VMOVHPD"} {
				fmt.Fprintf(&source, "\t%s X%d, 0(AX)\n", op, last)
				fmt.Fprintf(&source, "\t%s 8(AX), X%d, X%d\n", op, base, last)
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.goarch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"vmovhalfforms": {Name: "vmovhalfforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "extractelement <2 x i64>") || !strings.Contains(ir, "insertelement <2 x i64>") {
				t.Fatalf("VEX half-move lowering omitted lane operations:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "vmov-half-"+target.name+".ll", "vmov-half-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86VEXMoveHalfRejectsFormsOutsideGoTable(t *testing.T) {
	for _, instruction := range []string{
		"VMOVHPS.Z 0(AX), X1, X2",
		"VMOVLPS Y0, 0(AX)",
		"VMOVHPD 0(AX), Y1, Y2",
		"VMOVLPD X0, X1, X2",
		"VMOVHPS 0(AX), X1",
		"VMOVLPS X0, X1",
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, "amd64", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's _yvmovhpd table", instruction)
			}
		})
	}
}

func TestAMD64VEXMoveHalfRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT vmovhalfsemantics(SB),$0-24
	MOVQ out+0(FP), AX
	MOVQ base+8(FP), CX
	MOVQ half+16(FP), DX
	MOVUPS 0(CX), X1
	STC
	VMOVHPS 0(DX), X1, X2
	MOVUPS X2, 0(AX)
	VMOVLPS 0(DX), X1, X3
	MOVUPS X3, 16(AX)
	SETCS 32(AX)
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
		Sigs: map[string]FuncSig{"vmovhalfsemantics": {
			Name: "vmovhalfsemantics", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void vmovhalfsemantics(uint8_t *, const uint64_t *, const uint64_t *);
int main(void) {
  uint8_t out[33] = {0};
  const uint64_t base[2] = {UINT64_C(0x1111222233334444), UINT64_C(0x5555666677778888)};
  const uint64_t half[1] = {UINT64_C(0xaaaabbbbccccdddd)};
  uint64_t got[4];
  vmovhalfsemantics(out, base, half);
  memcpy(got, out, 32);
  if (got[0] != base[0] || got[1] != half[0]) return 10;
  if (got[2] != half[0] || got[3] != base[1]) return 11;
  if (out[32] != 1) return 12;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "vex_move_half_semantics", triple, ir, mainC, runPrefix)
}
