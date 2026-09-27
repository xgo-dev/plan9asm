package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64UnalignedLoadGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := map[Op]amd64UnalignedLoadSpec{
		"LDDQU":  {maxBytes: 16},
		"VLDDQU": {maxBytes: 32, vector: true},
	}
	if len(amd64UnalignedLoadSpecs) != len(expected) {
		t.Fatalf("unaligned-load grammar has %d entries, want %d", len(amd64UnalignedLoadSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64UnalignedLoadSpecs[op]; !ok {
			t.Errorf("unaligned-load grammar omitted %s", op)
		} else if got != want {
			t.Errorf("unaligned-load grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86LDDQUCompleteFormsAcrossTargets(t *testing.T) {
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
			last := 15
			if target.goarch == "386" {
				last = 7
			}
			source := fmt.Sprintf(`TEXT lddquforms(SB),$0-0
	LDDQU 1(AX), X%d
	VLDDQU 2(AX), X%d
	VLDDQU 3(AX), Y%d
`, last, last, last)
			if target.goarch == "386" {
				source += "\tVLDDQU 4(R9), Y8\n"
			}
			source += "\tRET\n"
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.goarch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"lddquforms": {Name: "lddquforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"load <16 x i8>", "load <32 x i8>"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("LDDQU/VLDDQU lowering omitted %q:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "lddqu-"+target.name+".ll", "lddqu-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86LDDQURejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "LDDQU X0, X1"},
		{goarch: "amd64", instruction: "LDDQU 0(AX), Y1"},
		{goarch: "amd64", instruction: "VLDDQU X0, X1"},
		{goarch: "amd64", instruction: "VLDDQU 0(AX), Z1"},
		{goarch: "amd64", instruction: "VLDDQU.Z 0(AX), X1"},
		{goarch: "386", instruction: "LDDQU 0(AX), X8"},
		{goarch: "386", instruction: "LDDQU 0(R9), X0"},
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
			if _, err := Translate(file, Options{Goarch: test.goarch, TargetTriple: triple, Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside the Go table for %s", test.instruction, test.goarch)
			}
		})
	}
}

func TestAMD64LDDQURuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT lddqusemantics(SB),$0-16
	MOVQ out+0(FP), AX
	MOVQ in+8(FP), CX
	STC
	LDDQU 1(CX), X0
	MOVUPS X0, 0(AX)
	SETCS 16(AX)
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
		Sigs: map[string]FuncSig{"lddqusemantics": {
			Name: "lddqusemantics", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void lddqusemantics(uint8_t *, const uint8_t *);
int main(void) {
  uint8_t in[17], out[17] = {0};
  for (int i = 0; i < 17; i++) in[i] = (uint8_t)(i * 7 + 3);
  lddqusemantics(out, in);
  for (int i = 0; i < 16; i++) if (out[i] != in[i + 1]) return 10 + i;
  if (out[16] != 1) return 30;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "lddqu_semantics", triple, ir, mainC, runPrefix)
}
