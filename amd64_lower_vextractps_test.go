package plan9asm

import (
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestAMD64PackedScalarExtractGrammarIsComplete(t *testing.T) {
	got := make([]string, 0, len(amd64PackedScalarExtractSpecs))
	for op := range amd64PackedScalarExtractSpecs {
		got = append(got, string(op))
	}
	sort.Strings(got)
	want := []string{
		"EXTRACTPS", "PEXTRB", "PEXTRD", "PEXTRQ", "PEXTRW",
		"VEXTRACTPS", "VPEXTRB", "VPEXTRD", "VPEXTRQ", "VPEXTRW",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packed scalar-extract grammar opcodes = %v, want %v", got, want)
	}
}

func TestTranslateX86ExtractPSCompleteGo127Forms(t *testing.T) {
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
			highX, highGP := "X15", "R15"
			if target.goarch == "386" {
				highX, highGP = "X7", "DI"
			}
			source := "TEXT extractpsforms(SB),$0-0\n" +
				"\tEXTRACTPS $0, X0, AX\n" +
				"\tEXTRACTPS $3, " + highX + ", (BX)\n" +
				"\tEXTRACTPS $2, " + highX + ", " + highGP + "\n" +
				"\tVEXTRACTPS $-128, X0, AX\n" +
				"\tVPEXTRQ $0, X0, (BX)\n" +
				"\tRET\n"
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"extractpsforms": {Name: "extractpsforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "extractps-"+target.name+".ll", "extractps-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86ExtractPSRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "EXTRACTPS $-1, X0, AX"},
		{goarch: "amd64", instruction: "EXTRACTPS $4, X0, AX"},
		{goarch: "amd64", instruction: "EXTRACTPS $0, X16, AX"},
		{goarch: "amd64", instruction: "EXTRACTPS $0, X0, M0"},
		{goarch: "386", instruction: "EXTRACTPS $0, X8, AX"},
		{goarch: "386", instruction: "EXTRACTPS $0, X0, R8"},
		{goarch: "386", instruction: "PEXTRQ $0, X0, AX"},
	} {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "$", "").Replace(test.instruction), func(t *testing.T) {
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
				t.Fatalf("Translate accepted %q outside Go 1.27's scalar-extract tables", test.instruction)
			}
		})
	}
}

func TestAMD64ExtractPSRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT extractpssemantics(SB),NOSPLIT,$0-16
	MOVQ in+0(FP), AX
	MOVQ out+8(FP), BX
	MOVUPS (AX), X0
	EXTRACTPS $0, X0, CX
	MOVL CX, 0(BX)
	EXTRACTPS $3, X0, 4(BX)
	VEXTRACTPS $2, X0, DX
	MOVL DX, 8(BX)
	RET
`
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
		Sigs: map[string]FuncSig{"extractpssemantics": {
			Name: "extractpssemantics", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void extractpssemantics(void *, void *);
int main(void) {
  uint32_t in[4] = {0x3f800001,0x40000002,0x40400003,0x40800004}, out[3] = {0};
  extractpssemantics(in, out);
  return out[0] == in[0] && out[1] == in[3] && out[2] == in[2] ? 0 : 10;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "extractps_semantics", triple, ir, mainC, runPrefix)
}

func TestTranslateAMD64VExtractPSCompleteGo127Forms(t *testing.T) {
	const source = `TEXT vextractpsforms(SB),$0-0
	VEXTRACTPS $-128, X0, AX
	VEXTRACTPS $255, X1, (AX)
	VEXTRACTPS $255, X31, R15
	RET
`
	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "darwin-amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", triple: "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			requireX86GoAssemblerResult(t, "amd64", source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"vextractpsforms": {Name: "vextractpsforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "vextractps-"+target.name+".ll", "vextractps-"+target.name+".o", ir)
		})
	}
}

func TestTranslateAMD64VExtractPSRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"VEXTRACTPS $-129, X1, AX",
		"VEXTRACTPS $-1, X31, AX",
		"VEXTRACTPS $256, X1, AX",
		"VEXTRACTPS $1, Y1, AX",
		"VEXTRACTPS $1, X1, X2",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's _yvextractps table", instruction)
			}
		})
	}
}
