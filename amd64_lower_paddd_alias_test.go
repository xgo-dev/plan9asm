package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64PackedAddGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := map[Op]amd64PackedAddSpec{
		"PADDB":    {canonical: "PADDB", form: amd64PackedAddLegacyYMM, laneBits: 8, mode: amd64PackedAddWrap},
		"PADDW":    {canonical: "PADDW", form: amd64PackedAddLegacyYMM, laneBits: 16, mode: amd64PackedAddWrap},
		"PADDL":    {canonical: "PADDL", form: amd64PackedAddLegacyYMM, laneBits: 32, mode: amd64PackedAddWrap},
		"PADDD":    {canonical: "PADDL", form: amd64PackedAddLegacyYMM, laneBits: 32, mode: amd64PackedAddWrap},
		"PADDQ":    {canonical: "PADDQ", form: amd64PackedAddLegacyYXM, laneBits: 64, mode: amd64PackedAddWrap},
		"PADDSB":   {canonical: "PADDSB", form: amd64PackedAddLegacyYMM, laneBits: 8, mode: amd64PackedAddSignedSaturating},
		"PADDSW":   {canonical: "PADDSW", form: amd64PackedAddLegacyYMM, laneBits: 16, mode: amd64PackedAddSignedSaturating},
		"PADDUSB":  {canonical: "PADDUSB", form: amd64PackedAddLegacyYMM, laneBits: 8, mode: amd64PackedAddUnsignedSaturating},
		"PADDUSW":  {canonical: "PADDUSW", form: amd64PackedAddLegacyYMM, laneBits: 16, mode: amd64PackedAddUnsignedSaturating},
		"VPADDB":   {canonical: "VPADDB", form: amd64PackedAddVEXEVEX, laneBits: 8, mode: amd64PackedAddWrap},
		"VPADDW":   {canonical: "VPADDW", form: amd64PackedAddVEXEVEX, laneBits: 16, mode: amd64PackedAddWrap},
		"VPADDD":   {canonical: "VPADDD", form: amd64PackedAddVEXEVEX, laneBits: 32, mode: amd64PackedAddWrap, allowBroadcast: true},
		"VPADDQ":   {canonical: "VPADDQ", form: amd64PackedAddVEXEVEX, laneBits: 64, mode: amd64PackedAddWrap, allowBroadcast: true},
		"VPADDSB":  {canonical: "VPADDSB", form: amd64PackedAddVEXEVEX, laneBits: 8, mode: amd64PackedAddSignedSaturating},
		"VPADDSW":  {canonical: "VPADDSW", form: amd64PackedAddVEXEVEX, laneBits: 16, mode: amd64PackedAddSignedSaturating},
		"VPADDUSB": {canonical: "VPADDUSB", form: amd64PackedAddVEXEVEX, laneBits: 8, mode: amd64PackedAddUnsignedSaturating},
		"VPADDUSW": {canonical: "VPADDUSW", form: amd64PackedAddVEXEVEX, laneBits: 16, mode: amd64PackedAddUnsignedSaturating},
	}
	if len(amd64PackedAddSpecs) != len(expected) {
		t.Fatalf("packed-add grammar has %d entries, want %d", len(amd64PackedAddSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64PackedAddSpecs[op]; !ok {
			t.Errorf("packed-add grammar omitted %s", op)
		} else if got != want {
			t.Errorf("packed-add grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86PADDDGoAliasCompleteFormsAcrossTargets(t *testing.T) {
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
			source.WriteString("TEXT padddaliasforms(SB),$0-0\n")
			for _, op := range []string{"PADDL", "PADDD"} {
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
				Sigs:         map[string]FuncSig{"padddaliasforms": {Name: "padddaliasforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "add <4 x i32>") {
				t.Fatalf("PADDL/PADDD lowering omitted dword addition:\n%s", ir)
			}
			if target.goarch == "amd64" && !strings.Contains(ir, "bitcast i64") {
				t.Fatalf("PADDL/PADDD lowering omitted MMX forms:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "paddd-alias-"+target.name+".ll", "paddd-alias-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86PADDDGoAliasRejectsFormsOutsidePADDLTable(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "PADDD M0, X1"},
		{goarch: "amd64", instruction: "PADDD X0, M1"},
		{goarch: "amd64", instruction: "PADDD Y0, Y1"},
		{goarch: "amd64", instruction: "PADDD.Z X0, X1"},
		{goarch: "386", instruction: "PADDD M0, M1"},
		{goarch: "386", instruction: "PADDL M0, M1"},
		{goarch: "386", instruction: "PADDD X0, X8"},
		{goarch: "386", instruction: "PADDD 8(R9), X0"},
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
				t.Fatalf("Translate accepted %q outside PADDD/PADDL's Go table for %s", test.instruction, test.goarch)
			}
		})
	}
}

func TestAMD64PADDDGoAliasRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT padddaliassemantics(SB),$0-24
	MOVQ out+0(FP), AX
	MOVQ a+8(FP), M0
	MOVQ b+16(FP), M1
	STC
	PADDD M0, M1
	MOVQ M1, 0(AX)
	SETCS 8(AX)
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
			"padddaliassemantics": {
				Name: "padddaliassemantics", Args: []LLVMType{Ptr, I64, I64}, Ret: Void,
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
extern void padddaliassemantics(uint8_t *, uint64_t, uint64_t);
int main(void) {
  uint8_t out[9] = {0};
  uint64_t a = UINT64_C(0xffffffff00000002);
  uint64_t b = UINT64_C(0x0000000200000003);
  padddaliassemantics(out, a, b);
  uint64_t got;
  memcpy(&got, out, 8);
  if (got != UINT64_C(0x0000000100000005)) return 10;
  if (out[8] != 1) return 11;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "paddd_alias_semantics", triple, ir, mainC, runPrefix)
}
