package plan9asm

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64StackWidthGrammarIsComplete(t *testing.T) {
	want := map[Op]amd64StackWidthSpec{
		"PUSHW":  {bits: 16, mode: amd64StackPushValue, segments: amd64StackPushSegments},
		"POPW":   {bits: 16, mode: amd64StackPopValue, segments: amd64StackPopSegments},
		"PUSHL":  {bits: 32, mode: amd64StackPushValue, segments: amd64StackPushSegments, segmentNativeWidth: true},
		"POPL":   {bits: 32, mode: amd64StackPopValue, segments: amd64StackPopSegments, segmentNativeWidth: true},
		"PUSHQ":  {bits: 64, mode: amd64StackPushValue, segments: amd64StackLongSegments, segmentNativeWidth: true},
		"POPQ":   {bits: 64, mode: amd64StackPopValue, segments: amd64StackLongSegments, segmentNativeWidth: true},
		"PUSHFW": {bits: 16, mode: amd64StackPushFlags},
		"POPFW":  {bits: 16, mode: amd64StackPopFlags},
		"PUSHFL": {bits: 32, mode: amd64StackPushFlags},
		"POPFL":  {bits: 32, mode: amd64StackPopFlags},
		"PUSHFQ": {bits: 64, mode: amd64StackPushFlags},
		"POPFQ":  {bits: 64, mode: amd64StackPopFlags},
	}
	if !reflect.DeepEqual(amd64StackWidthSpecs, want) {
		t.Fatalf("stack-width grammar = %+v, want %+v", amd64StackWidthSpecs, want)
	}
}

func TestTranslateX86StackWidthCompleteGoAssemblerForms(t *testing.T) {
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
			high := "R11"
			if target.goarch == "386" {
				high = "DX"
			}
			source := "TEXT stackwidthforms(SB),$0-0\n" +
				"\tPUSHW AX\n\tPOPW " + high + "\n" +
				"\tPUSHW $61731\n\tPOPW (BX)\n" +
				"\tPUSHW (BX)\n\tPOPW AX\n" +
				"\tPUSHFW\n\tPOPFW\n"
			if target.goarch == "amd64" {
				source += "\tPUSHQ R11\n\tPOPQ (BX)\n\tPUSHQ FS\n\tPUSHQ GS\n\tPOPQ FS\n\tPOPQ GS\n\tPUSHFQ\n\tPOPFQ\n"
			} else {
				source += "\tPUSHL DX\n\tPOPL (BX)\n\tPUSHFL\n\tPOPFL\n"
			}
			source += "\tRET\n"

			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"stackwidthforms": {Name: "stackwidthforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "stack-width-"+target.name+".ll", "stack-width-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86StackSegmentCompleteGoAssemblerForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	const source = `TEXT stacksegmentforms(SB),$0-0
	PUSHW CS
	PUSHW SS
	PUSHW DS
	PUSHW ES
	PUSHW FS
	PUSHW GS
	POPW SS
	POPW DS
	POPW ES
	POPW FS
	POPW GS
	PUSHL CS
	PUSHL SS
	PUSHL DS
	PUSHL ES
	PUSHL FS
	PUSHL GS
	POPL SS
	POPL DS
	POPL ES
	POPL FS
	POPL GS
	PUSHQ FS
	PUSHQ GS
	POPQ FS
	POPQ GS
	POPW DS
	POPL DS
	RET
`
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
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"stacksegmentforms": {Name: "stacksegmentforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "stack-segment-"+target.name+".ll", "stack-segment-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86StackWidthRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "PUSHW X0"},
		{goarch: "amd64", instruction: "POPW $1"},
		{goarch: "amd64", instruction: "PUSHFW AX"},
		{goarch: "amd64", instruction: "POPQ X0"},
		{goarch: "amd64", instruction: "PUSHL AX"},
		{goarch: "amd64", instruction: "PUSHQ DS"},
		{goarch: "amd64", instruction: "POPQ ES"},
		{goarch: "amd64", instruction: "POPW CS"},
		{goarch: "amd64", instruction: "POPL CS"},
		{goarch: "386", instruction: "PUSHQ AX"},
		{goarch: "386", instruction: "POPW R11"},
		{goarch: "386", instruction: "POPFQ"},
		{goarch: "386", instruction: "PUSHQ DS"},
		{goarch: "386", instruction: "POPQ ES"},
		{goarch: "386", instruction: "POPW CS"},
		{goarch: "386", instruction: "POPL CS"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's stack tables", test.instruction)
			}
		})
	}
}

func TestAMD64StackWidthRuntimeValuesAndFlags(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT stackwidthsemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	MOVW $0x1234, AX
	PUSHW AX
	POPW CX
	MOVW CX, 0(DI)
	MOVW $0x5678, 2(DI)
	PUSHW 2(DI)
	POPW DX
	MOVW DX, 4(DI)
	PUSHW $61731
	POPW 6(DI)
	MOVQ $0x123456789abcdef, AX
	PUSHQ AX
	POPQ 8(DI)
	STC
	PUSHFW
	CLC
	POPFW
	SETCS 16(DI)
	PUSHFQ
	CLC
	POPFQ
	SETCS 17(DI)
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
		Sigs: map[string]FuncSig{"stackwidthsemantics": {
			Name: "stackwidthsemantics", Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void stackwidthsemantics(uint8_t *);
static uint16_t load16(const uint8_t *p) { uint16_t v; memcpy(&v,p,2); return v; }
static uint64_t load64(const uint8_t *p) { uint64_t v; memcpy(&v,p,8); return v; }
int main(void) {
  uint8_t out[24] = {0}; stackwidthsemantics(out);
  if (load16(out) != 0x1234 || load16(out+4) != 0x5678 || load16(out+6) != 61731) return 10;
  if (load64(out+8) != UINT64_C(0x123456789abcdef)) return 11;
  if (out[16] != 1 || out[17] != 1) return 12;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "stack_width_semantics", triple, ir, mainC, runPrefix)
}
