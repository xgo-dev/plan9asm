package plan9asm

import (
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestAMD64SegmentQueryGrammarIsComplete(t *testing.T) {
	got := make([]string, 0, len(amd64SegmentQuerySpecs))
	for op := range amd64SegmentQuerySpecs {
		got = append(got, string(op))
	}
	sort.Strings(got)
	want := []string{"LARL", "LARQ", "LARW", "LSLL", "LSLQ", "LSLW", "VERR", "VERW"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("segment-query grammar opcodes = %v, want %v", got, want)
	}
	for op, want := range map[Op]amd64SegmentQuerySpec{
		"LARW": {kind: amd64SegmentQueryAccessRights, bits: 16},
		"LARL": {kind: amd64SegmentQueryAccessRights, bits: 32},
		"LARQ": {kind: amd64SegmentQueryAccessRights, bits: 64},
		"LSLW": {kind: amd64SegmentQueryLimit, bits: 16},
		"LSLL": {kind: amd64SegmentQueryLimit, bits: 32},
		"LSLQ": {kind: amd64SegmentQueryLimit, bits: 64},
		"VERR": {kind: amd64SegmentQueryReadable},
		"VERW": {kind: amd64SegmentQueryWritable},
	} {
		if got := amd64SegmentQuerySpecs[op]; got != want {
			t.Errorf("segment-query grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86SegmentQueryCompleteGoAssemblerForms(t *testing.T) {
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
			source := `TEXT segmentqueryforms(SB),$0-0
	LARW AX, DX
	LARW 2(BX), CX
	LARL CX, AX
	LARL 4(BX), DX
	LSLW DX, CX
	LSLW 6(BX), AX
	LSLL AX, DX
	LSLL 8(BX), CX
`
			if target.goarch == "386" {
				source += "\tLARW AX, SP\n\tLARL AX, SP\n\tLSLW AX, SP\n\tLSLL AX, SP\n"
			}
			if target.goarch == "amd64" {
				source += `	LARW R11, R12
	LARW 10(R13), R14
	LARQ R11, R12
	LARQ 12(R13), R14
	LSLW R11, R12
	LSLW 14(R13), R14
	LSLQ R11, R12
	LSLQ 16(R13), R14
`
			}
			source += "\tRET\n"
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"segmentqueryforms": {Name: "segmentqueryforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "segment-query-"+target.name+".ll", "segment-query-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86SegmentQueryRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "LARW $1, AX"},
		{goarch: "amd64", instruction: "LARL AX, (BX)"},
		{goarch: "amd64", instruction: "LSLQ X0, AX"},
		{goarch: "amd64", instruction: "LSLW AX, X0"},
		{goarch: "amd64", instruction: "LARW.Z AX, DX"},
		{goarch: "386", instruction: "LARQ AX, DX"},
		{goarch: "386", instruction: "LSLQ AX, DX"},
		{goarch: "386", instruction: "LARW R11, AX"},
	} {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "$", "", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
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
				t.Fatalf("Translate accepted %q outside Go 1.27's segment-query tables", test.instruction)
			}
		})
	}
}

func TestTranslateX86SegmentValidationCompleteGoAssemblerForms(t *testing.T) {
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
			high := "DI"
			if target.goarch == "amd64" {
				high = "R11"
			}
			source := "TEXT segmentvalidationforms(SB),$0-0\n" +
				"\tVERR AX\n\tVERR (BX)\n\tVERR " + high + "\n" +
				"\tVERW DX\n\tVERW 2(BX)\n\tVERW " + high + "\n\tRET\n"
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"segmentvalidationforms": {Name: "segmentvalidationforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "segment-validation-"+target.name+".ll", "segment-validation-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86SegmentValidationRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VERR $1"},
		{goarch: "amd64", instruction: "VERW X0"},
		{goarch: "amd64", instruction: "VERR AX, DX"},
		{goarch: "amd64", instruction: "VERW.Z AX"},
		{goarch: "386", instruction: "VERR R11"},
		{goarch: "386", instruction: "VERW (R11)"},
	} {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "$", "", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
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
				t.Fatalf("Translate accepted %q outside Go 1.27's segment-validation table", test.instruction)
			}
		})
	}
}

func TestAMD64SegmentQueryRuntimeSemantics(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		// Rosetta advertises amd64 execution but raises SIGILL for LAR/LSL.
		// Object compilation remains covered above; execute the architectural
		// descriptor checks only on native amd64 hardware.
		t.Skip("LAR/LSL runtime semantics require native amd64 hardware")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT segmentquerysemantics(SB),NOSPLIT,$0-16
	MOVQ selector+0(FP), AX
	MOVQ out+8(FP), DI
	MOVQ $0x1122334455667788, CX
	LARQ AX, CX
	MOVQ CX, 0(DI)
	SETEQ 8(DI)
	MOVQ $0x2233445566778899, CX
	XORQ AX, AX
	LARQ AX, CX
	MOVQ CX, 16(DI)
	SETEQ 24(DI)
	MOVQ selector+0(FP), AX
	MOVQ $0x33445566778899aa, DX
	LSLQ AX, DX
	MOVQ DX, 32(DI)
	SETEQ 40(DI)
	MOVQ $0x445566778899aabb, DX
	XORQ AX, AX
	LSLQ AX, DX
	MOVQ DX, 48(DI)
	SETEQ 56(DI)
	MOVQ selector+0(FP), AX
	STC
	VERR AX
	SETEQ 57(DI)
	SETCS 58(DI)
	VERW AX
	SETEQ 59(DI)
	XORQ AX, AX
	VERR AX
	SETEQ 60(DI)
	VERW AX
	SETEQ 61(DI)
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		Goarch: "amd64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"segmentquerysemantics": {
			Name: "segmentquerysemantics", Args: []LLVMType{I64, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: I64, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void segmentquerysemantics(uint64_t, uint8_t *);
static uint64_t load64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
int main(void) {
  uint16_t cs;
  uint8_t out[64] = {0};
  __asm__ volatile ("mov %%cs,%0" : "=r"(cs));
  segmentquerysemantics(cs, out);
  if (out[8] != 1 || out[40] != 1) return 10;
  if (out[24] != 0 || out[56] != 0) return 11;
  if (load64(out + 16) != UINT64_C(0x2233445566778899)) return 12;
  if (load64(out + 48) != UINT64_C(0x445566778899aabb)) return 13;
  if (out[57] != 1 || out[58] != 1) return 14;
  if (out[59] != 0 || out[60] != 0 || out[61] != 0) return 15;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "segment_query_semantics", triple, ir, mainC, nil)
}
