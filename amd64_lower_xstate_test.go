package plan9asm

import (
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestAMD64XStateGrammarIsComplete(t *testing.T) {
	got := make([]string, 0, len(amd64XStateSpecs))
	for op := range amd64XStateSpecs {
		got = append(got, string(op))
	}
	sort.Strings(got)
	want := []string{
		"FXRSTOR", "FXRSTOR64", "FXSAVE", "FXSAVE64",
		"XRSTOR", "XRSTOR64", "XRSTORS", "XRSTORS64",
		"XSAVE", "XSAVE64", "XSAVEC", "XSAVEC64", "XSAVEOPT", "XSAVEOPT64", "XSAVES", "XSAVES64",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("xstate grammar opcodes = %v, want %v", got, want)
	}
	for op, want := range map[Op]amd64XStateSpec{
		"FXSAVE":     {family: amd64XStateFX, direction: amd64XStateSave, memoryBytes: 512},
		"FXSAVE64":   {family: amd64XStateFX, direction: amd64XStateSave, mode64: true, memoryBytes: 512},
		"FXRSTOR":    {family: amd64XStateFX, direction: amd64XStateRestore, memoryBytes: 512},
		"FXRSTOR64":  {family: amd64XStateFX, direction: amd64XStateRestore, mode64: true, memoryBytes: 512},
		"XSAVE":      {family: amd64XStateXSAVE, direction: amd64XStateSave, implicitMask: true, memoryBytes: 1},
		"XSAVE64":    {family: amd64XStateXSAVE, direction: amd64XStateSave, mode64: true, implicitMask: true, memoryBytes: 1},
		"XSAVEOPT":   {family: amd64XStateXSAVEOPT, direction: amd64XStateSave, implicitMask: true, memoryBytes: 1},
		"XSAVEOPT64": {family: amd64XStateXSAVEOPT, direction: amd64XStateSave, mode64: true, implicitMask: true, memoryBytes: 1},
		"XSAVEC":     {family: amd64XStateXSAVEC, direction: amd64XStateSave, implicitMask: true, memoryBytes: 1},
		"XSAVEC64":   {family: amd64XStateXSAVEC, direction: amd64XStateSave, mode64: true, implicitMask: true, memoryBytes: 1},
		"XSAVES":     {family: amd64XStateXSAVES, direction: amd64XStateSave, implicitMask: true, memoryBytes: 1},
		"XSAVES64":   {family: amd64XStateXSAVES, direction: amd64XStateSave, mode64: true, implicitMask: true, memoryBytes: 1},
		"XRSTOR":     {family: amd64XStateXRSTOR, direction: amd64XStateRestore, implicitMask: true, memoryBytes: 1},
		"XRSTOR64":   {family: amd64XStateXRSTOR, direction: amd64XStateRestore, mode64: true, implicitMask: true, memoryBytes: 1},
		"XRSTORS":    {family: amd64XStateXRSTORS, direction: amd64XStateRestore, implicitMask: true, memoryBytes: 1},
		"XRSTORS64":  {family: amd64XStateXRSTORS, direction: amd64XStateRestore, mode64: true, implicitMask: true, memoryBytes: 1},
	} {
		if got := amd64XStateSpecs[op]; got != want {
			t.Errorf("xstate grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86XStateCompleteGoAssemblerForms(t *testing.T) {
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
			source := `TEXT xstateforms(SB),$0-0
	FXSAVE (BX)
	FXRSTOR 8(BP)
	XSAVE 16(SI)
	XRSTOR 24(DI)
	XSAVEOPT 32(BX)
	XSAVEC 40(BP)
	XSAVES 48(SI)
	XRSTORS 56(DI)
`
			if target.goarch == "amd64" {
				source += `	FXSAVE64 64(R11)
	FXRSTOR64 72(R12)
	XSAVE64 80(R13)
	XRSTOR64 88(R14)
	XSAVEOPT64 96(R15)
	XSAVEC64 104(R11)
	XSAVES64 112(R12)
	XRSTORS64 120(R13)
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
				Sigs: map[string]FuncSig{"xstateforms": {Name: "xstateforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"fxsave", "fxrstor", "xsave", "xrstor", "xsaveopt", "xsavec", "xsaves", "xrstors"} {
				if !strings.Contains(ir, want+" $0") {
					t.Errorf("IR is missing %s:\n%s", want, ir)
				}
			}
			if want := `"target-features"="+fxsr,+xsave,+xsavec,+xsaveopt,+xsaves"`; !strings.Contains(ir, want) {
				t.Errorf("IR is missing complete xstate feature set %s:\n%s", want, ir)
			}
			compileLLVMToObject(t, llc, target.triple, "xstate-"+target.name+".ll", "xstate-"+target.name+".o", ir)
		})
	}
}

func TestAMD64FXStateRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT fxstatesemantics(SB),NOSPLIT,$0-8
	MOVQ area+0(FP), DI
	FXSAVE (DI)
	FXRSTOR (DI)
	FXSAVE64 512(DI)
	FXRSTOR64 512(DI)
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
		Sigs: map[string]FuncSig{"fxstatesemantics": {
			Name: "fxstatesemantics", Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void fxstatesemantics(uint8_t *);
int main(void) {
  __attribute__((aligned(16))) uint8_t area[1024];
  memset(area, 0xa5, sizeof(area));
  fxstatesemantics(area);
  uint16_t control0 = 0, control1 = 0;
  memcpy(&control0, area, sizeof(control0));
  memcpy(&control1, area + 512, sizeof(control1));
  if (control0 == UINT16_C(0xa5a5)) return 10;
  if (control1 == UINT16_C(0xa5a5)) return 11;
  if (control0 != control1) return 12;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "fxstate_semantics", triple, ir, mainC, runPrefix)
}

func TestTranslateX86XStateRejectsFormsOutsideGoTables(t *testing.T) {
	tests := []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "FXSAVE AX"},
		{goarch: "amd64", instruction: "FXRSTOR $1"},
		{goarch: "amd64", instruction: "XSAVE"},
		{goarch: "amd64", instruction: "XRSTOR (BX), (CX)"},
		{goarch: "amd64", instruction: "XSAVEOPT.Z (BX)"},
		{goarch: "amd64", instruction: "XSAVEC X0"},
		{goarch: "amd64", instruction: "XSAVES AX"},
		{goarch: "amd64", instruction: "XRSTORS $1"},
		{goarch: "386", instruction: "XSAVE (R11)"},
	}
	for _, op := range []string{"FXSAVE64", "FXRSTOR64", "XSAVE64", "XRSTOR64", "XSAVEOPT64", "XSAVEC64", "XSAVES64", "XRSTORS64"} {
		tests = append(tests, struct {
			goarch      string
			instruction string
		}{goarch: "386", instruction: op + " (BX)"})
	}
	for _, test := range tests {
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
				t.Fatalf("Translate accepted %q outside Go 1.27's xstate tables", test.instruction)
			}
		})
	}
}
