package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86SizedNOPCompleteFormsSource(goarch string) string {
	var source strings.Builder
	source.WriteString("DATA nopdata+0(SB)/8, $1\n")
	source.WriteString("GLOBL nopdata(SB), $8\n")
	source.WriteString("TEXT sizednopforms(SB),$0-0\n")
	for _, op := range []string{"NOPW", "NOPL"} {
		fmt.Fprintf(&source, "\t%s AX\n", op)
		fmt.Fprintf(&source, "\t%s SP\n", op)
		fmt.Fprintf(&source, "\t%s 8(BX)\n", op)
		fmt.Fprintf(&source, "\t%s nopdata(SB)\n", op)
		if goarch == "amd64" {
			fmt.Fprintf(&source, "\t%s R11\n", op)
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateX86SizedNOPCompleteGo127FormsAcrossTargets(t *testing.T) {
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
			source := x86SizedNOPCompleteFormsSource(target.goarch)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"sizednopforms": {Name: "sizednopforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "sized-nop-"+target.name+".ll", "sized-nop-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86SizedNOPRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "NOPW"},
		{goarch: "amd64", instruction: "NOPL $1"},
		{goarch: "amd64", instruction: "NOPW X0"},
		{goarch: "amd64", instruction: "NOPL AX, BX"},
		{goarch: "amd64", instruction: "NOPL.Z AX"},
		{goarch: "386", instruction: "NOPW R8"},
	} {
		t.Run(test.goarch+"/"+strings.NewReplacer(" ", "_", ",", "").Replace(test.instruction), func(t *testing.T) {
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
				t.Fatalf("Translate accepted %q outside Go 1.27's NOPW/NOPL ydivl table", test.instruction)
			}
		})
	}
}

func TestAMD64SizedNOPRuntimePreservesState(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT sizednopsemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	MOVQ $0x123456789abcdef, AX
	MOVL $0x7fffffff, R8
	ADDL $1, R8
	STC
	NOPW AX
	NOPL 4096(DI)
	MOVQ AX, 0(DI)
	SETCS 8(DI)
	SETOS 9(DI)
	SETEQ 10(DI)
	SETMI 11(DI)
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
		Goarch:       "amd64",
		TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"sizednopsemantics": {
				Name: "sizednopsemantics", Args: []LLVMType{Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void sizednopsemantics(uint8_t *);
int main(void) {
  uint8_t out[16] = {0};
  sizednopsemantics(out);
  uint64_t value;
  memcpy(&value, out, sizeof(value));
  if (value != UINT64_C(0x123456789abcdef)) return 10;
  if (out[8] != 1 || out[9] != 1 || out[10] != 0 || out[11] != 1) return 11;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "sized_nop_semantics", triple, ir, mainC, runPrefix)
}
