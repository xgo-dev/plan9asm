package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

var x87ConditionalMoveGo127Ops = []string{
	"FCMOVCC", "FCMOVCS", "FCMOVEQ", "FCMOVHI", "FCMOVLS",
	"FCMOVB", "FCMOVBE", "FCMOVNB", "FCMOVNBE", "FCMOVE",
	"FCMOVNE", "FCMOVNU", "FCMOVU", "FCMOVUN",
}

func x86X87ConditionalMoveCompleteFormsSource() string {
	var source strings.Builder
	source.WriteString("TEXT x87conditionalmoveforms(SB),$0-0\n")
	for _, op := range x87ConditionalMoveGo127Ops {
		source.WriteString("\t" + op + " F0, F0\n")
		source.WriteString("\t" + op + " F7, F0\n")
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateX86X87ConditionalMoveCompleteGo127FormsAcrossTargets(t *testing.T) {
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
			source := x86X87ConditionalMoveCompleteFormsSource()
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"x87conditionalmoveforms": {Name: "x87conditionalmoveforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"select i1", "or i1", "and i1", "xor i1"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("x87 conditional-move lowering omitted %q:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "x87-conditional-move-"+target.name+".ll", "x87-conditional-move-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86X87ConditionalMoveRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, instruction := range []string{
		"FCMOVB 0(AX), F0",
		"FCMOVBE F8, F0",
		"FCMOVE F1, F2",
		"FCMOVNB F1",
		"FCMOVNBE F1, F0, F2",
		"FCMOVU.Z F1, F0",
	} {
		for _, goarch := range []string{"amd64", "386"} {
			t.Run(goarch+"/"+strings.NewReplacer(" ", "_", ",", "").Replace(instruction), func(t *testing.T) {
				source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
				requireX86GoAssemblerResult(t, goarch, source, false)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					return
				}
				triple := "x86_64-unknown-linux-gnu"
				if goarch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				if _, err := Translate(file, Options{
					Goarch:       goarch,
					TargetTriple: triple,
					Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
				}); err == nil {
					t.Fatalf("Translate accepted %q outside Go 1.27's yfcmv table", instruction)
				}
			})
		}
	}
}

func TestAMD64X87ConditionalMoveRuntimeConditions(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT x87conditionalmovesemantics(SB),NOSPLIT,$0-8
	MOVQ data+0(FP), DI

	FINIT
	FMOVD 64(DI), F0
	FMOVD 72(DI), F0
	STC
	FCMOVB F1, F0
	FMOVDP F0, 0(DI)
	FINIT
	FMOVD 64(DI), F0
	FMOVD 72(DI), F0
	STC
	FCMOVNB F1, F0
	FMOVDP F0, 8(DI)

	FINIT
	FMOVD 64(DI), F0
	FMOVD 72(DI), F0
	XORL AX, AX
	FCMOVE F1, F0
	FMOVDP F0, 16(DI)
	FINIT
	FMOVD 64(DI), F0
	FMOVD 72(DI), F0
	XORL AX, AX
	FCMOVNE F1, F0
	FMOVDP F0, 24(DI)

	FINIT
	FMOVD 64(DI), F0
	FMOVD 72(DI), F0
	XORL AX, AX
	FCMOVBE F1, F0
	FMOVDP F0, 32(DI)
	FINIT
	FMOVD 64(DI), F0
	FMOVD 72(DI), F0
	XORL AX, AX
	FCMOVNBE F1, F0
	FMOVDP F0, 40(DI)

	FINIT
	FMOVD 64(DI), F0
	FMOVD 72(DI), F0
	XORL AX, AX
	FCMOVU F1, F0
	FMOVDP F0, 48(DI)
	FINIT
	FMOVD 64(DI), F0
	FMOVD 72(DI), F0
	XORL AX, AX
	FCMOVNU F1, F0
	FMOVDP F0, 56(DI)
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
			"x87conditionalmovesemantics": {
				Name: "x87conditionalmovesemantics", Args: []LLVMType{Ptr}, Ret: Void,
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
extern void x87conditionalmovesemantics(uint8_t *);
int main(void) {
  double data[10] = {0};
  data[8] = 1.25;
  data[9] = 9.5;
  x87conditionalmovesemantics((uint8_t *)data);
  const double expected[8] = {1.25, 9.5, 1.25, 9.5, 1.25, 9.5, 1.25, 9.5};
  for (int i = 0; i < 8; ++i) if (data[i] != expected[i]) return 10+i;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "x87_conditional_move_semantics", triple, ir, mainC, runPrefix)
}
