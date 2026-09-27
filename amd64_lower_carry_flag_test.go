package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86CarryFlagControlCompleteGoAssemblerForms(t *testing.T) {
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
			file, err := Parse(ArchAMD64, "TEXT carryflagforms(SB),NOSPLIT,$0-0\n\tCLC\n\tSTC\n\tCMC\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs:         map[string]FuncSig{"carryflagforms": {Name: "carryflagforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"store i1 false, ptr %flags_cf", "store i1 true, ptr %flags_cf", "xor i1"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("carry flag lowering missing %q:\n%s", want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "carry-flag-"+target.name+".ll", "carry-flag-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86CarryFlagControlRejectsOperands(t *testing.T) {
	for _, instruction := range []string{"CLC AX", "STC $1", "CMC 0(BX)", "CLC.Z"} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err == nil {
				_, err = Translate(file, Options{
					TargetTriple: "x86_64-unknown-linux-gnu",
					Goarch:       "amd64",
					Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
				})
			}
			if err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's carry-control ynone table", instruction)
			}
		})
	}
}

func TestAMD64CarryFlagControlRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := `
TEXT carryflagsemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	CLC
	MOVQ $0, AX
	ADCQ $0, AX
	MOVQ AX, 0(DI)
	STC
	MOVQ $0, AX
	ADCQ $0, AX
	MOVQ AX, 8(DI)
	CLC
	CMC
	MOVQ $0, AX
	ADCQ $0, AX
	MOVQ AX, 16(DI)
	STC
	CMC
	MOVQ $0, AX
	ADCQ $0, AX
	MOVQ AX, 24(DI)
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	frame := FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"carryflagsemantics": {Name: "carryflagsemantics", Args: []LLVMType{Ptr}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
extern void carryflagsemantics(uint64_t *);
int main(void) {
  uint64_t out[4] = {9, 9, 9, 9};
  const uint64_t want[4] = {0, 1, 1, 0};
  carryflagsemantics(out);
  for (int i = 0; i < 4; i++) if (out[i] != want[i]) return 10+i;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "carry_flag_semantics", triple, ll, mainC, runPrefix)
}
