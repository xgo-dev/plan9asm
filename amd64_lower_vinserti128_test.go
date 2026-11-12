package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86VINSERTI128CompleteGo127Forms(t *testing.T) {
	const source = `TEXT vinserti128_forms(SB),$0-0
	VINSERTI128 $0, X0, Y1, Y2
	VINSERTI128 $255, 8(BX), Y15, Y15
	VINSERTI128 $1, X15, Y0, Y1
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "darwin-amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", triple: "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch:       "amd64",
				TargetTriple: target.triple,
				Sigs: map[string]FuncSig{
					"vinserti128_forms": {Name: "vinserti128_forms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "vinserti128-"+target.name+".ll", "vinserti128-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86VINSERTI128RejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"VINSERTI128 X0, Y1, Y2",
		"VINSERTI128 $0, X0, Y1",
		"VINSERTI128 $-1, X0, Y1, Y2",
		"VINSERTI128 $256, X0, Y1, Y2",
		"VINSERTI128 AX, X0, Y1, Y2",
		"VINSERTI128 $0, Y0, Y1, Y2",
		"VINSERTI128 $0, X16, Y1, Y2",
		"VINSERTI128 $0, X0, X1, Y2",
		"VINSERTI128 $0, X0, Y16, Y2",
		"VINSERTI128 $0, X0, Y1, X2",
		"VINSERTI128 $0, X0, Y1, Y16",
		"VINSERTI128 $0, X0, Y1, 8(BX)",
		"VINSERTI128.Z $0, X0, Y1, Y2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, "amd64", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				Goarch:       "amd64",
				TargetTriple: "x86_64-unknown-linux-gnu",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's VINSERTI128 table", instruction)
			}
		})
	}
	const source386 = "TEXT bad(SB),$0-0\n\tVINSERTI128 $0, X0, Y1, Y2\n\tRET\n"
	requireX86GoAssemblerResult(t, "386", source386, false)
	file, err := Parse(ArchAMD64, source386)
	if err == nil {
		if _, err := Translate(file, Options{
			Goarch:       "386",
			TargetTriple: "i386-unknown-linux-gnu",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatal("Translate accepted 386 VINSERTI128 despite Go 1.27's frontend operand limit")
		}
	}
}

func TestAMD64VINSERTI128RuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT vinserti128Semantics(SB),$0-24
	MOVQ out+0(FP), AX
	MOVQ narrow+8(FP), BX
	MOVQ wide+16(FP), CX
	VMOVDQU64 (BX), X0
	VMOVDQU64 (CX), Y1
	VINSERTI128 $0, X0, Y1, Y2
	VMOVDQU64 Y2, 0(AX)
	VINSERTI128 $255, X0, Y1, Y3
	VMOVDQU64 Y3, 32(AX)
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	frame := FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: Ptr, Index: 1, Field: -1},
		{Offset: 16, Type: Ptr, Index: 2, Field: -1},
	}}
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
			"vinserti128Semantics": {
				Name:  "vinserti128Semantics",
				Args:  []LLVMType{Ptr, Ptr, Ptr},
				Ret:   Void,
				Frame: frame,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void vinserti128Semantics(uint64_t *, const uint64_t *, const uint64_t *);
int main(void) {
  const uint64_t narrow[2] = {10, 11};
  const uint64_t wide[4] = {20, 21, 22, 23};
  uint64_t out[8] = {0};
  const uint64_t want[8] = {10, 11, 22, 23, 20, 21, 10, 11};
  vinserti128Semantics(out, narrow, wide);
  for (int i = 0; i < 8; i++) if (out[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "vinserti128", triple, ir, mainC, runPrefix)
}
