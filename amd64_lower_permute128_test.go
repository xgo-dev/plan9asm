package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86Permute128CompleteGoAssemblerForms(t *testing.T) {
	const source = `TEXT permute128forms(SB),$0-0
	VPERM2F128 $0, Y0, Y1, Y2
	VPERM2F128 $255, 8(AX), Y15, Y15
	VPERM2I128 $0, Y0, Y1, Y2
	VPERM2I128 $255, 8(AX), Y15, Y15
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
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"permute128forms": {Name: "permute128forms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "permute-128-"+target.name+".ll", "permute-128-"+target.name+".o", ll)
		})
	}
	requireX86GoAssemblerResult(t, "386", source, false)
}

func TestTranslateX86Permute128RejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VPERM2F128 $-1, Y0, Y1, Y2",
		"VPERM2F128 $256, Y0, Y1, Y2",
		"VPERM2I128 $-1, Y0, Y1, Y2",
		"VPERM2I128 $256, Y0, Y1, Y2",
		"VPERM2I128 $1, X0, Y1, Y2",
		"VPERM2I128 $1, Y0, 8(AX), Y2",
		"VPERM2I128 $1, Y0, X1, Y2",
		"VPERM2I128 $1, Y0, Y1, X2",
		"VPERM2I128.Z $1, Y0, Y1, Y2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			requireX86GoAssemblerResult(t, "amd64", "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n", false)
			assertX86Permute128Rejected(t, "amd64", "x86_64-unknown-linux-gnu", instruction)
		})
	}
	assertX86Permute128Rejected(t, "386", "i386-unknown-linux-gnu", "VPERM2I128 $1, Y0, Y1, Y2")
}

func assertX86Permute128Rejected(t *testing.T, goarch, triple, instruction string) {
	t.Helper()
	file, err := Parse(ArchAMD64, "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n")
	if err == nil {
		_, err = Translate(file, Options{
			TargetTriple: triple,
			Goarch:       goarch,
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		})
	}
	if err == nil {
		t.Fatalf("Translate accepted %q outside Go 1.27's VPERM2F128/VPERM2I128 table for %s", instruction, goarch)
	}
}

func TestAMD64Permute128RuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT permute128integer(SB),NOSPLIT,$0-24
	MOVQ out+0(FP), AX
	MOVQ first+8(FP), BX
	MOVQ second+16(FP), CX
	VMOVDQU (BX), Y0
	VMOVDQU (CX), Y1
	VPERM2I128 $0x21, Y0, Y1, Y2
	VMOVDQU Y2, (AX)
	VZEROUPPER
	RET
TEXT permute128float(SB),NOSPLIT,$0-24
	MOVQ out+0(FP), AX
	MOVQ first+8(FP), BX
	MOVQ second+16(FP), CX
	VMOVDQU (BX), Y0
	VMOVDQU (CX), Y1
	VPERM2F128 $0x12, Y0, Y1, Y2
	VMOVDQU Y2, (AX)
	VZEROUPPER
	RET
`
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
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"permute128integer": {Name: "permute128integer", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: frame},
			"permute128float":   {Name: "permute128float", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void permute128integer(uint8_t *, const uint8_t *, const uint8_t *);
extern void permute128float(uint8_t *, const uint8_t *, const uint8_t *);
int main(void) {
  uint8_t first[32], second[32], out[32];
  for (int i = 0; i < 32; i++) { first[i] = (uint8_t)i; second[i] = (uint8_t)(100+i); out[i] = 0; }
	permute128integer(out, first, second);
	for (int i = 0; i < 16; i++) if (out[i] != second[i+16]) return 10+i;
	for (int i = 16; i < 32; i++) if (out[i] != first[i-16]) return 50+i;
	permute128float(out, first, second);
	for (int i = 0; i < 16; i++) if (out[i] != first[i]) return 90+i;
	for (int i = 16; i < 32; i++) if (out[i] != second[i]) return 130+i;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "permute_128", triple, ll, mainC, runPrefix)
}
