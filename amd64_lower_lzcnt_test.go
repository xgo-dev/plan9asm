package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86LZCNTCompleteFormsSource(goarch string) string {
	var source strings.Builder
	symbol := "lzcntdata"
	size := 8
	if goarch == "386" {
		symbol = "lzcntdata386"
		size = 4
	}
	fmt.Fprintf(&source, "DATA %s+0(SB)/%d, $1\n", symbol, size)
	fmt.Fprintf(&source, "GLOBL %s(SB), $%d\n", symbol, size)
	source.WriteString("TEXT lzcntforms(SB),$0-0\n")
	widths := []string{"W", "L"}
	if goarch == "amd64" {
		widths = append(widths, "Q")
	}
	for _, width := range widths {
		fmt.Fprintf(&source, "\tLZCNT%s AX, BX\n", width)
		fmt.Fprintf(&source, "\tLZCNT%s 8(BX), CX\n", width)
		fmt.Fprintf(&source, "\tLZCNT%s %s(SB), DX\n", width, symbol)
		if goarch == "amd64" {
			fmt.Fprintf(&source, "\tLZCNT%s R11, R12\n", width)
		} else {
			fmt.Fprintf(&source, "\tLZCNT%s AX, SP\n", width)
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateX86LZCNTCompleteGo127FormsAcrossTargets(t *testing.T) {
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
			source := x86LZCNTCompleteFormsSource(target.goarch)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"lzcntforms": {Name: "lzcntforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"@llvm.ctlz.i16", "@llvm.ctlz.i32", `"target-features"="+lzcnt"`} {
				if !strings.Contains(ll, want) {
					t.Fatalf("LZCNT lowering omitted %q:\n%s", want, ll)
				}
			}
			if target.goarch == "amd64" && !strings.Contains(ll, "@llvm.ctlz.i64") {
				t.Fatalf("LZCNTQ lowering omitted llvm.ctlz.i64:\n%s", ll)
			}
			compileLLVMToObject(t, llc, target.triple, "lzcnt-"+target.name+".ll", "lzcnt-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86LZCNTRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "LZCNTW AL, BX"},
		{goarch: "amd64", instruction: "LZCNTL AX, AH"},
		{goarch: "amd64", instruction: "LZCNTQ X0, AX"},
		{goarch: "amd64", instruction: "LZCNTW AX, 0(BX)"},
		{goarch: "amd64", instruction: "LZCNTL $1, AX"},
		{goarch: "amd64", instruction: "LZCNTQ AX"},
		{goarch: "amd64", instruction: "LZCNTW.Z AX, BX"},
		{goarch: "386", instruction: "LZCNTL R8, AX"},
		{goarch: "386", instruction: "LZCNTQ AX, BX"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's LZCNT yml_rl table", test.instruction)
			}
		})
	}
}

func TestAMD64LZCNTRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT lzcntsemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	MOVQ $0x1122334455660000, AX
	MOVQ $0xaabbccddeeff1234, BX
	LZCNTW AX, BX
	MOVQ BX, 0(DI)
	SETCS 8(DI)
	SETEQ 9(DI)
	MOVQ $0x80000000, AX
	MOVQ $0x1122334455667788, CX
	LZCNTL AX, CX
	MOVQ CX, 16(DI)
	SETCS 24(DI)
	SETEQ 25(DI)
	MOVQ $1, 32(DI)
	LZCNTQ 32(DI), DX
	MOVQ DX, 40(DI)
	SETCS 48(DI)
	SETEQ 49(DI)
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
	ll, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"lzcntsemantics": {
				Name:  "lzcntsemantics",
				Args:  []LLVMType{Ptr},
				Ret:   Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void lzcntsemantics(uint8_t *);
int main(void) {
  uint8_t out[56] = {0};
  lzcntsemantics(out);
  if (*(uint64_t *)(out+0) != UINT64_C(0xaabbccddeeff0010)) return 10;
  if (out[8] != 1 || out[9] != 0) return 11;
  if (*(uint64_t *)(out+16) != 0) return 12;
  if (out[24] != 0 || out[25] != 1) return 13;
  if (*(uint64_t *)(out+40) != 63) return 14;
  if (out[48] != 0 || out[49] != 0) return 15;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "lzcnt_semantics", triple, ll, mainC, runPrefix)
}
