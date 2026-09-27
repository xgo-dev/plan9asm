package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86XCHGCompleteFormsSource(goarch string) string {
	var source strings.Builder
	symbol := "xchgdata"
	size := 8
	if goarch == "386" {
		symbol = "xchgdata386"
		size = 4
	}
	fmt.Fprintf(&source, "DATA %s+0(SB)/%d, $0\n", symbol, size)
	fmt.Fprintf(&source, "GLOBL %s(SB), $%d\n", symbol, size)
	source.WriteString("TEXT xchgforms(SB),$0-0\n")
	if goarch == "amd64" {
		source.WriteString("\tXCHGB AH, BL\n\tXCHGB R11, R12\n")
	} else {
		source.WriteString("\tXCHGB AH, BL\n\tXCHGB BP, DI\n")
	}
	source.WriteString("\tXCHGB DL, 8(BX)\n\tXCHGB 8(BX), DL\n")
	if goarch == "amd64" {
		source.WriteString("\tXCHGB R11, " + symbol + "(SB)\n\tXCHGB " + symbol + "(SB), R11\n")
	} else {
		source.WriteString("\tXCHGB SI, " + symbol + "(SB)\n\tXCHGB " + symbol + "(SB), SI\n")
	}
	widths := []string{"W", "L"}
	if goarch == "amd64" {
		widths = append(widths, "Q")
	}
	for _, width := range widths {
		if goarch == "amd64" {
			fmt.Fprintf(&source, "\tXCHG%s DX, BX\n\tXCHG%s R11, R12\n", width, width)
		} else {
			fmt.Fprintf(&source, "\tXCHG%s DX, BX\n\tXCHG%s SI, DI\n", width, width)
		}
		fmt.Fprintf(&source, "\tXCHG%s DX, 8(BX)\n\tXCHG%s 8(BX), DX\n", width, width)
		if goarch == "amd64" {
			fmt.Fprintf(&source, "\tXCHG%s R11, %s(SB)\n\tXCHG%s %s(SB), R11\n", width, symbol, width, symbol)
		} else {
			fmt.Fprintf(&source, "\tXCHG%s SI, %s(SB)\n\tXCHG%s %s(SB), SI\n", width, symbol, width, symbol)
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateX86XCHGCompleteGo127FormsAcrossTargets(t *testing.T) {
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
			source := x86XCHGCompleteFormsSource(target.goarch)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"xchgforms": {Name: "xchgforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"asm sideeffect \"xchg", "i8", "i16", "i32"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("XCHG lowering omitted %q:\n%s", want, ll)
				}
			}
			if target.goarch == "amd64" && !strings.Contains(ll, "i64") {
				t.Fatalf("XCHGQ lowering omitted i64 operations:\n%s", ll)
			}
			compileLLVMToObject(t, llc, target.triple, "xchg-"+target.name+".ll", "xchg-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86XCHGRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "XCHGB X0, DL"},
		{goarch: "amd64", instruction: "XCHGW $1, DX"},
		{goarch: "amd64", instruction: "XCHGL 0(BX), 8(CX)"},
		{goarch: "amd64", instruction: "XCHGQ DX, X0"},
		{goarch: "amd64", instruction: "XCHGW DX"},
		{goarch: "amd64", instruction: "XCHGL DX, BX, AX"},
		{goarch: "amd64", instruction: "XCHGL.Z DX, BX"},
		{goarch: "386", instruction: "XCHGB SP, (BX)"},
		{goarch: "386", instruction: "XCHGL R8, (BX)"},
		{goarch: "386", instruction: "XCHGL 1(R8), DX"},
		{goarch: "386", instruction: "XCHGQ DX, BX"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's XCHG optab", test.instruction)
			}
		})
	}
}

func TestAMD64XCHGRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT xchgsemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	MOVQ $0x1122, AX
	MOVQ $0x3344, BX
	XCHGB AH, BL
	MOVQ AX, 0(DI)
	MOVQ BX, 8(DI)
	MOVQ $0x1122334455667788, AX
	MOVQ $0x887766554433aabb, BX
	XCHGW AX, BX
	MOVQ AX, 16(DI)
	MOVQ BX, 24(DI)
	MOVQ $0x1122334455667788, AX
	MOVQ $0x88776655aabbccdd, BX
	XCHGL AX, BX
	MOVQ AX, 32(DI)
	MOVQ BX, 40(DI)
	MOVQ $5, AX
	MOVQ $7, BX
	XCHGQ AX, BX
	MOVQ AX, 48(DI)
	MOVQ BX, 56(DI)
	MOVB $0x5a, 64(DI)
	MOVQ $0x11223344556677c3, AX
	CMPQ AX, AX
	STC
	XCHGB 64(DI), AL
	MOVQ AX, 72(DI)
	SETCS 80(DI)
	SETEQ 81(DI)
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
			"xchgsemantics": {
				Name:  "xchgsemantics",
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
extern void xchgsemantics(uint8_t *);
int main(void) {
  uint8_t out[88] = {0};
  xchgsemantics(out);
  if (*(uint64_t *)(out+0) != UINT64_C(0x4422)) return 10;
  if (*(uint64_t *)(out+8) != UINT64_C(0x3311)) return 11;
  if (*(uint64_t *)(out+16) != UINT64_C(0x112233445566aabb)) return 12;
  if (*(uint64_t *)(out+24) != UINT64_C(0x8877665544337788)) return 13;
  if (*(uint64_t *)(out+32) != UINT64_C(0xaabbccdd)) return 14;
  if (*(uint64_t *)(out+40) != UINT64_C(0x55667788)) return 15;
  if (*(uint64_t *)(out+48) != 7 || *(uint64_t *)(out+56) != 5) return 16;
  if (out[64] != 0xc3 || *(uint64_t *)(out+72) != UINT64_C(0x112233445566775a)) return 17;
  if (out[80] != 1 || out[81] != 1) return 18;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "xchg_semantics", triple, ll, mainC, runPrefix)
}
