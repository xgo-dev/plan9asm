package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func x86LEACompleteFormsSource(goarch string) string {
	var source strings.Builder
	source.WriteString("DATA leadata+0(SB)/8, $1\n")
	source.WriteString("GLOBL leadata(SB), $8\n")
	source.WriteString("TEXT leaforms(SB),$0-0\n")
	widths := []string{"W", "L"}
	if goarch == "amd64" {
		widths = append(widths, "Q")
	}
	for _, width := range widths {
		op := "LEA" + width
		source.WriteString("\t" + op + " 8(BX)(CX*2), AX\n")
		source.WriteString("\t" + op + " leadata(SB), DX\n")
		source.WriteString("\t" + op + " 16(BX), SP\n")
		if goarch == "amd64" {
			source.WriteString("\t" + op + " 24(R11)(R12*4), R13\n")
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateX86LEACompleteGo127FormsAcrossTargets(t *testing.T) {
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
			source := x86LEACompleteFormsSource(target.goarch)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"leaforms": {Name: "leaforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"trunc i64", "to i16", "to i32"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("LEA lowering omitted %q:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "lea-complete-"+target.name+".ll", "lea-complete-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86LEARejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "LEAW AX, BX"},
		{goarch: "amd64", instruction: "LEAL 8(AX), X0"},
		{goarch: "amd64", instruction: "LEAQ 8(AX)"},
		{goarch: "amd64", instruction: "LEAW.Z 8(AX), BX"},
		{goarch: "386", instruction: "LEAQ 8(AX), BX"},
		{goarch: "386", instruction: "LEAW 8(R9), AX"},
		{goarch: "386", instruction: "LEAL 8(AX), R8"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's ym_rl table", test.instruction)
			}
		})
	}
}

func TestAMD64LEARuntimeWidthsAndFlags(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT leasementics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	MOVL $0x7fffffff, R8
	ADDL $1, R8
	STC
	MOVQ $0x1122334455667788, AX
	LEAW 0x1234(DI), AX
	MOVQ AX, 0(DI)
	LEAL 0x1234(DI), BX
	MOVQ BX, 8(DI)
	LEAQ 0x1234(DI), CX
	MOVQ CX, 16(DI)
	SETCS 24(DI)
	SETOS 25(DI)
	SETEQ 26(DI)
	SETMI 27(DI)
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
			"leasementics": {
				Name: "leasementics", Args: []LLVMType{Ptr}, Ret: Void,
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
extern void leasementics(uint8_t *);
static uint64_t load64(const uint8_t *p) {
  uint64_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}
int main(void) {
  uint8_t out[32] = {0};
  uintptr_t address = (uintptr_t)(out + 0x1234);
  leasementics(out);
  uint64_t want16 = UINT64_C(0x1122334455660000) | (address & UINT64_C(0xffff));
  if (load64(out+0) != want16) return 10;
  if (load64(out+8) != (uint32_t)address) return 11;
  if (load64(out+16) != address) return 12;
  if (out[24] != 1 || out[25] != 1 || out[26] != 0 || out[27] != 1) return 13;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "lea_semantics", triple, ir, mainC, runPrefix)
}
