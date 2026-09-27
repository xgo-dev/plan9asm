package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86MOVBECompleteFormsSource(goarch string) string {
	var source strings.Builder
	source.WriteString("DATA movedata+0(SB)/8, $1\n")
	source.WriteString("GLOBL movedata(SB), $8\n")
	source.WriteString("TEXT moveforms(SB),$0-0\n")
	widths := []string{"W", "L"}
	if goarch == "amd64" {
		widths = append(widths, "Q")
	}
	for _, width := range widths {
		op := "MOVBE" + width
		fmt.Fprintf(&source, "\t%s 8(BX), AX\n", op)
		fmt.Fprintf(&source, "\t%s AX, 16(BX)\n", op)
		fmt.Fprintf(&source, "\t%s movedata(SB), CX\n", op)
		fmt.Fprintf(&source, "\t%s DX, movedata(SB)\n", op)
		if goarch == "amd64" {
			fmt.Fprintf(&source, "\t%s 24(R11), R12\n", op)
			fmt.Fprintf(&source, "\t%s R13, 32(R14)\n", op)
		}
	}
	if goarch == "amd64" {
		// Older external packages use the Go assembler's MOVBEQQ alias for
		// the 64-bit MOVBE form. Keep this spelling covered alongside MOVBEQ.
		source.WriteString("\tMOVBEQQ 40(R11), R12\n")
		source.WriteString("\tMOVBEQQ R13, 48(R14)\n")
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateX86MOVBECompleteGo127FormsAcrossTargets(t *testing.T) {
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
			source := x86MOVBECompleteFormsSource(target.goarch)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"moveforms": {Name: "moveforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"@llvm.bswap.i16", "@llvm.bswap.i32", `"target-features"="+movbe"`} {
				if !strings.Contains(ir, want) {
					t.Fatalf("MOVBE lowering omitted %q:\n%s", want, ir)
				}
			}
			if target.goarch == "amd64" && !strings.Contains(ir, "@llvm.bswap.i64") {
				t.Fatalf("MOVBEQ lowering omitted i64 byte swap:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "movbe-"+target.name+".ll", "movbe-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86MOVBERejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "MOVBEW AX, BX"},
		{goarch: "amd64", instruction: "MOVBEL 0(AX), 0(BX)"},
		{goarch: "amd64", instruction: "MOVBEQ $1, 0(BX)"},
		{goarch: "amd64", instruction: "MOVBEW AL, 0(BX)"},
		{goarch: "amd64", instruction: "MOVBEL 0(AX), X0"},
		{goarch: "amd64", instruction: "MOVBEQ AX"},
		{goarch: "amd64", instruction: "MOVBEQQ AX"},
		{goarch: "amd64", instruction: "MOVBEL.Z 0(AX), BX"},
		{goarch: "386", instruction: "MOVBEQ 0(AX), BX"},
		{goarch: "386", instruction: "MOVBEL R8, 0(AX)"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's MOVBE ymovbe table", test.instruction)
			}
		})
	}
}

func TestAMD64MOVBERuntimeSemanticsWidthsDirectionsAndFlags(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT movesemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	MOVL $0x7fffffff, R8
	ADDL $1, R8
	STC

	MOVW $0x3412, 0(DI)
	MOVQ $0x1122334455667788, AX
	MOVBEW 0(DI), AX
	MOVQ AX, 8(DI)

	MOVL $0x78563412, 16(DI)
	MOVBEL 16(DI), BX
	MOVQ BX, 24(DI)

	MOVQ $0xefcdab8967452301, 32(DI)
	MOVBEQ 32(DI), CX
	MOVQ CX, 40(DI)

	MOVQ $0x1122334455667788, AX
	MOVBEW AX, 48(DI)
	MOVBEL AX, 50(DI)
	MOVBEQ AX, 54(DI)

	SETCS 62(DI)
	SETOS 63(DI)
	SETEQ 64(DI)
	SETMI 65(DI)
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
			"movesemantics": {
				Name: "movesemantics", Args: []LLVMType{Ptr}, Ret: Void,
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
extern void movesemantics(uint8_t *);
static uint64_t load64(const uint8_t *p) {
  uint64_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}
int main(void) {
  uint8_t out[72] = {0};
  movesemantics(out);
  if (load64(out+8) != UINT64_C(0x1122334455661234)) return 10;
  if (load64(out+24) != UINT64_C(0x12345678)) return 11;
  if (load64(out+40) != UINT64_C(0x0123456789abcdef)) return 12;
  const uint8_t stores[14] = {0x77,0x88, 0x55,0x66,0x77,0x88, 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
  if (memcmp(out+48, stores, sizeof(stores)) != 0) return 13;
  if (out[62] != 1 || out[63] != 1 || out[64] != 0 || out[65] != 1) return 14;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "movbe_semantics", triple, ir, mainC, runPrefix)
}
