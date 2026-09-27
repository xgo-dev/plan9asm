package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86BZHICompleteFormsSource(goarch string) string {
	var source strings.Builder
	source.WriteString("DATA bzhidata+0(SB)/8, $1\n")
	source.WriteString("GLOBL bzhidata(SB), $8\n")
	source.WriteString("TEXT bzhiforms(SB),$0-0\n")
	for _, width := range []string{"L", "Q"} {
		op := "BZHI" + width
		fmt.Fprintf(&source, "\t%s AX, BX, CX\n", op)
		fmt.Fprintf(&source, "\t%s DX, 8(BX), SI\n", op)
		fmt.Fprintf(&source, "\t%s CX, bzhidata(SB), DX\n", op)
		if goarch == "amd64" {
			fmt.Fprintf(&source, "\t%s R11, R12, R13\n", op)
		} else {
			fmt.Fprintf(&source, "\t%s AX, BX, SP\n", op)
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateX86BZHICompleteGo127FormsAcrossTargets(t *testing.T) {
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
			source := x86BZHICompleteFormsSource(target.goarch)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"bzhiforms": {Name: "bzhiforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"shl i32", "shl i64", `"target-features"="+bmi2"`} {
				if !strings.Contains(ir, want) {
					t.Fatalf("BZHI lowering omitted %q:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "bzhi-"+target.name+".ll", "bzhi-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86BZHIRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "BZHIL $1, AX, BX"},
		{goarch: "amd64", instruction: "BZHIQ 0(AX), BX, CX"},
		{goarch: "amd64", instruction: "BZHIQ AX, $1, CX"},
		{goarch: "amd64", instruction: "BZHIL AX, BX, 0(CX)"},
		{goarch: "amd64", instruction: "BZHIQ X0, AX, BX"},
		{goarch: "amd64", instruction: "BZHIQ AX, X0, BX"},
		{goarch: "amd64", instruction: "BZHIQ AX, BX, X0"},
		{goarch: "amd64", instruction: "BZHIQ AX, BX"},
		{goarch: "amd64", instruction: "BZHIQ.Z AX, BX, CX"},
		{goarch: "386", instruction: "BZHIL R8, AX, BX"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's _ybextrl table", test.instruction)
			}
		})
	}
}

func TestAMD64BZHIRuntimeSemanticsAndFlags(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT bzhisemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI

	MOVL $0x7fffffff, R8
	ADDL $1, R8
	MOVL $8, AX
	MOVL $0x1234, BX
	BZHIL AX, BX, CX
	MOVQ CX, 0(DI)
	SETCS 8(DI)
	SETOS 9(DI)
	SETEQ 10(DI)
	SETMI 11(DI)

	MOVL $31, AX
	MOVL $0x80000000, BX
	BZHIL AX, BX, CX
	MOVQ CX, 16(DI)
	SETEQ 24(DI)

	MOVL $32, AX
	MOVL $0x80000000, BX
	BZHIL AX, BX, CX
	MOVQ CX, 32(DI)
	SETCS 40(DI)
	SETMI 41(DI)

	MOVQ $0x1000000000000004, AX
	MOVQ $-1, 48(DI)
	BZHIQ AX, 48(DI), CX
	MOVQ CX, 56(DI)

	MOVQ $64, AX
	MOVQ $0x1234, BX
	BZHIQ AX, BX, AX
	MOVQ AX, 64(DI)
	SETCS 72(DI)
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
			"bzhisemantics": {
				Name:  "bzhisemantics",
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
#include <string.h>
extern void bzhisemantics(uint8_t *);
static uint64_t load64(const uint8_t *p) {
  uint64_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}
int main(void) {
  uint8_t out[80] = {0};
  bzhisemantics(out);
  if (load64(out + 0) != UINT64_C(0x34)) return 10;
  if (out[8] != 0 || out[9] != 0 || out[10] != 0 || out[11] != 0) return 11;
  if (load64(out + 16) != 0 || out[24] != 1) return 12;
  if (load64(out + 32) != UINT64_C(0x80000000) || out[40] != 1 || out[41] != 1) return 13;
  if (load64(out + 56) != UINT64_C(0xf)) return 14;
  if (load64(out + 64) != UINT64_C(0x1234) || out[72] != 1) return 15;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "bzhi_semantics", triple, ir, mainC, runPrefix)
}
