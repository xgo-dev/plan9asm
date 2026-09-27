package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86BMI2VariableShiftFormsSource(goarch string) string {
	var source strings.Builder
	symbol := "bmi2shiftdata"
	size := 8
	if goarch == "386" {
		symbol = "bmi2shiftdata386"
		size = 4
	}
	fmt.Fprintf(&source, "DATA %s+0(SB)/%d, $1\n", symbol, size)
	fmt.Fprintf(&source, "GLOBL %s(SB), $%d\n", symbol, size)
	source.WriteString("TEXT bmi2shiftforms(SB),$0-0\n")
	for _, stem := range []string{"SARX", "SHLX", "SHRX"} {
		for _, width := range []string{"L", "Q"} {
			op := stem + width
			fmt.Fprintf(&source, "\t%s AX, BX, CX\n", op)
			fmt.Fprintf(&source, "\t%s DX, 8(BX), SI\n", op)
			fmt.Fprintf(&source, "\t%s CX, %s(SB), DX\n", op, symbol)
			if goarch == "amd64" {
				fmt.Fprintf(&source, "\t%s R11, R12, R13\n", op)
			}
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateX86BMI2VariableShiftCompleteGo127FormsAcrossTargets(t *testing.T) {
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
			source := x86BMI2VariableShiftFormsSource(target.goarch)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"bmi2shiftforms": {Name: "bmi2shiftforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			operations := []string{"ashr i32", "shl i32", "lshr i32", `"target-features"="+bmi2"`}
			if target.goarch == "amd64" {
				operations = append(operations, "ashr i64", "shl i64", "lshr i64")
			} else if strings.Contains(ll, "ashr i64") || strings.Contains(ll, "shl i64") || strings.Contains(ll, "lshr i64") {
				t.Fatal("386 BMI2 shift used 64-bit arithmetic")
			}
			for _, want := range operations {
				if !strings.Contains(ll, want) {
					t.Fatalf("BMI2 variable-shift lowering omitted %q:\n%s", want, ll)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "bmi2-shift-"+target.name+".ll", "bmi2-shift-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86BMI2VariableShiftRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "SHLXQ $1, AX, BX"},
		{goarch: "amd64", instruction: "SHRXQ 0(BX), AX, CX"},
		{goarch: "amd64", instruction: "SARXL AX, BX, 0(CX)"},
		{goarch: "amd64", instruction: "SHLXL X0, AX, BX"},
		{goarch: "amd64", instruction: "SHRXQ AX, X0, BX"},
		{goarch: "amd64", instruction: "SARXQ AX, BX"},
		{goarch: "amd64", instruction: "SHLXQ.Z AX, BX, CX"},
		{goarch: "386", instruction: "SHLXL R8, AX, BX"},
		{goarch: "386", instruction: "SHRXQ AX, R8, BX"},
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

func TestAMD64BMI2VariableShiftRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT bmi2shiftsemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	MOVQ $36, AX
	MOVQ $0x12345678, BX
	SHLXL AX, BX, CX
	MOVQ CX, 0(DI)
	MOVQ $-81985529216486896, 8(DI)
	MOVQ $72, AX
	SHRXQ AX, 8(DI), CX
	MOVQ CX, 8(DI)
	MOVQ $0x80000000, BX
	SARXL AX, BX, CX
	MOVQ CX, 16(DI)
	MOVQ $-9223372036854775808, BX
	SARXQ AX, BX, CX
	MOVQ CX, 24(DI)
	MOVQ $1, AX
	MOVQ $3, BX
	CMPQ BX, BX
	STC
	SHLXQ AX, BX, AX
	MOVQ AX, 32(DI)
	SETCS 40(DI)
	SETEQ 41(DI)
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
			"bmi2shiftsemantics": {
				Name:  "bmi2shiftsemantics",
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
extern void bmi2shiftsemantics(uint8_t *);
int main(void) {
  uint8_t out[48] = {0};
  bmi2shiftsemantics(out);
  if (*(uint64_t *)(out+0) != UINT64_C(0x23456780)) return 10;
  if (*(uint64_t *)(out+8) != UINT64_C(0x00fedcba98765432)) return 11;
  if (*(uint64_t *)(out+16) != UINT64_C(0xff800000)) return 12;
  if (*(uint64_t *)(out+24) != UINT64_C(0xff80000000000000)) return 13;
  if (*(uint64_t *)(out+32) != 6) return 14;
  if (out[40] != 1 || out[41] != 1) return 15;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "bmi2_shift_semantics", triple, ll, mainC, runPrefix)
}
