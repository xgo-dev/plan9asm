package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64CompareNegativeCompleteGo127Forms(t *testing.T) {
	const source = `TEXT compareNegativeForms(SB), $0-0
	CMNW R21.UXTB<<4, R15
	CMN R0.UXTW<<4, R16
	CMNW R13>>8, R9
	CMN R6->17, R3
	CMNW $(2<<12), R5
	CMN $(8<<12), R12
	CMN R6->0, R3
	CMN R6, R3
	CMNW R30, R5
	CMNW $2, R5
	CMN ZR, R3
	CMN R1.SXTX<<2, R10
	CMNW R1.SXTB, R9
	CMN R1<<3, RSP
	CMNW $0x3fffffc0, R2
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"compareNegativeForms": {Name: "compareNegativeForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"add i64", "add i32", "icmp ult i32", "icmp slt i32"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("CMN/CMNW lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-cmn.ll", "arm64-cmn.o", ll)
		})
	}
}

func TestTranslateARM64CompareNegativeRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, instruction := range []string{
		"CMN R0",
		"CMNW R0, R1, R2",
		"CMN (R0), R1",
		"CMNW R0@>1, R1",
		"CMN R0.UXTB<<5, R1",
		"CMNW.P R0, R1",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			source := "TEXT badCompareNegative(SB), $0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badCompareNegative": {Name: "badCompareNegative", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's CMN/CMNW optab", instruction)
			}
		})
	}
}

func TestARM64CompareNegativeRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT compareNegativeRuntime(SB), $0-16
	MOVD value+0(FP), R0
	MOVD $0, R1
	CMNW $1, R0
	BNE notWordMinusOne
	ORR $1, R1
notWordMinusOne:
	CMN $1, R0
	BNE done
	ORR $2, R1
done:
	MOVD R1, ret+8(FP)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"compareNegativeRuntime": {
				Name: "compareNegativeRuntime", Args: []LLVMType{I64}, Ret: I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern uint64_t compareNegativeRuntime(uint64_t);
int main(void) {
  if (compareNegativeRuntime(UINT64_C(0xffffffffffffffff)) != 3) return 1;
  if (compareNegativeRuntime(UINT64_C(0x00000000ffffffff)) != 1) return 2;
  if (compareNegativeRuntime(7) != 0) return 3;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_cmn", triple, ll, mainC, nil)
}
