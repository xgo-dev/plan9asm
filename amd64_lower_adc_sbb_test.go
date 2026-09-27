package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86ADCSBBCompleteGoAssemblerForms(t *testing.T) {
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
			var source strings.Builder
			source.WriteString("TEXT adcsbbforms(SB),NOSPLIT,$32-0\n")
			for _, stem := range []string{"ADC", "SBB"} {
				for _, width := range []string{"B", "W", "L", "Q"} {
					if target.goarch == "386" && width == "Q" {
						continue
					}
					op := stem + width
					srcReg, dstReg := "BX", "AX"
					if width == "B" {
						srcReg, dstReg = "BL", "AL"
					}
					fmt.Fprintf(&source, "\t%s $1, %s\n", op, dstReg)
					fmt.Fprintf(&source, "\t%s %s, %s\n", op, srcReg, dstReg)
					fmt.Fprintf(&source, "\t%s 8(BX), %s\n", op, dstReg)
					fmt.Fprintf(&source, "\t%s $1, 16(BX)\n", op)
					fmt.Fprintf(&source, "\t%s %s, 24(BX)\n", op, srcReg)
					if target.goarch == "386" && width != "B" {
						fmt.Fprintf(&source, "\t%s $0, SP\n", op)
					}
					if target.goarch == "amd64" && width == "Q" {
						fmt.Fprintf(&source, "\t%s $4294967295, AX\n", op)
					}
				}
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs:         map[string]FuncSig{"adcsbbforms": {Name: "adcsbbforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "adc-sbb-"+target.name+".ll", "adc-sbb-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86ADCSBBRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	tests := []struct {
		goarch      string
		triple      string
		instruction string
	}{
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "ADCB SP, AL"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "SBBB AL, SP"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "ADCQ 0(BX), 8(CX)"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "SBBL X0, AX"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "ADCW.Z AX, BX"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "ADCQ $4294967296, AX"},
		{goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "ADCQ AX, BX"},
		{goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "SBBQ $1, 0(BX)"},
		{goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "ADCL R8, AX"},
	}
	for _, test := range tests {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+test.instruction+"\n\tRET\n")
			if err == nil {
				_, err = Translate(file, Options{
					TargetTriple: test.triple,
					Goarch:       test.goarch,
					Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
				})
			}
			if err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ADC/SBB tables for %s", test.instruction, test.goarch)
			}
		})
	}
}

func TestAMD64ADCSBBMemoryRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := `
TEXT adcsbbmemory(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	MOVQ $0xffffffffffffffff, 0(DI)
	CLC
	ADCQ $1, 0(DI)
	SETCS 32(DI)
	SBBQ $0, 0(DI)
	SETCS 33(DI)
	MOVL $0x7fffffff, 8(DI)
	STC
	ADCL $0, 8(DI)
	SETOS 34(DI)
	MOVW $0, 16(DI)
	STC
	SBBW $0, 16(DI)
	SETCS 35(DI)
	MOVB $0xff, 24(DI)
	CLC
	ADCB $1, 24(DI)
	SETCS 36(DI)
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
			"adcsbbmemory": {Name: "adcsbbmemory", Args: []LLVMType{Ptr}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
extern void adcsbbmemory(uint8_t *);
int main(void) {
  uint8_t out[40] = {0};
  adcsbbmemory(out);
  if (*(uint64_t *)(out+0) != UINT64_MAX) return 10;
  if (*(uint32_t *)(out+8) != 0x80000000U) return 11;
  if (*(uint16_t *)(out+16) != 0xffffU) return 12;
  if (out[24] != 0) return 13;
  for (int i = 32; i <= 36; i++) if (out[i] != 1) return 20+i;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "adc_sbb_memory", triple, ll, mainC, runPrefix)
}
