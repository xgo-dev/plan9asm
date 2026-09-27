package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func arm64AddSubCarryCompleteForms() string {
	var source strings.Builder
	source.WriteString("TEXT addSubCarryComplete(SB),$0-0\n")
	for _, op := range []string{"ADC", "ADCW", "ADCS", "ADCSW", "SBC", "SBCW", "SBCS", "SBCSW"} {
		source.WriteString("\t" + op + " R1, R2\n")
		source.WriteString("\t" + op + " R3, R4, R5\n")
		source.WriteString("\t" + op + " ZR, R6, R7\n")
		source.WriteString("\t" + op + " $0, R8\n")
		source.WriteString("\t" + op + " R9, ZR, ZR\n")
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64AddSubCarryCompleteFormats(t *testing.T) {
	source := arm64AddSubCarryCompleteForms()
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: arm64LinuxGNUTriple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"addSubCarryComplete": {Name: "addSubCarryComplete", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"add i64", "add i32", "sub i64", "sub i32",
		"zext i32", "icmp ult i64", "icmp ult i32",
		"icmp slt i64", "icmp slt i32",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM64 add/sub-with-carry lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-addsub-carry.ll", "arm64-addsub-carry.o", ll)
}

func TestTranslateARM64AddSubCarryRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"ADCW R0",
		"ADCW R0, R1, R2, R3",
		"ADCW (R0), R1",
		"ADCW R0<<1, R1, R2",
		"ADCW R0, RSP, R2",
		"ADCW R0, R1, RSP",
		"ADCW $1, R1",
		"ADCSW.P R0, R1",
		"SBCW R0, 8(R1), R2",
		"SBCSW R0.UXTW, R1, R2",
	} {
		source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: arm64LinuxGNUTriple,
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's ARM64 ADC/SBC optab", instruction)
		}
	}
}

func TestARM64AddSubCarryRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT addSubCarryRuntime(SB),$0-8
	MOVD out+0(FP), R10
	MOVD $0xffffffff, R0
	MOVD $0, R1
	CMP R1, R1
	ADCSW R1, R0, R2
	MOVD R2, 0(R10)
	CSET CS, R3
	MOVD R3, 8(R10)
	CSET EQ, R3
	MOVD R3, 16(R10)
	CSET MI, R3
	MOVD R3, 24(R10)
	CSET VS, R3
	MOVD R3, 32(R10)
	CMP $1, R1
	SBCSW R1, R1, R2
	MOVD R2, 40(R10)
	CSET CS, R3
	MOVD R3, 48(R10)
	CSET EQ, R3
	MOVD R3, 56(R10)
	CSET MI, R3
	MOVD R3, 64(R10)
	CSET VS, R3
	MOVD R3, 72(R10)
	MOVD $0x7fffffff, R0
	CMP R1, R1
	ADCSW R1, R0, R2
	MOVD R2, 80(R10)
	CSET CS, R3
	MOVD R3, 88(R10)
	CSET EQ, R3
	MOVD R3, 96(R10)
	CSET MI, R3
	MOVD R3, 104(R10)
	CSET VS, R3
	MOVD R3, 112(R10)
	MOVD $0x80000000, R0
	CMP $1, R1
	SBCSW R1, R0, R2
	MOVD R2, 120(R10)
	CSET CS, R3
	MOVD R3, 128(R10)
	CSET EQ, R3
	MOVD R3, 136(R10)
	CSET MI, R3
	MOVD R3, 144(R10)
	CSET VS, R3
	MOVD R3, 152(R10)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"addSubCarryRuntime": {
				Name: "addSubCarryRuntime", Args: []LLVMType{Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void addSubCarryRuntime(uint64_t *);
int main(void) {
  uint64_t got[20] = {0};
  addSubCarryRuntime(got);
  const uint64_t want[20] = {
    0, 1, 1, 0, 0,
    UINT64_C(0xffffffff), 0, 0, 1, 0,
    UINT64_C(0x80000000), 0, 0, 1, 1,
    UINT64_C(0x7fffffff), 1, 0, 0, 1,
  };
  for (int i = 0; i < 20; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_addsub_carry", triple, ir, mainC, nil)
}
