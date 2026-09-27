package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x86ADXCompleteFormsSource(goarch string) string {
	var source strings.Builder
	symbol := "adxdata"
	size := 8
	if goarch == "386" {
		symbol = "adxdata386"
		size = 4
	}
	fmt.Fprintf(&source, "DATA %s+0(SB)/%d, $1\n", symbol, size)
	fmt.Fprintf(&source, "GLOBL %s(SB), $%d\n", symbol, size)
	source.WriteString("TEXT adxforms(SB),$0-0\n")
	widths := []string{"L"}
	if goarch == "amd64" {
		widths = append(widths, "Q")
	}
	for _, stem := range []string{"ADCX", "ADOX"} {
		for _, width := range widths {
			op := stem + width
			fmt.Fprintf(&source, "\t%s AX, BX\n", op)
			fmt.Fprintf(&source, "\t%s 8(BX), CX\n", op)
			fmt.Fprintf(&source, "\t%s %s(SB), DX\n", op, symbol)
			if goarch == "amd64" {
				fmt.Fprintf(&source, "\t%s R11, R12\n", op)
			} else {
				fmt.Fprintf(&source, "\t%s AX, SP\n", op)
			}
		}
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateX86ADXCompleteGo127FormsAcrossTargets(t *testing.T) {
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
			source := x86ADXCompleteFormsSource(target.goarch)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"adxforms": {Name: "adxforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"add i32", "icmp ult i32", `"target-features"="+adx"`} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ADX lowering omitted %q:\n%s", want, ll)
				}
			}
			if target.goarch == "amd64" && !strings.Contains(ll, "add i64") {
				t.Fatalf("ADX Q-width lowering omitted add i64:\n%s", ll)
			}
			compileLLVMToObject(t, llc, target.triple, "adx-"+target.name+".ll", "adx-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86ADXRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "ADCXQ $1, AX"},
		{goarch: "amd64", instruction: "ADOXL AX, 0(BX)"},
		{goarch: "amd64", instruction: "ADCXL X0, AX"},
		{goarch: "amd64", instruction: "ADOXQ AX, X0"},
		{goarch: "amd64", instruction: "ADCXQ AX"},
		{goarch: "amd64", instruction: "ADOXL.Z AX, BX"},
		{goarch: "386", instruction: "ADCXL R8, AX"},
		{goarch: "386", instruction: "ADOXQ AX, BX"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's ADX yml_rl table", test.instruction)
			}
		})
	}
}

func TestAMD64ADXRuntimeSemanticsAndIndependentFlags(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test only runs on amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT adxsemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI

	// ADCXL consumes CF, updates only CF, and zero-extends its destination.
	MOVL $0x7fffffff, R8
	ADDL $1, R8
	STC
	MOVL $-1, AX
	MOVL $0, BX
	ADCXL AX, BX
	MOVQ BX, 0(DI)
	SETCS 8(DI)
	SETOS 9(DI)
	SETEQ 10(DI)
	SETMI 11(DI)

	// ADOXL consumes OF, updates only OF, and leaves CF untouched.
	MOVL $0x7fffffff, R8
	ADDL $1, R8
	STC
	MOVL $-1, AX
	MOVL $0, BX
	ADOXL AX, BX
	MOVQ BX, 16(DI)
	SETOS 24(DI)
	SETCS 25(DI)
	SETEQ 26(DI)
	SETMI 27(DI)

	// The Q-width memory form uses CF while preserving OF and ZF.
	XORQ R8, R8
	STC
	MOVQ $-1, 32(DI)
	MOVQ $0, BX
	ADCXQ 32(DI), BX
	MOVQ BX, 40(DI)
	SETCS 48(DI)
	SETOS 49(DI)
	SETEQ 50(DI)
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
		TargetTriple: triple,
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"adxsemantics": {
				Name:  "adxsemantics",
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
extern void adxsemantics(uint8_t *);
static uint64_t load64(const uint8_t *p) {
  uint64_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}
int main(void) {
  uint8_t out[56] = {0};
  adxsemantics(out);
  if (load64(out + 0) != 0) return 10;
  const uint8_t adcx_flags[4] = {1, 1, 0, 1};
  for (int i = 0; i < 4; i++) if (out[8+i] != adcx_flags[i]) return 20+i;
  if (load64(out + 16) != 0) return 30;
  const uint8_t adox_flags[4] = {1, 1, 0, 1};
  for (int i = 0; i < 4; i++) if (out[24+i] != adox_flags[i]) return 40+i;
  if (load64(out + 40) != 0) return 50;
  const uint8_t adcxq_flags[3] = {1, 0, 1};
  for (int i = 0; i < 3; i++) if (out[48+i] != adcxq_flags[i]) return 60+i;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "adx_semantics", triple, ir, mainC, runPrefix)
}
