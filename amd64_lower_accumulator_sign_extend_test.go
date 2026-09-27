package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func x86AccumulatorSignExtendCompleteFormsSource(goarch string) string {
	ops := []string{"CBW", "CWDE", "CWD", "CDQ"}
	if goarch == "amd64" {
		ops = append(ops, "CDQE", "CQO")
	}
	var source strings.Builder
	source.WriteString("TEXT signextendforms(SB),$0-0\n")
	for _, op := range ops {
		source.WriteString("\t" + op + "\n")
	}
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateX86AccumulatorSignExtendCompleteGo127FormsAcrossTargets(t *testing.T) {
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
			source := x86AccumulatorSignExtendCompleteFormsSource(target.goarch)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"signextendforms": {Name: "signextendforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"sext i8", "sext i16", "ashr i16", "ashr i32"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("accumulator sign-extension lowering omitted %q:\n%s", want, ir)
				}
			}
			if target.goarch == "amd64" {
				for _, want := range []string{"sext i32", "ashr i64"} {
					if !strings.Contains(ir, want) {
						t.Fatalf("amd64 accumulator sign-extension lowering omitted %q:\n%s", want, ir)
					}
				}
			}
			compileLLVMToObject(t, llc, target.triple, "accumulator-sign-extend-"+target.name+".ll", "accumulator-sign-extend-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86AccumulatorSignExtendRejectsFormsOutsideGo127Optab(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "CBW AX"},
		{goarch: "amd64", instruction: "CWDE $1"},
		{goarch: "amd64", instruction: "CDQ AX, DX"},
		{goarch: "amd64", instruction: "CWD.Z"},
		{goarch: "386", instruction: "CDQE"},
		{goarch: "386", instruction: "CQO"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's ynone tables", test.instruction)
			}
		})
	}
}

func TestAMD64AccumulatorSignExtendRuntimeSemanticsAndFlags(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT signextendsemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	MOVL $0x7fffffff, R8
	ADDL $1, R8
	STC

	MOVQ $0x1122334455660080, AX
	CBW
	MOVQ AX, 0(DI)

	MOVQ $0x1122334455667788, DX
	MOVW $0x8001, AX
	CWD
	MOVQ DX, 8(DI)

	MOVQ $0x1122334455668001, AX
	CWDE
	MOVQ AX, 16(DI)

	MOVL $0x80000001, AX
	MOVQ $0x1122334455667788, DX
	CDQ
	MOVQ DX, 24(DI)

	MOVL $0x80000001, AX
	CDQE
	MOVQ AX, 32(DI)

	MOVQ $0x8000000000000001, AX
	CQO
	MOVQ DX, 40(DI)

	SETCS 48(DI)
	SETOS 49(DI)
	SETEQ 50(DI)
	SETMI 51(DI)
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
			"signextendsemantics": {
				Name: "signextendsemantics", Args: []LLVMType{Ptr}, Ret: Void,
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
extern void signextendsemantics(uint8_t *);
static uint64_t load64(const uint8_t *p) {
  uint64_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}
int main(void) {
  uint8_t out[56] = {0};
  signextendsemantics(out);
  if (load64(out+0) != UINT64_C(0x112233445566ff80)) return 10;
  if (load64(out+8) != UINT64_C(0x112233445566ffff)) return 11;
  if (load64(out+16) != UINT64_C(0x00000000ffff8001)) return 12;
  if (load64(out+24) != UINT64_C(0x00000000ffffffff)) return 13;
  if (load64(out+32) != UINT64_C(0xffffffff80000001)) return 14;
  if (load64(out+40) != UINT64_C(0xffffffffffffffff)) return 15;
  if (out[48] != 1 || out[49] != 1 || out[50] != 0 || out[51] != 1) return 16;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "accumulator_sign_extend_semantics", triple, ir, mainC, runPrefix)
}
