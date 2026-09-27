package plan9asm

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64LegacyMMXMoveGrammarIsComplete(t *testing.T) {
	want := map[Op]amd64LegacyMMXMoveSpec{
		"MOVQOZX": {source: amd64LegacyMMXMMX | amd64LegacyMMXXMM | amd64LegacyMMXMemory, destination: amd64LegacyMMXXMM, transferBits: 64, zeroExtend: true},
		"MOVDQ2Q": {source: amd64LegacyMMXXMM, destination: amd64LegacyMMXMMX, transferBits: 64},
		"MOVNTQ":  {source: amd64LegacyMMXMMX, destination: amd64LegacyMMXMemory, transferBits: 64, nonTemporal: true},
		"MOVNTDQ": {source: amd64LegacyMMXXMM, destination: amd64LegacyMMXMemory, transferBits: 128, nonTemporal: true},
	}
	if !reflect.DeepEqual(amd64LegacyMMXMoveSpecs, want) {
		t.Fatalf("legacy MMX move grammar = %+v, want %+v", amd64LegacyMMXMoveSpecs, want)
	}
}

func TestTranslateX86LegacyMMXCompleteGoAssemblerForms(t *testing.T) {
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
			base := "BX"
			xreg := "X7"
			if target.goarch == "amd64" {
				base = "R11"
				xreg = "X15"
			}
			source := `TEXT legacymmxforms(SB),$0-0
	PSHUFW $-128, M1, M2
	PSHUFW $127, 8(BX), M3
	MOVQOZX M2, X2
	MOVQOZX X1, X3
	MOVQOZX 16(BX), X4
	MOVNTQ M2, 24(BX)
` + "\tMOVQOZX M3, " + xreg + "\n" +
				"\tMOVNTQ M3, 32(" + base + ")\n\tRET\n"
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"legacymmxforms": {Name: "legacymmxforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"!nontemporal !0", "!0 = !{i32 1}"} {
				if !strings.Contains(ir, want) {
					t.Errorf("IR is missing %s:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "legacy-mmx-"+target.name+".ll", "legacy-mmx-"+target.name+".o", ir)
		})
	}
}

func TestAMD64LegacyMMXRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT legacymmxsemantics(SB),NOSPLIT,$0-16
	MOVQ value+0(FP), AX
	MOVQ AX, M1
	MOVQ out+8(FP), DI
	PSHUFW $0x1b, M1, M2
	MOVNTQ M2, 0(DI)
	MOVQOZX M2, X1
	MOVDQ2Q X1, M3
	MOVNTQ M3, 8(DI)
	MOVNTDQ X1, 16(DI)
	SFENCE
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
		Goarch: "amd64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"legacymmxsemantics": {
			Name: "legacymmxsemantics", Args: []LLVMType{I64, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: I64, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void legacymmxsemantics(uint64_t, uint8_t *);
static uint64_t load64(const uint8_t *p) {
  uint64_t value;
  memcpy(&value, p, sizeof(value));
  return value;
}
int main(void) {
  __attribute__((aligned(16))) uint8_t out[32] = {0xff};
  legacymmxsemantics(UINT64_C(0x1122334455667788), out);
  const uint64_t shuffled = UINT64_C(0x7788556633441122);
  if (load64(out) != shuffled) return 10;
  if (load64(out + 8) != shuffled) return 11;
  if (load64(out + 16) != shuffled) return 12;
  if (load64(out + 24) != 0) return 13;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "legacy_mmx_semantics", triple, ir, mainC, runPrefix)
}

func TestTranslateX86LegacyMMXEncoderAliases(t *testing.T) {
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
			const source = `TEXT encoderaliases(SB),$0-0
	MOVDQ2Q X1, M1
	MOVNTDQ X2, 8(BX)
	RET
`
			// Go accepts these Intel decoder names in addition to the MOVQ and
			// MOVNTO spellings used by its primary optab entries.
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"encoderaliases": {Name: "encoderaliases", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "legacy-mmx-alias-"+target.name+".ll", "legacy-mmx-alias-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86LegacyMMXRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "PSHUFW $-129, M1, M2"},
		{goarch: "amd64", instruction: "PSHUFW $128, M1, M2"},
		{goarch: "amd64", instruction: "PSHUFW $1, X1, M2"},
		{goarch: "amd64", instruction: "PSHUFW $1, M1, X2"},
		{goarch: "amd64", instruction: "PSHUFW.Z $1, M1, M2"},
		{goarch: "amd64", instruction: "MOVQOZX M1, M2"},
		{goarch: "amd64", instruction: "MOVQOZX $1, X2"},
		{goarch: "amd64", instruction: "MOVNTQ X1, 8(BX)"},
		{goarch: "amd64", instruction: "MOVNTQ M1, M2"},
		{goarch: "amd64", instruction: "MOVDQ2Q M1, X1"},
		{goarch: "amd64", instruction: "MOVNTDQ 8(BX), X1"},
		{goarch: "386", instruction: "MOVQOZX M1, X8"},
		{goarch: "386", instruction: "MOVNTQ M1, 8(R11)"},
	} {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "$", "", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
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
				Goarch: test.goarch, TargetTriple: triple,
				Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside the legacy MMX grammar", test.instruction)
			}
		})
	}
}
