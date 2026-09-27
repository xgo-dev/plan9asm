package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64VectorTestGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := map[Op]amd64VectorTestSpec{
		"PTEST":   {maxBytes: 16},
		"VPTEST":  {maxBytes: 32, vector: true},
		"VTESTPD": {maxBytes: 32, vector: true, signLaneBits: 64},
		"VTESTPS": {maxBytes: 32, vector: true, signLaneBits: 32},
	}
	if len(amd64VectorTestSpecs) != len(expected) {
		t.Fatalf("vector-test grammar has %d entries, want %d", len(amd64VectorTestSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64VectorTestSpecs[op]; !ok {
			t.Errorf("vector-test grammar omitted %s", op)
		} else if got != want {
			t.Errorf("vector-test grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86VectorTestCompleteGoFormsAcrossTargets(t *testing.T) {
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
			legacyLast := 15
			if target.goarch == "386" {
				legacyLast = 7
			}
			source := fmt.Sprintf(`TEXT vectortestforms(SB),$0-0
	PTEST X0, X%d
	PTEST 0(AX), X%d
	VPTEST X0, X15
	VPTEST 16(R9), X15
	VPTEST Y0, Y15
	VPTEST 32(R9), Y15
	VTESTPD X0, X15
	VTESTPD 48(R9), X15
	VTESTPD Y0, Y15
	VTESTPD 64(R9), Y15
	VTESTPS X0, X15
	VTESTPS 80(R9), X15
	VTESTPS Y0, Y15
	VTESTPS 96(R9), Y15
	RET
`, legacyLast, legacyLast)
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs: map[string]FuncSig{
					"vectortestforms": {Name: "vectortestforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"<16 x i8>", "<32 x i8>", "store i1"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("vector-test lowering omitted %q:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "vector-test-"+target.name+".ll", "vector-test-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86VectorTestRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "PTEST Y0, Y1"},
		{goarch: "amd64", instruction: "PTEST X0, 0(AX)"},
		{goarch: "amd64", instruction: "PTEST X16, X0"},
		{goarch: "amd64", instruction: "PTEST.Z X0, X1"},
		{goarch: "386", instruction: "PTEST X8, X0"},
		{goarch: "386", instruction: "PTEST 0(R9), X0"},
		{goarch: "amd64", instruction: "VPTEST X0, Y1"},
		{goarch: "amd64", instruction: "VPTEST Z0, Z1"},
		{goarch: "amd64", instruction: "VPTEST X16, X0"},
		{goarch: "amd64", instruction: "VPTEST.Z X0, X1"},
		{goarch: "amd64", instruction: "VTESTPD X0, Y1"},
		{goarch: "amd64", instruction: "VTESTPD Z0, Z1"},
		{goarch: "amd64", instruction: "VTESTPS X16, X0"},
		{goarch: "amd64", instruction: "VTESTPS X0, X1, X2"},
	} {
		t.Run(test.goarch+"/"+strings.NewReplacer(" ", "_", ",", "", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
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
				t.Fatalf("Translate accepted %q outside the Go 1.27 vector-test tables", test.instruction)
			}
		})
	}
}

func TestAMD64VectorTestRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT vectortestsemantics(SB),$0-24
	MOVQ out+0(FP), CX
	MOVQ source+8(FP), AX
	MOVQ destination+16(FP), BX
	MOVUPS 0(AX), X0
	MOVUPS 0(BX), X1
	MOVB $0x7f, DL
	ADDB $1, DL
	PTEST X0, X1
	SETEQ 0(CX)
	SETCS 1(CX)
	SETMI 2(CX)
	SETOS 3(CX)
	SETPS 4(CX)

	MOVQ source+8(FP), AX
	MOVQ destination+16(FP), BX
	VMOVDQU 32(BX), Y1
	XORB DL, DL
	VPTEST 32(AX), Y1
	SETEQ 5(CX)
	SETCS 6(CX)
	SETMI 7(CX)
	SETOS 8(CX)
	SETPS 9(CX)

	MOVQ source+8(FP), AX
	MOVQ destination+16(FP), BX
	MOVUPS 64(BX), X1
	VTESTPS 64(AX), X1
	SETEQ 10(CX)
	SETCS 11(CX)
	SETMI 12(CX)
	SETOS 13(CX)
	SETPS 14(CX)

	MOVQ source+8(FP), AX
	MOVQ destination+16(FP), BX
	VMOVDQU 96(BX), Y1
	VTESTPD 96(AX), Y1
	SETEQ 15(CX)
	SETCS 16(CX)
	SETMI 17(CX)
	SETOS 18(CX)
	SETPS 19(CX)
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
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
		Sigs: map[string]FuncSig{"vectortestsemantics": {
			Name: "vectortestsemantics", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void vectortestsemantics(uint8_t *, const uint8_t *, const uint8_t *);
int main(void) {
  uint8_t source[128] = {0}, destination[128] = {0}, out[20] = {0};
  source[0] = 1;
  source[32] = 1; destination[32] = 1;
  source[64] = 1; destination[64] = 1;
  source[103] = 0x80;
  vectortestsemantics(out, source, destination);
  const uint8_t want[20] = {
    1, 0, 0, 0, 0,
    0, 1, 0, 0, 0,
    1, 1, 0, 0, 0,
    1, 0, 0, 0, 0,
  };
  for (int i = 0; i < 20; i++) if (out[i] != want[i]) return 10 + i;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "vector_test_semantics", triple, ir, mainC, runPrefix)

	// Exercise the raw-byte path with the same independently checked flag
	// oracle. Keep the displacements and operand order identical to the named
	// Go source above, including both 128-bit and 256-bit memory forms.
	rawSource := strings.NewReplacer(
		"PTEST X0, X1", "BYTE $0x66\n\tBYTE $0x0f\n\tBYTE $0x38\n\tBYTE $0x17\n\tBYTE $0xc8",
		"VPTEST 32(AX), Y1", "BYTE $0xc4\n\tBYTE $0xe2\n\tBYTE $0x7d\n\tBYTE $0x17\n\tBYTE $0x48\n\tBYTE $0x20",
		"VTESTPS 64(AX), X1", "BYTE $0xc4\n\tBYTE $0xe2\n\tBYTE $0x79\n\tBYTE $0x0e\n\tBYTE $0x48\n\tBYTE $0x40",
		"VTESTPD 96(AX), Y1", "BYTE $0xc4\n\tBYTE $0xe2\n\tBYTE $0x7d\n\tBYTE $0x0f\n\tBYTE $0x48\n\tBYTE $0x60",
	).Replace(source)
	requireX86GoAssemblerResult(t, "amd64", rawSource, true)
	rawFile, err := Parse(ArchAMD64, rawSource)
	if err != nil {
		t.Fatal(err)
	}
	rawIR, err := Translate(rawFile, Options{
		Goarch:       "amd64",
		TargetTriple: triple,
		Sigs: map[string]FuncSig{"vectortestsemantics": {
			Name: "vectortestsemantics", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "raw_vector_test_semantics", triple, rawIR, mainC, runPrefix)
}
