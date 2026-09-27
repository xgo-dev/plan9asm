package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64PackedSADGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := map[Op]amd64PackedSADSpec{
		"PSADBW":    {kind: amd64PackedSADBlockSum, form: amd64PackedSADLegacyX},
		"VPSADBW":   {kind: amd64PackedSADBlockSum, form: amd64PackedSADEVEXXYZ},
		"MPSADBW":   {kind: amd64PackedSADMultiple, form: amd64PackedSADLegacyX},
		"VMPSADBW":  {kind: amd64PackedSADMultiple, form: amd64PackedSADVEXXY},
		"VDBPSADBW": {kind: amd64PackedSADDoubleBlock, form: amd64PackedSADEVEXXYZ},
	}
	if len(amd64PackedSADSpecs) != len(expected) {
		t.Fatalf("packed SAD grammar has %d entries, want %d", len(amd64PackedSADSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64PackedSADSpecs[op]; !ok {
			t.Errorf("packed SAD grammar omitted %s", op)
		} else if got != want {
			t.Errorf("packed SAD grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86MultipleSADCompleteFormsAcrossTargets(t *testing.T) {
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
			last := 15
			if target.goarch == "386" {
				last = 7
			}
			var source strings.Builder
			source.WriteString("TEXT mpsadforms(SB),$0-0\n")
			fmt.Fprintf(&source, "\tMPSADBW $7, X0, X%d\n", last)
			fmt.Fprintf(&source, "\tMPSADBW $7, 0(AX), X%d\n", last)
			if target.goarch == "amd64" {
				fmt.Fprintf(&source, "\tVMPSADBW $7, X0, X1, X%d\n", last)
				fmt.Fprintf(&source, "\tVMPSADBW $7, 16(AX), X1, X%d\n", last)
				fmt.Fprintf(&source, "\tVMPSADBW $7, Y0, Y1, Y%d\n", last)
				fmt.Fprintf(&source, "\tVMPSADBW $7, 32(AX), Y1, Y%d\n", last)
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"mpsadforms": {Name: "mpsadforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "call <8 x i16> @llvm.x86.sse41.mpsadbw") {
				t.Fatalf("MPSADBW lowering omitted the SSE4.1 intrinsic:\n%s", ir)
			}
			if target.goarch == "amd64" && !strings.Contains(ir, "call <16 x i16> @llvm.x86.avx2.mpsadbw") {
				t.Fatalf("VMPSADBW Y lowering omitted the AVX2 intrinsic:\n%s", ir)
			}
			compileLLVMToObject(t, llc, target.triple, "mpsadbw-"+target.name+".ll", "mpsadbw-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86DoubleSADCompleteFormsAcrossTargets(t *testing.T) {
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
	} {
		t.Run(target.name, func(t *testing.T) {
			last := 23
			var source strings.Builder
			source.WriteString("TEXT dbpsadforms(SB),$0-0\n")
			for _, width := range []string{"X", "Y", "Z"} {
				fmt.Fprintf(&source, "\tVDBPSADBW $0, %s0, %s1, %s%d\n", width, width, width, last)
				fmt.Fprintf(&source, "\tVDBPSADBW $85, 0(AX), %s1, %s%d\n", width, width, last)
				fmt.Fprintf(&source, "\tVDBPSADBW $170, %s2, %s1, K1, %s%d\n", width, width, width, last)
				fmt.Fprintf(&source, "\tVDBPSADBW.Z $255, 64(AX), %s1, K2, %s%d\n", width, width, last)
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"dbpsadforms": {Name: "dbpsadforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "dbpsadbw-"+target.name+".ll", "dbpsadbw-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86DoubleSADRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VDBPSADBW $-1, X0, X1, X2"},
		{goarch: "amd64", instruction: "VDBPSADBW $256, X0, X1, X2"},
		{goarch: "amd64", instruction: "VDBPSADBW.Z $1, X0, X1, X2"},
		{goarch: "amd64", instruction: "VDBPSADBW.BCST $1, 0(AX), X1, X2"},
		{goarch: "amd64", instruction: "VDBPSADBW $1, X0, Y1, Y2"},
		{goarch: "amd64", instruction: "VDBPSADBW $1, X0, X1, K0, X2"},
		{goarch: "amd64", instruction: "VDBPSADBW $1, X0, X1, K1, X2, X3"},
		{goarch: "386", instruction: "VDBPSADBW $1, X0, X1, X2"},
		{goarch: "386", instruction: "VDBPSADBW.Z $1, X0, X1, K1, X2"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's VDBPSADBW table", test.instruction)
			}
		})
	}
}

func TestTranslateX86MultipleSADRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "MPSADBW $-1, X0, X1"},
		{goarch: "amd64", instruction: "MPSADBW $256, X0, X1"},
		{goarch: "amd64", instruction: "MPSADBW.Z $1, X0, X1"},
		{goarch: "amd64", instruction: "MPSADBW $1, Y0, Y1"},
		{goarch: "amd64", instruction: "VMPSADBW $1, Z0, Z1, Z2"},
		{goarch: "amd64", instruction: "VMPSADBW $1, X0, Y1, Y2"},
		{goarch: "386", instruction: "MPSADBW $1, X0, X8"},
		{goarch: "386", instruction: "VMPSADBW $1, X0, X1, X2"},
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
			if _, err := Translate(file, Options{Goarch: test.goarch, TargetTriple: triple, Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside the Go table for %s", test.instruction, test.goarch)
			}
		})
	}
}

func TestTranslateX86PackedSADRejects386OutOfRangeForms(t *testing.T) {
	for _, instruction := range []string{
		"PSADBW X0, X8",
		"PSADBW 8(R9), X0",
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, "386", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				Goarch:       "386",
				TargetTriple: "i386-unknown-linux-gnu",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside the Go 386 SAD tables", instruction)
			}
		})
	}
}

func TestAMD64MultipleSADRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT mpsadsemantics(SB),$0-24
	MOVQ out+0(FP), AX
	MOVQ a+8(FP), CX
	MOVQ b+16(FP), DX
	MOVUPS 0(CX), X1
	MOVUPS 0(DX), X0
	STC
	MPSADBW $0, X0, X1
	MOVUPS X1, 0(AX)
	SETCS 16(AX)
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
		Sigs: map[string]FuncSig{"mpsadsemantics": {
			Name: "mpsadsemantics", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
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
extern void mpsadsemantics(uint8_t *, const uint8_t *, const uint8_t *);
int main(void) {
  uint8_t out[17] = {0};
  const uint8_t a[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  const uint8_t b[16] = {0};
  const uint16_t want[8] = {6, 10, 14, 18, 22, 26, 30, 34};
  uint16_t got[8];
  mpsadsemantics(out, a, b);
  memcpy(got, out, 16);
  for (int i = 0; i < 8; i++) if (got[i] != want[i]) return 10 + i;
  if (out[16] != 1) return 20;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "multiple_sad_semantics", triple, ir, mainC, runPrefix)
}

func TestAMD64DoubleSADRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT dbpsadsemantics(SB),$0-40
	MOVQ out+0(FP), AX
	MOVQ a+8(FP), CX
	MOVQ b+16(FP), DX
	MOVQ old+24(FP), R8
	MOVQ mask+32(FP), R9
	KMOVQ R9, K1
	VMOVDQU8 0(CX), Z1
	VMOVDQU8 0(DX), Z0
	VMOVDQU16 0(R8), Z2
	STC
	VDBPSADBW $27, Z0, Z1, K1, Z2
	VMOVDQU16 Z2, 0(AX)
	VDBPSADBW.Z $228, Z0, Z1, K1, Z3
	VMOVDQU16 Z3, 64(AX)
	SETCS 128(AX)
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
		Goarch: "amd64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"dbpsadsemantics": {
			Name: "dbpsadsemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: Ptr, Index: 3, Field: -1},
				{Offset: 32, Type: I64, Index: 4, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void dbpsadsemantics(uint8_t *, const uint8_t *, const uint8_t *, const uint16_t *, uint64_t);
static void oracle(uint16_t *out, const uint8_t *src1, const uint8_t *src2, const uint16_t *old, unsigned imm, uint64_t mask, int zeroing) {
  uint8_t shuffled[64];
  for (int lane = 0; lane < 64; lane += 16)
    for (int dword = 0; dword < 4; dword++)
      for (int byte = 0; byte < 4; byte++)
        shuffled[lane + dword * 4 + byte] = src2[lane + ((imm >> (2 * dword)) & 3) * 4 + byte];
  for (int block = 0; block < 64; block += 8) {
    for (int word = 0; word < 4; word++) {
      unsigned sum = 0;
      int src1_base = block + (word >= 2 ? 4 : 0);
      int shuffled_base = block + word;
      for (int byte = 0; byte < 4; byte++) {
        int difference = (int)src1[src1_base + byte] - (int)shuffled[shuffled_base + byte];
        sum += difference < 0 ? -difference : difference;
      }
      int index = block / 2 + word;
      out[index] = (mask >> index) & 1 ? (uint16_t)sum : (zeroing ? 0 : old[index]);
    }
  }
}
int main(void) {
  uint8_t a[64], b[64], bytes[129] = {0}; uint16_t old[32], got[64], want[64];
  for (int i = 0; i < 64; i++) { a[i] = (uint8_t)(i * 7 + 3); b[i] = (uint8_t)(255 - i * 5); }
  for (int i = 0; i < 32; i++) old[i] = (uint16_t)(1000 + i);
  uint64_t mask = UINT64_C(0xa55aa55a);
  dbpsadsemantics(bytes, a, b, old, mask);
  memcpy(got, bytes, 128);
  oracle(want, a, b, old, 27, mask, 0);
  oracle(want + 32, a, b, old, 228, mask, 1);
  for (int i = 0; i < 64; i++) if (got[i] != want[i]) return 10 + i;
  if (bytes[128] != 1) return 80;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "double_sad_semantics", triple, ir, mainC, runPrefix)
}
