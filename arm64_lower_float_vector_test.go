package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64VectorFMACompleteGoAssemblerForms(t *testing.T) {
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, `
TEXT vectorfmaforms(SB),NOSPLIT,$0-0
	VFMLA V0.S2, V1.S2, V2.S2
	VFMLA V3.S4, V4.S4, V5.S4
	VFMLA V6.D2, V7.D2, V8.D2
	VFMLS V9.S2, V10.S2, V11.S2
	VFMLS V12.S4, V13.S4, V14.S4
	VFMLS V15.D2, V16.D2, V31.D2
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"vectorfmaforms": {Name: "vectorfmaforms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"@llvm.fma.v2f32", "@llvm.fma.v4f32", "@llvm.fma.v2f64"} {
			if !strings.Contains(ll, want) {
				t.Fatalf("ARM64 vector FMA for %s omitted %s:\n%s", triple, want, ll)
			}
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-fma.ll", "arm64-vector-fma.o", ll)
	}
}

func TestTranslateARM64VectorFMARejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"VFMLA V0.S2, V1.S2",
		"VFMLS V0.S2, V1.S2, V2.S2, V3.S2",
		"VFMLA V0.D2, V1.D2, V2.S2",
		"VFMLA V0.S2, V1.S4, V2.S2",
		"VFMLS V0.B16, V1.B16, V2.B16",
		"VFMLS V0.H8, V1.H8, V2.H8",
		"VFMLA V0.S[0], V1.S2, V2.S2",
		"VFMLA.P V0.S4, V1.S4, V2.S4",
	} {
		file, err := Parse(ArchARM64, "TEXT badvectorfma(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"badvectorfma": {Name: "badvectorfma", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's VFMLA/VFMLS optab", instruction)
		}
	}
}

func TestTranslateARM64VectorIntegerAddSubCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT vectorintegeraddsubforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"VADD", "VSUB"} {
		for i, arrangement := range []string{"B8", "B16", "H4", "H8", "S2", "S4", "D2"} {
			src.WriteString("\t" + op + " V0." + arrangement + ", V1." + arrangement + ", V" + string(rune('2'+i)) + "." + arrangement + "\n")
		}
		src.WriteString("\t" + op + " V12, V30\n")
		src.WriteString("\t" + op + " V12, V20, V31\n")
	}
	src.WriteString("\tRET\n")
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, src.String())
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"vectorintegeraddsubforms": {Name: "vectorintegeraddsubforms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-integer-add-sub.ll", "arm64-vector-integer-add-sub.o", ll)
	}
}

func TestTranslateARM64VectorIntegerAddSubRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"VADD V0.B8, V1.B8",
		"VSUB V0.B8, V1.B8, V2.B8, V3.B8",
		"VADD V0.B8, V1.B16, V2.B8",
		"VSUB V0.D1, V1.D1, V2.D1",
		"VADD V0.F4, V1.F4, V2.F4",
		"VSUB V0.S[0], V1.S2, V2.S2",
		"VADD V0, V1, V2, V3",
		"VSUB V0.S4, V1, V2.S4",
		"VADD.P V0.S4, V1.S4, V2.S4",
	} {
		file, err := Parse(ArchARM64, "TEXT badvectorintegeraddsub(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"badvectorintegeraddsub": {Name: "badvectorintegeraddsub", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's VADD/VSUB optab", instruction)
		}
	}
}

func TestTranslateARM64AddAcrossCompleteGoAssemblerForms(t *testing.T) {
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, `
TEXT addacrossforms(SB),NOSPLIT,$0-0
	VADDV V0.B8, V1
	VADDV V2.B16, V3
	VADDV V4.H4, V5
	VADDV V6.H8, V7
	VADDV V30.S4, V31
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"addacrossforms": {Name: "addacrossforms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-add-across.ll", "arm64-add-across.o", ll)
	}
}

func TestTranslateARM64AddAcrossRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"VADDV V0.B8",
		"VADDV V0.B8, V1, V2",
		"VADDV V0.S2, V1",
		"VADDV V0.D2, V1",
		"VADDV V0.B16, V1.B16",
		"VADDV V0, V1",
		"VADDV.P V0.S4, V1",
	} {
		file, err := Parse(ArchARM64, "TEXT badaddacross(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"badaddacross": {Name: "badaddacross", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's VADDV optab", instruction)
		}
	}
}

func TestTranslateARM64VectorFloatArithmeticCompleteGoAssemblerForms(t *testing.T) {
	ops := []string{
		"VFADD", "VFSUB", "VFMUL", "VFDIV",
		"VFMAX", "VFMAXNM", "VFMIN", "VFMINNM",
		"VFADDP", "VFMAXP", "VFMAXNMP", "VFMINP", "VFMINNMP",
	}
	var src strings.Builder
	src.WriteString("TEXT vectorfloatarithmeticforms(SB),NOSPLIT,$0-0\n")
	for _, op := range ops {
		for _, arrangement := range []string{"S2", "S4", "D2"} {
			src.WriteString("\t" + op + " V0." + arrangement + ", V1." + arrangement + ", V31." + arrangement + "\n")
		}
	}
	src.WriteString("\tRET\n")
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, src.String())
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"vectorfloatarithmeticforms": {Name: "vectorfloatarithmeticforms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-float-arithmetic.ll", "arm64-vector-float-arithmetic.o", ll)
	}
}

func TestTranslateARM64VectorFloatArithmeticRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, op := range []string{
		"VFADD", "VFSUB", "VFMUL", "VFDIV",
		"VFMAX", "VFMAXNM", "VFMIN", "VFMINNM",
		"VFADDP", "VFMAXP", "VFMAXNMP", "VFMINP", "VFMINNMP",
	} {
		for _, operands := range []string{
			"V0.S4, V1.S4",
			"V0.H4, V1.H4, V2.H4",
			"V0.S2, V1.S4, V2.S2",
			"V0.S[0], V1.S2, V2.S2",
		} {
			instruction := op + " " + operands
			file, err := Parse(ArchARM64, "TEXT badvectorfloatarithmetic(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badvectorfloatarithmetic": {Name: "badvectorfloatarithmetic", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's vector floating arithmetic optab", instruction)
			}
		}
	}
}

func TestTranslateARM64VectorFloatUnaryCompleteGoAssemblerForms(t *testing.T) {
	ops := []string{
		"VFABS", "VFNEG", "VFSQRT",
		"VFRINTN", "VFRINTP", "VFRINTM", "VFRINTZ",
		"VFCVTZS", "VFCVTZU", "VSCVTF", "VUCVTF",
	}
	var src strings.Builder
	src.WriteString("TEXT vectorfloatunaryforms(SB),NOSPLIT,$0-0\n")
	for _, op := range ops {
		for _, arrangement := range []string{"S2", "S4", "D2"} {
			src.WriteString("\t" + op + " V0." + arrangement + ", V31." + arrangement + "\n")
		}
	}
	src.WriteString("\tRET\n")
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, src.String())
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"vectorfloatunaryforms": {Name: "vectorfloatunaryforms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-float-unary.ll", "arm64-vector-float-unary.o", ll)
	}
}

func TestTranslateARM64VectorFloatUnaryRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, op := range []string{
		"VFABS", "VFNEG", "VFSQRT",
		"VFRINTN", "VFRINTP", "VFRINTM", "VFRINTZ",
		"VFCVTZS", "VFCVTZU", "VSCVTF", "VUCVTF",
	} {
		for _, operands := range []string{
			"V0.S4",
			"V0.H4, V1.H4",
			"V0.S2, V1.S4",
			"V0.S[0], V1.S2",
		} {
			instruction := op + " " + operands
			file, err := Parse(ArchARM64, "TEXT badvectorfloatunary(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badvectorfloatunary": {Name: "badvectorfloatunary", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's vector floating unary optab", instruction)
			}
		}
	}
}

func TestTranslateARM64VectorShiftRightCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT vectorshiftrightforms(SB),$0-0\n")
	for _, form := range []struct {
		arrangement string
		width       string
	}{
		{arrangement: "B8", width: "8"},
		{arrangement: "B16", width: "8"},
		{arrangement: "H4", width: "16"},
		{arrangement: "H8", width: "16"},
		{arrangement: "S2", width: "32"},
		{arrangement: "S4", width: "32"},
		{arrangement: "D2", width: "64"},
	} {
		for _, op := range []string{"VUSHR", "VSSHR", "VSRSHR", "VUSRA"} {
			src.WriteString("\t" + op + " $1, V0." + form.arrangement + ", V1." + form.arrangement + "\n")
			src.WriteString("\t" + op + " $" + form.width + ", V30." + form.arrangement + ", V31." + form.arrangement + "\n")
		}
	}
	src.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, src.String(), true)
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, src.String())
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"vectorshiftrightforms": {Name: "vectorshiftrightforms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-signed-shift-right.ll", "arm64-vector-signed-shift-right.o", ll)
	}
}

func TestTranslateARM64VectorShiftRightRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"VSSHR V0.S4, V1.S4",
		"VSSHR $0, V0.S4, V1.S4",
		"VSSHR $33, V0.S4, V1.S4",
		"VUSHR $0, V0.B8, V1.B8",
		"VSRSHR $65, V0.D2, V1.D2",
		"VUSRA $17, V0.H8, V1.H8",
		"VSSHR $9, V0.B16, V1.B16",
		"VSSHR $1, V0.S2, V1.S4",
		"VSSHR $1, V0.D1, V1.D1",
		"VSSHR.P $1, V0.S4, V1.S4",
	} {
		source := "TEXT badvectorshiftright(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"badvectorshiftright": {Name: "badvectorshiftright", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's vector shift-right optab", instruction)
		}
	}
}

func TestTranslateARM64VectorIntegerCompareCompleteGoAssemblerForms(t *testing.T) {
	arrangements := []string{"B8", "B16", "H4", "H8", "S2", "S4", "D2"}
	var src strings.Builder
	src.WriteString("TEXT vectorintegercompareforms(SB),$0-0\n")
	for _, op := range []string{"VCMEQ", "VCMGE", "VCMGT", "VCMHI", "VCMHS"} {
		for _, arrangement := range arrangements {
			src.WriteString("\t" + op + " V0." + arrangement + ", V1." + arrangement + ", V31." + arrangement + "\n")
		}
	}
	for _, arrangement := range arrangements {
		src.WriteString("\tVCMTST V0." + arrangement + ", V1." + arrangement + ", V31." + arrangement + "\n")
	}
	for _, op := range []string{"VCMEQ", "VCMGE", "VCMGT", "VCMLE", "VCMLT"} {
		for _, arrangement := range arrangements {
			src.WriteString("\t" + op + " $0, V30." + arrangement + ", V31." + arrangement + "\n")
		}
	}
	src.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, src.String(), true)
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, src.String())
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"vectorintegercompareforms": {Name: "vectorintegercompareforms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-integer-compare.ll", "arm64-vector-integer-compare.o", ll)
	}
}

func TestTranslateARM64VectorIntegerCompareRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"VCMEQ V0, V1, V2",
		"VCMEQ V0.S4, V1.S4",
		"VCMGE V0.S2, V1.S4, V2.S2",
		"VCMGT V0.D1, V1.D1, V2.D1",
		"VCMLE V0.S4, V1.S4, V2.S4",
		"VCMLT V0.S4, V1.S4, V2.S4",
		"VCMEQ $1, V0.S4, V1.S4",
		"VCMGT $-1, V0.S4, V1.S4",
		"VCMHI $0, V0.S4, V1.S4",
		"VCMHS V0.S4, V1.S4",
		"VCMLE $0, V0.S2, V1.S4",
		"VCMLT.P $0, V0.S4, V1.S4",
		"VCMTST V0.S4, V1.S4",
		"VCMTST V0.S2, V1.S4, V2.S2",
		"VCMTST $0, V0.S4, V1.S4",
	} {
		source := "TEXT badvectorintegercompare(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"badvectorintegercompare": {Name: "badvectorintegercompare", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's vector integer compare optab", instruction)
		}
	}
}

func TestARM64VectorTestBitsRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT vectortestbits(SB),$0-24
	MOVD first+0(FP), R0
	MOVD second+8(FP), R1
	MOVD output+16(FP), R2
	VLD1 (R0), [V0.B16]
	VLD1 (R1), [V1.B16]
	VCMTST V0.B16, V1.B16, V2.B16
	VCMTST V0.H8, V1.H8, V3.H8
	VCMTST V0.S4, V1.S4, V4.S4
	VCMTST V0.D2, V1.D2, V5.D2
	VST1 [V2.B16, V3.B16, V4.B16, V5.B16], (R2)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple, Goarch: "arm64",
		Sigs: map[string]FuncSig{"vectortestbits": {
			Name: "vectortestbits", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
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
extern void vectortestbits(const uint8_t *, const uint8_t *, uint8_t *);
int main(void) {
  const uint8_t first[16]  = {1,2,4,8, 1,2,4,8, 1,2,4,8, 1,2,4,8};
  const uint8_t second[16] = {1,1,1,1, 2,2,2,2, 4,4,4,4, 8,8,8,8};
  uint8_t got[64] = {0};
  uint8_t want[64] = {0};
  vectortestbits(first, second, got);
  for (int lane = 0; lane < 16; lane++) want[lane] = (first[lane] & second[lane]) ? 255 : 0;
  for (int width = 2; width <= 8; width *= 2) {
    int block = width == 2 ? 16 : width == 4 ? 32 : 48;
    for (int lane = 0; lane < 16 / width; lane++) {
      int nonzero = 0;
      for (int byte = 0; byte < width; byte++) nonzero |= first[lane * width + byte] & second[lane * width + byte];
      memset(want + block + lane * width, nonzero ? 255 : 0, width);
    }
  }
  for (int i = 0; i < 64; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_vector_test_bits", triple, ir, mainC, nil)
}

func TestTranslateARM64VectorLogicalCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT vectorlogicalforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"VAND", "VORR", "VEOR", "VBIC", "VORN", "VBSL", "VBIT", "VBIF"} {
		for _, arrangement := range []string{"B8", "B16"} {
			src.WriteString("\t" + op + " V0." + arrangement + ", V1." + arrangement + ", V31." + arrangement + "\n")
		}
	}
	src.WriteString("\tRET\n")
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, src.String())
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"vectorlogicalforms": {Name: "vectorlogicalforms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-logical.ll", "arm64-vector-logical.o", ll)
	}
}

func TestTranslateARM64VectorLogicalRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, op := range []string{"VAND", "VORR", "VEOR", "VBIC", "VORN", "VBSL", "VBIT", "VBIF"} {
		for _, operands := range []string{
			"V0.B16, V1.B16",
			"V0.H8, V1.H8, V2.H8",
			"V0.B8, V1.B16, V2.B8",
			"V0, V1, V2",
		} {
			instruction := op + " " + operands
			file, err := Parse(ArchARM64, "TEXT badvectorlogical(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badvectorlogical": {Name: "badvectorlogical", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's vector logical optab", instruction)
			}
		}
	}
}

func TestTranslateARM64VectorFloatWidenCompleteGoAssemblerForms(t *testing.T) {
	const source = `
TEXT vectorfloatwidenforms(SB),$0-0
	VFCVTL V0.S2, V31.D2
	VFCVTL2 V30.S4, V1.D2
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"vectorfloatwidenforms": {Name: "vectorfloatwidenforms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(ll, "fpext <2 x float>") {
			t.Fatalf("ARM64 VFCVTL family omitted vector fpext:\n%s", ll)
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "arm64-vector-float-widen.ll", "arm64-vector-float-widen.o", ll)
	}
}

func TestTranslateARM64VectorFloatWidenRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"VFCVTL V0.S2",
		"VFCVTL V0.S4, V1.D2",
		"VFCVTL2 V0.S2, V1.D2",
		"VFCVTL V0.H4, V1.S4",
		"VFCVTL2 V0.S4, V1.S4",
		"VFCVTL.P V0.S2, V1.D2",
	} {
		file, err := Parse(ArchARM64, "TEXT badvectorfloatwiden(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"badvectorfloatwiden": {Name: "badvectorfloatwiden", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's VFCVTL/VFCVTL2 optab", instruction)
		}
	}
}
