package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

type packedStringCompareTestSpec struct {
	op       string
	explicit bool
	mask     bool
	vector   bool
}

func go127PackedStringCompareSpecs() []packedStringCompareTestSpec {
	return []packedStringCompareTestSpec{
		{op: "PCMPESTRI", explicit: true},
		{op: "PCMPESTRM", explicit: true, mask: true},
		{op: "PCMPISTRI"},
		{op: "PCMPISTRM", mask: true},
		{op: "VPCMPESTRI", explicit: true, vector: true},
		{op: "VPCMPESTRM", explicit: true, mask: true, vector: true},
		{op: "VPCMPISTRI", vector: true},
		{op: "VPCMPISTRM", mask: true, vector: true},
	}
}

func TestAMD64PackedStringCompareGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := go127PackedStringCompareSpecs()
	if len(amd64PackedStringCompareSpecs) != len(expected) {
		t.Fatalf("packed-string grammar has %d entries, want %d", len(amd64PackedStringCompareSpecs), len(expected))
	}
	for _, want := range expected {
		got, ok := amd64PackedStringCompareSpecs[Op(want.op)]
		if !ok {
			t.Errorf("packed-string grammar omitted %s", want.op)
			continue
		}
		if got.explicitLength != want.explicit || got.maskResult != want.mask || got.vector != want.vector {
			t.Errorf("packed-string grammar %s = %+v, want explicit=%v mask=%v vector=%v", want.op, got, want.explicit, want.mask, want.vector)
		}
	}
}

func TestTranslateX86PackedStringCompareCompleteGoAssemblerForms(t *testing.T) {
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
			var source strings.Builder
			source.WriteString("TEXT packedstringcompareforms(SB),$0-0\n")
			for index, spec := range go127PackedStringCompareSpecs() {
				last := 15
				if target.goarch == "386" && !spec.vector {
					last = 7
				}
				fmt.Fprintf(&source, "\t%s $0, X1, X%d\n", spec.op, last)
				fmt.Fprintf(&source, "\t%s $255, %d(AX), X%d\n", spec.op, index*16, last)
				if spec.vector {
					fmt.Fprintf(&source, "\t%s $-128, X1, X%d\n", spec.op, last)
				}
			}
			source.WriteString("\tRET\n")

			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"packedstringcompareforms": {Name: "packedstringcompareforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, intrinsic := range []string{
				"@llvm.x86.sse42.pcmpestri128", "@llvm.x86.sse42.pcmpestrm128",
				"@llvm.x86.sse42.pcmpistri128", "@llvm.x86.sse42.pcmpistrm128",
				"@llvm.x86.sse42.pcmpestric128", "@llvm.x86.sse42.pcmpistriz128",
			} {
				if !strings.Contains(ir, intrinsic) {
					t.Fatalf("translation omitted %s:\n%s", intrinsic, ir)
				}
			}
			wantFeatures := `"target-features"="+avx,+sse4.2"`
			if !strings.Contains(ir, wantFeatures) {
				t.Fatalf("translation omitted %s:\n%s", wantFeatures, ir)
			}
			compileLLVMToObject(t, llc, target.triple, "packed-string-compare-"+target.name+".ll", "packed-string-compare-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86PackedStringCompareRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "PCMPESTRI $-1, X0, X1"},
		{goarch: "amd64", instruction: "PCMPISTRM $256, X0, X1"},
		{goarch: "amd64", instruction: "VPCMPESTRI.Z $7, X0, X1"},
		{goarch: "amd64", instruction: "VPCMPESTRI $-129, X0, X1"},
		{goarch: "amd64", instruction: "PCMPISTRI $7, Y0, X1"},
		{goarch: "amd64", instruction: "VPCMPISTRM $7, X0, X16"},
		{goarch: "386", instruction: "PCMPESTRM $7, X0, X8"},
		{goarch: "386", instruction: "VPCMPESTRM $7, X0, X16"},
	} {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", ",", "", "$", "", ".", "_").Replace(test.instruction), func(t *testing.T) {
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
				t.Fatalf("Translate accepted %q outside Go 1.27's packed-string tables", test.instruction)
			}
		})
	}
}

func TestAMD64PackedStringCompareRuntimeSemanticsAndFlags(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT packedstringcomparesemantics(SB),NOSPLIT,$0-40
	MOVQ left+0(FP), SI
	MOVOU (SI), X1
	MOVQ right+8(FP), DI
	MOVOU (DI), X2
	MOVQ out+16(FP), BX
	MOVQ lenLeft+24(FP), AX
	MOVQ lenRight+32(FP), DX

	PCMPESTRI $12, X2, X1
	MOVQ CX, 0(BX)
	SETCS 8(BX)
	SETEQ 9(BX)
	SETLT 10(BX)
	SETOS 11(BX)
	SETPS 12(BX)

	PCMPESTRM $64, X2, X1
	MOVOU X0, 16(BX)
	SETCS 32(BX)
	SETEQ 33(BX)
	SETLT 34(BX)
	SETOS 35(BX)
	SETPS 36(BX)

	VPCMPISTRI $0, X2, X1
	MOVQ CX, 40(BX)
	SETCS 48(BX)
	SETEQ 49(BX)
	SETLT 50(BX)
	SETOS 51(BX)
	SETPS 52(BX)

	VPCMPISTRM $64, X2, X1
	MOVOU X0, 56(BX)
	SETCS 72(BX)
	SETEQ 73(BX)
	SETLT 74(BX)
	SETOS 75(BX)
	SETPS 76(BX)
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
		Sigs: map[string]FuncSig{"packedstringcomparesemantics": {
			Name: "packedstringcomparesemantics", Args: []LLVMType{Ptr, Ptr, Ptr, I64, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: I64, Index: 3, Field: -1},
				{Offset: 32, Type: I64, Index: 4, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <nmmintrin.h>
#include <stdint.h>
#include <string.h>
extern void packedstringcomparesemantics(const uint8_t *, const uint8_t *, uint8_t *, uint64_t, uint64_t);
static uint64_t load64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static int flags_equal(const uint8_t *p, int c, int z, int s, int o) {
  return p[0] == c && p[1] == z && p[2] == (s ^ o) && p[3] == o && p[4] == 0;
}
__attribute__((target("sse4.2"))) static int check(void) {
  const uint8_t left[16] = {'a','b','c','d','e',0,'x','y','z',0,1,2,3,4,5,6};
  const uint8_t right[16] = {'q','q','a','b','c','d','e',0,'x',0,9,8,7,6,5,4};
  const int la = 5, lb = 9;
  uint8_t out[80] = {0}, want[16];
  __m128i a = _mm_loadu_si128((const __m128i *)left);
  __m128i b = _mm_loadu_si128((const __m128i *)right);
  packedstringcomparesemantics(left, right, out, la, lb);
  if (load64(out) != (uint64_t)_mm_cmpestri(a, la, b, lb, 12)) return 10;
  if (!flags_equal(out + 8, _mm_cmpestrc(a,la,b,lb,12), _mm_cmpestrz(a,la,b,lb,12), _mm_cmpestrs(a,la,b,lb,12), _mm_cmpestro(a,la,b,lb,12))) return 11;
  _mm_storeu_si128((__m128i *)want, _mm_cmpestrm(a,la,b,lb,64));
  if (memcmp(out + 16, want, 16)) return 12;
  if (!flags_equal(out + 32, _mm_cmpestrc(a,la,b,lb,64), _mm_cmpestrz(a,la,b,lb,64), _mm_cmpestrs(a,la,b,lb,64), _mm_cmpestro(a,la,b,lb,64))) return 13;
  if (load64(out + 40) != (uint64_t)_mm_cmpistri(a,b,0)) return 14;
  if (!flags_equal(out + 48, _mm_cmpistrc(a,b,0), _mm_cmpistrz(a,b,0), _mm_cmpistrs(a,b,0), _mm_cmpistro(a,b,0))) return 15;
  _mm_storeu_si128((__m128i *)want, _mm_cmpistrm(a,b,64));
  if (memcmp(out + 56, want, 16)) return 16;
  if (!flags_equal(out + 72, _mm_cmpistrc(a,b,64), _mm_cmpistrz(a,b,64), _mm_cmpistrs(a,b,64), _mm_cmpistro(a,b,64))) return 17;
  return 0;
}
int main(void) { return check(); }
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_string_compare_semantics", triple, ir, mainC, runPrefix)
}
