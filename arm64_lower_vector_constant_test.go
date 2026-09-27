package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64VectorConstantForms = `
TEXT vectorconstantforms(SB),$0-0
	VMOVS $0x80402010, V1
	VMOVD $0x7040201008040201, V2
	VMOVQ $0x7040201008040201, $0x3040201008040201, V3
	RET
`

func TestTranslateARM64VectorConstantCompleteGoAssemblerForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64VectorConstantForms, true)
	file, err := Parse(ArchARM64, arm64VectorConstantForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"vectorconstantforms": {Name: "vectorconstantforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"insertelement <4 x i32> zeroinitializer", "insertelement <2 x i64> zeroinitializer", "bitcast <2 x i64>"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 vector constant lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-vector-constants.ll", "arm64-vector-constants.o", ll)
		})
	}
}

func TestTranslateARM64VectorConstantRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VMOVS V0, V1",
		"VMOVS $1, V1.S4",
		"VMOVS $1, $2, V1",
		"VMOVD $1",
		"VMOVD $1, R1",
		"VMOVQ $1, V1",
		"VMOVQ $1, $2, V1, V2",
		"VMOVQ.P $1, $2, V1",
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badvectorconstant(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badvectorconstant": {Name: "badvectorconstant", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's VMOVS/VMOVD/VMOVQ table", instruction)
			}
		})
	}
}

func TestARM64VectorConstantRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT vectorconstants(SB),$0-8
	MOVD out+0(FP), R0
	VMOVS $0x80402010, V1
	VMOV V1.S[0], R1
	MOVW R1, 0(R0)
	VMOVD $0x7040201008040201, V2
	VMOV V2.D[0], R2
	VMOV V2.D[1], R3
	MOVD R2, 8(R0)
	MOVD R3, 16(R0)
	VMOVQ $0x7040201008040201, $0x3040201008040201, V4
	VMOV V4.D[0], R4
	VMOV V4.D[1], R5
	MOVD R4, 24(R0)
	MOVD R5, 32(R0)
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
			"vectorconstants": {
				Name: "vectorconstants", Args: []LLVMType{Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
struct values { uint32_t s; uint32_t pad; uint64_t d; uint64_t dzero; uint64_t qlo; uint64_t qhi; };
extern void vectorconstants(struct values *);
int main(void) {
  struct values got = {0};
  vectorconstants(&got);
  if (got.s != UINT32_C(0x80402010)) return 1;
  if (got.d != UINT64_C(0x7040201008040201) || got.dzero != 0) return 2;
  if (got.qlo != UINT64_C(0x7040201008040201)) return 3;
  if (got.qhi != UINT64_C(0x3040201008040201)) return 4;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_vector_constants", triple, ll, mainC, nil)
}
