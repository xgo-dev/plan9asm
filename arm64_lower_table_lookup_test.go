package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64VectorTableLookupCompleteGoAssemblerForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT vectortablelookupforms(SB),$0-0\n")
	for _, op := range []string{"VTBL", "VTBX"} {
		for _, arrangement := range []string{"B8", "B16"} {
			for _, tableArrangement := range []string{"B8", "B16", "H4", "H8", "S2", "S4", "D1", "D2"} {
				for count := 1; count <= 4; count++ {
					fmt.Fprintf(&source, "\t%s V8.%s, %s, V9.%s\n", op, arrangement, arm64TestVectorList(30, count, tableArrangement), arrangement)
				}
			}
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"vectortablelookupforms": {Name: "vectortablelookupforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"icmp ult i32", "extractelement", "insertelement", "select i1"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 vector table lookup lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-vector-table-lookup.ll", "arm64-vector-table-lookup.o", ll)
		})
	}
}

func TestTranslateARM64VectorTableLookupRejectsInvalidForms(t *testing.T) {
	for _, instruction := range []string{
		"VTBL V0.B16, [V1.B16, V3.B16], V4.B16",
		"VTBL V0.B16, [V1.B8, V2.H8], V4.B16",
		"VTBX V0.B8, [V1.B16], V4.B16",
		"VTBL V0.H8, [V1.B16], V4.H8",
		"VTBL V0.B16, [V1.B16, V2.B16, V3.B16, V4.B16, V5.B16], V6.B16",
		"VTBL.P V0.B16, [V1.B16], V4.B16",
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badvectortablelookup(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64",
				Sigs: map[string]FuncSig{"badvectortablelookup": {Name: "badvectortablelookup", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted invalid vector table lookup form %q", instruction)
			}
		})
	}
}

func TestARM64VectorTableLookupRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT vectortablelookup(SB),$0-32
	MOVD table+0(FP), R0
	MOVD indices+8(FP), R1
	MOVD initial+16(FP), R2
	MOVD out+24(FP), R3
	VLD1 (R0), [V0.B16, V1.B16, V2.B16, V3.B16]
	VLD1 (R1), [V4.B16]
	VTBL V4.B16, [V0.B16, V1.B16, V2.B16, V3.B16], V5.B16
	VST1.P [V5.B16], 16(R3)
	VLD1 (R2), [V6.B16]
	VTBX V4.B16, [V0.B16, V1.B16, V2.B16, V3.B16], V6.B16
	VST1 [V6.B16], (R3)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple, Goarch: "arm64",
		Sigs: map[string]FuncSig{
			"vectortablelookup": {
				Name: "vectortablelookup", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
					{Offset: 24, Type: Ptr, Index: 3, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void vectortablelookup(const uint8_t *, const uint8_t *, const uint8_t *, uint8_t *);
int main(void) {
  uint8_t table[64], initial[16], got[32] = {0};
  const uint8_t indices[16] = {0,15,16,31,32,47,48,63,64,255,7,23,39,55,62,1};
  for (int i = 0; i < 64; i++) table[i] = (uint8_t)(10+i);
  for (int i = 0; i < 16; i++) initial[i] = (uint8_t)(200+i);
  vectortablelookup(table, indices, initial, got);
  for (int i = 0; i < 16; i++) {
    uint8_t tbl = indices[i] < 64 ? table[indices[i]] : 0;
    uint8_t tbx = indices[i] < 64 ? table[indices[i]] : initial[i];
    if (got[i] != tbl) return i + 1;
    if (got[16+i] != tbx) return i + 21;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_vector_table_lookup", triple, ll, mainC, nil)
}
