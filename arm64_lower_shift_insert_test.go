package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64VectorShiftInsertCompleteGoAssemblerForms(t *testing.T) {
	forms := []struct {
		arrangement string
		bits        int
	}{{"B8", 8}, {"B16", 8}, {"H4", 16}, {"H8", 16}, {"S2", 32}, {"S4", 32}, {"D2", 64}}
	var source strings.Builder
	source.WriteString("TEXT vectorshiftinsertforms(SB),$0-0\n")
	for _, form := range forms {
		for _, shift := range []int{1, form.bits} {
			fmt.Fprintf(&source, "\tVSRI $%d, V0.%s, V1.%s\n", shift, form.arrangement, form.arrangement)
		}
		for _, shift := range []int{0, form.bits - 1} {
			fmt.Fprintf(&source, "\tVSLI $%d, V2.%s, V3.%s\n", shift, form.arrangement, form.arrangement)
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
				Sigs: map[string]FuncSig{"vectorshiftinsertforms": {Name: "vectorshiftinsertforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"lshr <", "shl <", "and <", "or <"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 vector shift-insert lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-vector-shift-insert.ll", "arm64-vector-shift-insert.o", ll)
		})
	}
}

func TestTranslateARM64VectorShiftInsertRejectsInvalidForms(t *testing.T) {
	for _, tc := range []struct {
		instruction string
		goAccepts   bool
	}{
		{"VSRI $0, V0.S4, V1.S4", false},
		{"VSRI $33, V0.S4, V1.S4", false},
		// Go 1.27 accepts this and encodes it as a different element width.
		// Retain the architectural range check instead of copying that bug.
		{"VSLI $-1, V0.S4, V1.S4", true},
		{"VSLI $32, V0.S4, V1.S4", false},
		{"VSRI $1, V0.S2, V1.S4", false},
		{"VSLI $1, V0.D1, V1.D1", false},
		{"VSRI.P $1, V0.S4, V1.S4", false},
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "", ".", "_").Replace(tc.instruction), func(t *testing.T) {
			source := "TEXT badvectorshiftinsert(SB),$0-0\n\t" + tc.instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, tc.goAccepts)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64",
				Sigs: map[string]FuncSig{"badvectorshiftinsert": {Name: "badvectorshiftinsert", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted invalid vector shift-insert form %q", tc.instruction)
			}
		})
	}
}

func TestARM64VectorShiftInsertRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT vectorshiftinsert(SB),$0-24
	MOVD src+0(FP), R0
	MOVD dst+8(FP), R1
	MOVD out+16(FP), R2
	VLD1 (R0), [V0.S4]
	VLD1 (R1), [V1.S4]
	VSRI $20, V0.S4, V1.S4
	VST1.P [V1.S4], 16(R2)
	VLD1 (R1), [V1.S4]
	VSLI $7, V0.S4, V1.S4
	VST1 [V1.S4], (R2)
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
			"vectorshiftinsert": {
				Name: "vectorshiftinsert", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void vectorshiftinsert(const uint32_t *, const uint32_t *, uint32_t *);
int main(void) {
  const uint32_t src[4] = {0x12345678u, 0xffffffffu, 0x80000000u, 1u};
  const uint32_t dst[4] = {0xabcdef01u, 0x01234567u, 0xffffffffu, 0u};
  uint32_t got[8] = {0};
  vectorshiftinsert(src, dst, got);
  for (int i = 0; i < 4; i++) {
    uint32_t sri = (dst[i] & 0xfffff000u) | (src[i] >> 20);
    uint32_t sli = (dst[i] & 0x0000007fu) | (src[i] << 7);
    if (got[i] != sri) return i + 1;
    if (got[4+i] != sli) return i + 11;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_vector_shift_insert", triple, ll, mainC, nil)
}
