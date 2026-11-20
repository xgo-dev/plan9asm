package plan9asm

import (
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestTranslateARM64VectorShiftLeftCompleteGoAssemblerForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT vectorshiftleftforms(SB),$0-0\n")
	for _, form := range []struct {
		arrangement string
		maxShift    int
	}{
		{"B8", 7}, {"B16", 7}, {"H4", 15}, {"H8", 15},
		{"S2", 31}, {"S4", 31}, {"D2", 63},
	} {
		source.WriteString("\tVSHL $0, V0." + form.arrangement + ", V1." + form.arrangement + "\n")
		source.WriteString("\tVSHL $" + strconv.Itoa(form.maxShift) + ", V2." + form.arrangement + ", V3." + form.arrangement + "\n")
	}
	source.WriteString("\tRET\n")
	forms := source.String()
	requireARM64GoAssemblerResult(t, forms, true)
	file, err := Parse(ArchARM64, forms)
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
					"vectorshiftleftforms": {Name: "vectorshiftleftforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ll, "shl <") {
				t.Fatalf("ARM64 VSHL lowering for %s omitted vector shift:\n%s", triple, ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-vector-shift-left.ll", "arm64-vector-shift-left.o", ll)
		})
	}
}

func TestTranslateARM64VectorShiftLeftRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VSHL $8, V0.B16, V1.B16",
		"VSHL $16, V0.H8, V1.H8",
		"VSHL $32, V0.S4, V1.S4",
		"VSHL $64, V0.D2, V1.D2",
		"VSHL $1, V0.S2, V1.S4",
		"VSHL $1, V0.D1, V1.D1",
		"VSHL V0.S4, V1.S4",
		"VSHL.P $1, V0.S4, V1.S4",
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badvectorshiftleft(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badvectorshiftleft": {Name: "badvectorshiftleft", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's VSHL optab", instruction)
			}
		})
	}
}

func TestARM64VectorShiftLeftRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT vectorshiftleft(SB),$0-8
	MOVD out+0(FP), R0
	VMOVQ $0x0000000200000001, $0x8000000040000000, V1
	VSHL $1, V1.S4, V2.S4
	VSHL $31, V1.S4, V3.S4
	VMOV V2.D[0], R1
	VMOV V2.D[1], R2
	VMOV V3.D[0], R3
	VMOV V3.D[1], R4
	MOVD R1, 0(R0)
	MOVD R2, 8(R0)
	MOVD R3, 16(R0)
	MOVD R4, 24(R0)
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
			"vectorshiftleft": {
				Name: "vectorshiftleft", Args: []LLVMType{Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void vectorshiftleft(uint64_t *);
int main(void) {
  uint64_t got[4] = {0};
  vectorshiftleft(got);
  if (got[0] != UINT64_C(0x0000000400000002) || got[1] != UINT64_C(0x0000000080000000)) return 1;
  if (got[2] != UINT64_C(0x0000000080000000) || got[3] != 0) return 2;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_vector_shift_left", triple, ll, mainC, nil)
}
