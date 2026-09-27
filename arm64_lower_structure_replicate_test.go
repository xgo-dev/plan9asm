package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64StructureReplicateLoadCompleteGoAssemblerForms(t *testing.T) {
	arrangements := []string{"B8", "B16", "H4", "H8", "S2", "S4", "D1", "D2"}
	var source strings.Builder
	source.WriteString("TEXT structurereplicateloadforms(SB),$0-0\n")
	for count := 1; count <= 4; count++ {
		op := fmt.Sprintf("VLD%dR", count)
		for _, arrangement := range arrangements {
			regs := arm64TestVectorList(28, count, arrangement)
			elementBytes := map[byte]int{'B': 1, 'H': 2, 'S': 4, 'D': 8}[arrangement[0]]
			fmt.Fprintf(&source, "\t%s (R0), %s\n", op, regs)
			fmt.Fprintf(&source, "\t%s.P %d(R0), %s\n", op, count*elementBytes, regs)
			fmt.Fprintf(&source, "\t%s.P (R0)(R1), %s\n", op, regs)
		}
		// Go classifies every one-through-four-register list as C_LIST. The
		// opcode still determines how many registers hardware writes. Only an
		// explicit nonzero post-index immediate triggers an exact-count check.
		for writtenCount := 1; writtenCount <= 4; writtenCount++ {
			regs := arm64TestVectorList(24, writtenCount, "S4")
			fmt.Fprintf(&source, "\t%s (R0), %s\n", op, regs)
			fmt.Fprintf(&source, "\t%s.P (R0), %s\n", op, regs)
			fmt.Fprintf(&source, "\t%s.P (R0)(R1), %s\n", op, regs)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
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
					"structurereplicateloadforms": {Name: "structurereplicateloadforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"load i8", "load i16", "load i32", "load i64", "shufflevector"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 VLDnR lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-structure-replicate-load.ll", "arm64-structure-replicate-load.o", ll)
		})
	}
}

func TestTranslateARM64StructureReplicateLoadRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VLD2R (R0), [V0.S4, V2.S4]",
		"VLD2R.P 4(R0), [V0.S4]",
		"VLD3R (R0), [V0.H8, V1.S4, V2.H8]",
		"VLD4R.P 8(R0), [V0.S4, V1.S4, V2.S4, V3.S4]",
		"VLD1R.Z (R0), [V0.B16]",
		"VLD1R 1(R0), [V0.B16]",
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badstructurereplicateload(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badstructurereplicateload": {Name: "badstructurereplicateload", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's VLDnR optab", instruction)
			}
		})
	}
}

func TestARM64StructureReplicateLoadRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT structurereplicateload(SB),$0-0
	VLD4R.P 16(R0), [V0.S4, V1.S4, V2.S4, V3.S4]
	VST1.P [V0.S4, V1.S4, V2.S4, V3.S4], 64(R1)
	MOVD R0, 0(R2)
	MOVD R1, 8(R2)
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
			"structurereplicateload": {
				Name: "structurereplicateload", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <stddef.h>
extern void structurereplicateload(const uint32_t *, uint32_t *, uintptr_t *);
int main(void) {
  const uint32_t input[4] = {11, 22, 33, 44};
  uint32_t output[16] = {0};
  uintptr_t advanced[2] = {0};
  structurereplicateload(input, output, advanced);
  for (int group = 0; group < 4; group++)
    for (int lane = 0; lane < 4; lane++)
      if (output[group*4+lane] != input[group]) return 1 + group*4 + lane;
  if (advanced[0] != (uintptr_t)(input+4)) return 30;
  if (advanced[1] != (uintptr_t)(output+16)) return 31;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_structure_replicate_load", triple, ll, mainC, nil)
}
