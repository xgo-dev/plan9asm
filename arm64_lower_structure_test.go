package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64StructureLoadStoreCompleteGoAssemblerForms(t *testing.T) {
	arrangements := []string{"B8", "B16", "H4", "H8", "S2", "S4", "D2"}
	var source strings.Builder
	source.WriteString("TEXT ·structureloadstoreforms(SB), $0-0\n")
	for count := 1; count <= 4; count++ {
		loadOp := fmt.Sprintf("VLD%d", count)
		storeOp := fmt.Sprintf("VST%d", count)
		for _, arrangement := range arrangements {
			regs := arm64TestVectorList(0, count, arrangement)
			fmt.Fprintf(&source, "\t%s (R0), %s\n", loadOp, regs)
			fmt.Fprintf(&source, "\t%s %s, (R0)\n", storeOp, regs)
		}
		bytes := count * 16
		regs := arm64TestVectorList(28, count, "D2")
		fmt.Fprintf(&source, "\t%s.P %d(R0), %s\n", loadOp, bytes, regs)
		fmt.Fprintf(&source, "\t%s.P %s, %d(R0)\n", storeOp, regs, bytes)
		regs = arm64TestVectorList(28, count, "B8")
		fmt.Fprintf(&source, "\t%s.P (R0)(R1), %s\n", loadOp, regs)
		fmt.Fprintf(&source, "\t%s.P %s, (R0)(R1)\n", storeOp, regs)
	}
	for count := 2; count <= 4; count++ {
		regs := arm64TestVectorList(8, count, "S4")
		fmt.Fprintf(&source, "\tVLD1 (R0), %s\n", regs)
		fmt.Fprintf(&source, "\tVST1 %s, (R0)\n", regs)
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs:         map[string]FuncSig{"structureloadstoreforms": {Name: "structureloadstoreforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-structure-load-store.ll", "arm64-structure-load-store.o", ll)
		})
	}
}

func TestARM64StructureLoadStoreRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	source := `
TEXT structureroundtrip(SB), $0-0
	VLD3.P 48(R0), [V0.S4, V1.S4, V2.S4]
	VST1.P [V0.S4, V1.S4, V2.S4], 48(R1)
	VLD1.P 48(R2), [V3.S4, V4.S4, V5.S4]
	VST3.P [V3.S4, V4.S4, V5.S4], 48(R3)
	MOVD R0, 0(R4)
	MOVD R1, 8(R4)
	MOVD R2, 16(R4)
	MOVD R3, 24(R4)
	RET
`
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	frame := FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: Ptr, Index: 1, Field: -1},
		{Offset: 16, Type: Ptr, Index: 2, Field: -1},
		{Offset: 24, Type: Ptr, Index: 3, Field: -1},
		{Offset: 32, Type: Ptr, Index: 4, Field: -1},
	}}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"structureroundtrip": {Name: "structureroundtrip", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr}, Ret: Void, Frame: frame},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mainC := `
#include <stdint.h>
extern void structureroundtrip(const int32_t *, int32_t *, const int32_t *, int32_t *, uintptr_t *);
int main(void) {
  const int32_t interleaved[12] = {10,20,30, 11,21,31, 12,22,32, 13,23,33};
  const int32_t separated[12] = {10,11,12,13, 20,21,22,23, 30,31,32,33};
  int32_t got_separated[12] = {0}, got_interleaved[12] = {0};
  uintptr_t advanced[4] = {0};
  structureroundtrip(interleaved, got_separated, separated, got_interleaved, advanced);
  for (int i = 0; i < 12; i++) {
    if (got_separated[i] != separated[i]) return 10+i;
    if (got_interleaved[i] != interleaved[i]) return 30+i;
  }
  if (advanced[0] != (uintptr_t)(interleaved+12)) return 51;
  if (advanced[1] != (uintptr_t)(got_separated+12)) return 52;
  if (advanced[2] != (uintptr_t)(separated+12)) return 53;
  if (advanced[3] != (uintptr_t)(got_interleaved+12)) return 54;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_structure_load_store", triple, ll, mainC, nil)
}

func TestTranslateARM64StructureLoadStoreRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VLD2 (R0), [V0.S4, V2.S4]",
		"VST3 [V0.B16, V1.H8, V2.B16], (R0)",
		"VLD3.P 32(R0), [V0.S4, V1.S4, V2.S4]",
		"VST4.Z [V0.B16, V1.B16, V2.B16, V3.B16], (R0)",
	} {
		source := "TEXT ·bad(SB), $0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's structure load/store table", instruction)
		}
	}
}

func arm64TestVectorList(start, count int, arrangement string) string {
	regs := make([]string, count)
	for i := range regs {
		regs[i] = fmt.Sprintf("V%d.%s", (start+i)%32, arrangement)
	}
	return "[" + strings.Join(regs, ", ") + "]"
}
