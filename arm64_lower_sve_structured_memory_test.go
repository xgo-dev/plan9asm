package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEStructuredMemoryCompleteGo127Forms() string {
	var source strings.Builder
	source.WriteString("TEXT svestructuredmemoryforms(SB),$0-0\n")
	for _, count := range []int{2, 3, 4} {
		for _, width := range []struct {
			name        string
			arrangement string
			shift       int
		}{
			{name: "B", arrangement: "B"},
			{name: "H", arrangement: "H", shift: 1},
			{name: "W", arrangement: "S", shift: 2},
			{name: "D", arrangement: "D", shift: 3},
			{name: "Q", arrangement: "Q", shift: 4},
		} {
			registers := make([]string, count)
			for i := range registers {
				registers[i] = fmt.Sprintf("Z%d.%s", 12+i, width.arrangement)
			}
			list := "[" + strings.Join(registers, ", ") + "]"
			index := "R6"
			if width.shift != 0 {
				index = fmt.Sprintf("R6<<%d", width.shift)
			}
			load := fmt.Sprintf("ZLD%d%s", count, width.name)
			store := fmt.Sprintf("ZST%d%s", count, width.name)
			fmt.Fprintf(&source, "\t%s (%s)(R14), P4.Z, %s\n", load, index, list)
			fmt.Fprintf(&source, "\t%s (-VL*%d)(R14), P4.Z, %s\n", load, count, list)
			fmt.Fprintf(&source, "\t%s %s, P4, (%s)(R14)\n", store, list, index)
			fmt.Fprintf(&source, "\t%s %s, P4, (VL*%d)(R14)\n", store, list, count)
		}
	}
	// The hardware encoding wraps consecutive Z lists modulo 32.
	source.WriteString("\tZLD2B (R6)(R14), P4.Z, [Z31.B, Z0.B]\n")
	source.WriteString("\tZST3H [Z31.H, Z0.H, Z1.H], P4, (R6<<1)(R14)\n")
	source.WriteString("\tZLD4D (-VL*4)(R14), P4.Z, [Z30.D, Z31.D, Z0.D, Z1.D]\n")
	// Exercise every architectural MUL VL boundary, not only representative values.
	source.WriteString("\tZLD2B (-VL*16)(R14), P4.Z, [Z12.B, Z13.B]\n")
	source.WriteString("\tZST2B [Z12.B, Z13.B], P4, (VL*14)(R14)\n")
	source.WriteString("\tZLD3B (-VL*24)(R14), P4.Z, [Z12.B, Z13.B, Z14.B]\n")
	source.WriteString("\tZST3B [Z12.B, Z13.B, Z14.B], P4, (VL*21)(R14)\n")
	source.WriteString("\tZLD4B (-VL*32)(R14), P4.Z, [Z12.B, Z13.B, Z14.B, Z15.B]\n")
	source.WriteString("\tZST4B [Z12.B, Z13.B, Z14.B, Z15.B], P4, (VL*28)(R14)\n")
	source.WriteString("\tRET\n")
	return source.String()
}

func TestTranslateARM64SVEStructuredMemoryCompleteGo127Family(t *testing.T) {
	source := arm64SVEStructuredMemoryCompleteGo127Forms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svestructuredmemoryforms": {Name: "svestructuredmemoryforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2p1"`,
				"@llvm.aarch64.sve.ld2.sret.",
				"@llvm.aarch64.sve.ld3.sret.",
				"@llvm.aarch64.sve.ld4.sret.",
				"@llvm.aarch64.sve.st2.",
				"@llvm.aarch64.sve.st3.",
				"@llvm.aarch64.sve.st4.",
				"@llvm.aarch64.sve.ld2q.sret.",
				"@llvm.aarch64.sve.ld3q.sret.",
				"@llvm.aarch64.sve.ld4q.sret.",
				"@llvm.aarch64.sve.st2q.",
				"@llvm.aarch64.sve.st3q.",
				"@llvm.aarch64.sve.st4q.",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE structured memory lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-structured-memory.ll", "arm64-sve-structured-memory.o", ll)
		})
	}
}

func TestTranslateARM64SVEStructuredMemoryRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZLD2B (R6)(R14), P8.Z, [Z12.B, Z13.B]",
		"ZLD2B (R6)(R14), P4, [Z12.B, Z13.B]",
		"ZST2B [Z12.B, Z13.B], P4.Z, (R6)(R14)",
		"ZLD2H (R6)(R14), P4.Z, [Z12.H, Z13.H]",
		"ZLD3W (R6<<1)(R14), P4.Z, [Z12.S, Z13.S, Z14.S]",
		"ZST4Q [Z12.Q, Z13.Q, Z14.Q, Z15.Q], P4, (R6<<3)(R14)",
		"ZLD2B (R6)(R14), P4.Z, [Z12.B]",
		"ZLD3B (R6)(R14), P4.Z, [Z12.B, Z14.B, Z15.B]",
		"ZST4H [Z12.H, Z13.H, Z14.S, Z15.H], P4, (R6<<1)(R14)",
		"ZLD2B (-VL*18)(R14), P4.Z, [Z12.B, Z13.B]",
		"ZST2B [Z12.B, Z13.B], P4, (VL*16)(R14)",
		"ZLD3B (-VL*27)(R14), P4.Z, [Z12.B, Z13.B, Z14.B]",
		"ZST3B [Z12.B, Z13.B, Z14.B], P4, (VL*24)(R14)",
		"ZLD4B (-VL*36)(R14), P4.Z, [Z12.B, Z13.B, Z14.B, Z15.B]",
		"ZST4B [Z12.B, Z13.B, Z14.B, Z15.B], P4, (VL*32)(R14)",
		"ZLD2B (VL*3)(R14), P4.Z, [Z12.B, Z13.B]",
		"ZLD3B (VL*4)(R14), P4.Z, [Z12.B, Z13.B, Z14.B]",
		"ZLD4B (VL*6)(R14), P4.Z, [Z12.B, Z13.B, Z14.B, Z15.B]",
		"ZLD2B.Z (R6)(R14), P4.Z, [Z12.B, Z13.B]",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvestructuredmemory(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvestructuredmemory": {Name: "badsvestructuredmemory", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's structured memory forms", instruction)
			}
		})
	}
}
