package plan9asm

import (
	"strings"
	"testing"
)

// Parse outside the timer; include complete public Translate, result analysis,
// lowering, LLVM verification and IR serialization. Each initialized kernel
// writes its actual arithmetic result to the declared ABI0 result slot.
func BenchmarkX86ScalarShiftTranslation(b *testing.B) {
	for _, row := range []string{
		"SHLQ $7,AX",
		"SARL CX,AX",
		"RCLB $10,AL",
		"RCRW CX,AX",
		"SHLW $16,BX,AX",
		"SHRL CX,BX,AX",
		"RCRQ $0,AX",
		"RORXL $7,BX,AX", // Adjacent BMI2 dispatch remains independent.
	} {
		b.Run(row, func(b *testing.B) {
			source := "TEXT scalarshift(SB),4,$0-8\n" +
				"MOVQ $-8127,AX\nMOVQ $32769,BX\nMOVQ $3,CX\nCLC\n" +
				strings.Repeat(row+"\n", 32) + "MOVQ AX,ret+0(FP)\nRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				b.Fatal(err)
			}
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				Sigs: map[string]FuncSig{"scalarshift": {
					Name: "scalarshift", Ret: I64,
					Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Field: -1}}},
				}}}
			if _, err := Translate(file, options); err != nil {
				b.Fatal("benchmark must translate successfully before timing", err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := Translate(file, options); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
