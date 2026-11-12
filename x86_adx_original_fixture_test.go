package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

const x86ADXOriginalRuntimeSource = `TEXT adxsemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI

	// ADCXL consumes CF, updates only CF, and zero-extends its destination.
	MOVL $0x7fffffff, R8
	ADDL $1, R8
	STC
	MOVL $-1, AX
	MOVL $0, BX
	ADCXL AX, BX
	MOVQ BX, 0(DI)
	SETCS 8(DI)
	SETOS 9(DI)
	SETEQ 10(DI)
	SETMI 11(DI)

	// ADOXL consumes OF, updates only OF, and leaves CF untouched.
	MOVL $0x7fffffff, R8
	ADDL $1, R8
	STC
	MOVL $-1, AX
	MOVL $0, BX
	ADOXL AX, BX
	MOVQ BX, 16(DI)
	SETOS 24(DI)
	SETCS 25(DI)
	SETEQ 26(DI)
	SETMI 27(DI)

	// The Q-width memory form uses CF while preserving OF and ZF.
	XORQ R8, R8
	STC
	MOVQ $-1, 32(DI)
	MOVQ $0, BX
	ADCXQ 32(DI), BX
	MOVQ BX, 40(DI)
	SETCS 48(DI)
	SETOS 49(DI)
	SETEQ 50(DI)

	// ADOXQ memory form consumes OF without changing CF, ZF or SF.
	MOVL $0x7fffffff, R8
	ADDL $1, R8
	STC
	MOVQ $0, BX
	ADOXQ 32(DI), BX
	MOVQ BX, 56(DI)
	SETOS 64(DI)
	SETCS 65(DI)
	SETEQ 66(DI)
	SETMI 67(DI)
	RET
`

func x86ADXOriginalRawSource(source string) string {
	return strings.NewReplacer(
		"ADCXL AX, BX", "BYTE $0x66; BYTE $0x0f; BYTE $0x38; BYTE $0xf6; BYTE $0xd8",
		"ADOXL AX, BX", "BYTE $0xf3; BYTE $0x0f; BYTE $0x38; BYTE $0xf6; BYTE $0xd8",
		"ADCXQ 32(DI), BX", "BYTE $0x66; BYTE $0x48; BYTE $0x0f; BYTE $0x38; BYTE $0xf6; BYTE $0x5f; BYTE $0x20",
		"ADOXQ 32(DI), BX", "BYTE $0xf3; BYTE $0x48; BYTE $0x0f; BYTE $0x38; BYTE $0xf6; BYTE $0x5f; BYTE $0x20",
	).Replace(source)
}

func TestX86ADXOriginalRuntimeSourceObjects(t *testing.T) {
	for _, raw := range []bool{false, true} {
		source := x86ADXOriginalRuntimeSource
		if raw {
			source = x86ADXOriginalRawSource(source)
		}
		for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
			t.Run(fmt.Sprintf("%s/raw=%t", triple, raw), func(t *testing.T) {
				x86RawNumericalFamilyObjects(t, source, "func adxsemantics(out *[72]byte)", "amd64", triple)
			})
		}
	}
}

func TestX86ADXInitializedFiveTargetObjects(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := 8, "MOVQ"
			widths := []string{"L", "Q"}
			if target.arch == "386" {
				word, move = 4, "MOVL"
				widths = widths[:1]
			}
			var source, declarations strings.Builder
			count := 0
			for _, stem := range []string{"ADCX", "ADOX"} {
				for _, width := range widths {
					for _, memory := range []bool{false, true} {
						for _, raw := range []bool{false, true} {
							name, input := fmt.Sprintf("Value%d", count), "AX"
							if memory {
								input = "(DX)"
							}
							line := stem + width + " " + input + ",BX"
							if raw {
								line = x86RawNumericalInstruction(t, target.arch, line)
							}
							fmt.Fprintf(&declarations, "func %s(value uintptr,input *[8]byte) uintptr\n", name)
							fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s value+0(FP),AX\n%s input+%d(FP),DX\n%s $-1,BX\nCMPL AX,AX\n%s\n%s BX,ret+%d(FP)\nRET\n", name, word*3, move, move, word, move, line, move, word*2)
							count++
						}
					}
				}
			}
			if count != 8*len(widths) {
				t.Fatal("complete named/raw register/memory ADX denominator changed", count)
			}
			x86RawNumericalFamilyObjects(t, source.String(), declarations.String(), target.arch, target.triple)
		})
	}
}
