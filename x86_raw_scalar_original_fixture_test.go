package plan9asm

import "testing"

const x86RawCountOriginalRuntimeSource = `
TEXT rawbitcountsemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	MOVQ $0x12340000, AX
	BYTE $0x66; BYTE $0xf3; BYTE $0x0f; BYTE $0xbc; BYTE $0xc0 // TZCNTW AX, AX
	MOVQ AX, 0(DI)
	SETCS 8(DI)
	SETEQ 9(DI)
	MOVQ $0x1122334480000000, AX
	BYTE $0xf3; BYTE $0x0f; BYTE $0xbd; BYTE $0xc0 // LZCNTL AX, AX
	MOVQ AX, 16(DI)
	SETCS 24(DI)
	SETEQ 25(DI)
	MOVQ $0, AX
	BYTE $0xf3; BYTE $0x48; BYTE $0x0f; BYTE $0xbc; BYTE $0xc0 // TZCNTQ AX, AX
	MOVQ AX, 32(DI)
	SETCS 40(DI)
	SETEQ 41(DI)
	MOVQ $0x100, 48(DI)
	BYTE $0xf3; BYTE $0x48; BYTE $0x0f; BYTE $0xbd; BYTE $0x4f; BYTE $0x30 // LZCNTQ 48(DI), CX
	MOVQ CX, 56(DI)
	SETCS 64(DI)
	SETEQ 65(DI)
	RET
`

const x86RawMoveMaskOriginalRuntimeSource = `TEXT rawmovemasksemantics(SB),4,$0-16
	MOVQ input+0(FP), DI
	MOVQ out+8(FP), SI
	VMOVDQU (DI), Y1
	BYTE $0xc5; BYTE $0xfd; BYTE $0xd7; BYTE $0xc1
	MOVL AX, 0(SI)
	BYTE $0xc5; BYTE $0xf8; BYTE $0x50; BYTE $0xc1
	MOVL AX, 4(SI)
	BYTE $0xc5; BYTE $0xfd; BYTE $0x50; BYTE $0xc1
	MOVL AX, 8(SI)
	RET
`

func TestX86RawScalarOriginalVoidNativeObjects(t *testing.T) {
	for _, fixture := range []struct{ name, source, declaration string }{
		{"count", x86RawCountOriginalRuntimeSource, "func rawbitcountsemantics(out *[72]byte)"},
		{"move-mask", x86RawMoveMaskOriginalRuntimeSource, "func rawmovemasksemantics(input *[32]byte,out *[12]byte)"},
	} {
		for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
			t.Run(fixture.name+"/"+triple, func(t *testing.T) {
				x86RawNumericalFamilyObjects(t, fixture.source, fixture.declaration, "amd64", triple)
			})
		}
	}
}
