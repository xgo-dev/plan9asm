package main

import (
	"fmt"
	"strings"
	"testing"

	plan9asm "github.com/xgo-dev/plan9asm"
)

func TestModernX86RawAVX2DirectiveStreamDecodesAtInstructionBoundaries(t *testing.T) {
	// This is the complete AVX2 register-setup sequence used by the BLAKE2b
	// assembly shared by golang.org/x/crypto and many go-ethereum forks. Each
	// instruction addresses registers or memory through general registers; none
	// of them is PC-relative.
	code := []byte{
		0xc5, 0x7a, 0x7e, 0x26,
		0xc5, 0x7a, 0x7e, 0x5e, 0x20,
		0xc4, 0x63, 0x99, 0x22, 0x66, 0x10, 0x01,
		0xc4, 0x63, 0xa1, 0x22, 0x5e, 0x30, 0x01,
	}
	var source strings.Builder
	source.WriteString("TEXT rawAVX2(SB), NOSPLIT, $0-0\n")
	for _, value := range code {
		fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
	}
	source.WriteString("\tRET\n")

	file, err := plan9asm.Parse(plan9asm.ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plan9asm.Translate(file, plan9asm.Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]plan9asm.FuncSig{
			"rawAVX2": {Name: "rawAVX2", Ret: plan9asm.Void},
		},
	}); err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
}

func TestModernX86RawCRC32WidthIsPreserved(t *testing.T) {
	// 66 f2 0f 38 f1 /r is the register/memory 16-bit CRC32 form. The
	// architecture decoder names every width CRC32, so plan9asm must restore
	// the Plan 9 width suffix before operand-form validation.
	const source = `TEXT rawCRC32W(SB), NOSPLIT, $0-0
	BYTE $0x66
	BYTE $0xf2
	BYTE $0x0f
	BYTE $0x38
	BYTE $0xf1
	BYTE $0x06
	RET
`
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plan9asm.Translate(file, plan9asm.Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]plan9asm.FuncSig{
			"rawCRC32W": {Name: "rawCRC32W", Ret: plan9asm.Void},
		},
	}); err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
}
