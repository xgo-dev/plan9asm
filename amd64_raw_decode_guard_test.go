package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86RawDecoderRejectsUnrecognizedVEXInsteadOfLegacyInstructions(t *testing.T) {
	// x/arch v0.14 can return SUB AL,imm instead of an error for these
	// invalid scalar conversions. Such a successful decode is not semantic support.
	for _, code := range [][]byte{{0xc5, 0xf8, 0x2c, 0xc1}, {0xc5, 0xf8, 0x2d, 0xc1}, {0xc4, 0xe1, 0xf8, 0x2c, 0xc1}} {
		for _, arch := range []string{"386", "amd64"} {
			var source strings.Builder
			source.WriteString("TEXT f(SB),4,$0-0\n")
			for _, b := range code {
				fmt.Fprintf(&source, "BYTE $%#02x\n", b)
			}
			source.WriteString("RET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{Goarch: arch, Sigs: map[string]FuncSig{"f": {Name: "f", Ret: Void}}}); err == nil {
				t.Errorf("%s raw %x must fail closed instead of executing legacy arithmetic: %v", arch, code, err)
			}
		}
	}
}

func TestX86RawDecoderRecognizesSupportedScalarConversionsBeforeLegacyFallback(t *testing.T) {
	for _, tc := range []struct {
		code []byte
		op   Op
	}{
		{[]byte{0xc5, 0xfb, 0x2c, 0xc1}, "VCVTTSD2SI"},
		{[]byte{0xc5, 0xfa, 0x2c, 0xc1}, "VCVTTSS2SI"},
		{[]byte{0xc4, 0xe1, 0xfb, 0x2c, 0xc1}, "VCVTTSD2SIQ"},
	} {
		decoded, err := decodeX86RawDirectives(rawX86Function(tc.code), "amd64")
		if err != nil || len(decoded.Instrs) != 1 || decoded.Instrs[0].Op != tc.op {
			t.Errorf("supported VEX %x: %+v, %v; want %s", tc.code, decoded.Instrs, err, tc.op)
		}
	}
}

func TestX86RawDecoderRetainsRecognizedVEXFallback(t *testing.T) {
	for _, code := range [][]byte{
		{0xc5, 0xf8, 0x77}, {0xc5, 0xf9, 0x6f, 0xc1}, {0xc5, 0xfa, 0x6f, 0xc1},
		{0xc5, 0xf9, 0xe7, 0x00}, {0xc4, 0xe2, 0x79, 0x2a, 0x00},
	} {
		decoded, err := decodeX86RawDirectives(rawX86Function(code), "amd64")
		if err != nil || len(decoded.Instrs) != 1 {
			t.Fatalf("recognized VEX %x: %+v, %v", code, decoded.Instrs, err)
		}
	}
}
