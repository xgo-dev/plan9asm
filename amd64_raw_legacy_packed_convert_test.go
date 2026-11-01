package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

var x86LegacyPackedConversionForms = []struct {
	name string
	code []byte
	op   Op
}{
	{"dword-to-single-X", []byte{0x0f, 0x5b, 0xc1}, "CVTPL2PS"},
	{"dword-to-single-M", []byte{0x0f, 0x2a, 0xc1}, "CVTPL2PS"},
	{"single-to-dword-X", []byte{0x66, 0x0f, 0x5b, 0xc1}, "CVTPS2PL"},
	{"single-to-dword-M", []byte{0x0f, 0x2d, 0xc1}, "CVTPS2PL"},
	{"truncate-single-X", []byte{0xf3, 0x0f, 0x5b, 0xc1}, "CVTTPS2PL"},
	{"truncate-single-M", []byte{0x0f, 0x2c, 0xc1}, "CVTTPS2PL"},
	{"dword-to-double-X", []byte{0xf3, 0x0f, 0xe6, 0xc1}, "CVTPL2PD"},
	{"dword-to-double-M", []byte{0x66, 0x0f, 0x2a, 0xc1}, "CVTPL2PD"},
	{"double-to-dword-X", []byte{0xf2, 0x0f, 0xe6, 0xc1}, "CVTPD2PL"},
	{"double-to-dword-M", []byte{0x66, 0x0f, 0x2d, 0xc1}, "CVTPD2PL"},
	{"truncate-double-X", []byte{0x66, 0x0f, 0xe6, 0xc1}, "CVTTPD2PL"},
	{"truncate-double-M", []byte{0x66, 0x0f, 0x2c, 0xc1}, "CVTTPD2PL"},
}

func TestX86RawLegacyPackedConversionGo127Names(t *testing.T) {
	for _, form := range x86LegacyPackedConversionForms {
		t.Run(form.name, func(t *testing.T) {
			decoded, err := decodeX86RawDirectives(rawX86Function(form.code), "amd64")
			if err != nil {
				t.Fatal(err)
			}
			if len(decoded.Instrs) != 1 || decoded.Instrs[0].Op != form.op {
				t.Fatalf("raw %#x decoded as %+v; want %s", form.code, decoded.Instrs, form.op)
			}
		})
	}
}

func TestX86RawLegacyPackedConversionCompilesEveryForm(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name, goarch, triple string
	}{
		{"linux-386", "386", "i386-unknown-linux-gnu"},
		{"windows-386", "386", "i686-pc-windows-msvc"},
		{"linux-amd64", "amd64", "x86_64-unknown-linux-gnu"},
		{"darwin-amd64", "amd64", "x86_64-apple-darwin"},
		{"windows-amd64", "amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			for index, form := range x86LegacyPackedConversionForms {
				name := fmt.Sprintf("rawlegacyconversion%d", index)
				var one strings.Builder
				fmt.Fprintf(&one, "TEXT %s(SB),4,$0-0\n", name)
				for _, value := range form.code {
					fmt.Fprintf(&one, "\tBYTE $%d\n", value)
				}
				one.WriteString("\tRET\n")
				if strings.HasSuffix(form.name, "-M") {
					// Decode and actual Go objects remain covered. A raw MMX
					// transport does not certify the physical x87/MMX state.
					goAssemblerOracleOutput(t, target.goarch, one.String(), "", true)
					file, err := Parse(ArchAMD64, one.String())
					if err != nil {
						t.Fatal(err)
					}
					_, err = Translate(file, Options{Goarch: target.goarch, TargetTriple: target.triple,
						Sigs: map[string]FuncSig{name: {Name: name, Ret: Void}}})
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("unknown raw MMX state got a native numerical-only contract", err)
					}
					continue
				}
				source.WriteString(one.String())
			}
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			ir := x86UnboundVoidRawScalarFormatObject(t, source.String(), target.goarch, target.triple)
			compileLLVMToObject(t, llc, target.triple, "raw-legacy-conversion.ll", "raw-legacy-conversion.o", ir)
		})
	}
}

func TestX86RawLegacyPackedConversionMMXStateContext(t *testing.T) {
	for _, name := range []string{"CVTPS2PL", "CVTTPS2PL", "CVTPD2PL", "CVTTPD2PL"} {
		for _, target := range x86RawReturnTargets {
			source := "TEXT probe(SB),4,$0-0\n" + name + " X1,M0\nEMMS\nRET\n"
			code := x86PackedShiftActualGoBytes(t, target.arch, source)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"probe": {Ret: Void}}}
			if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("EMMS is not a complete entry/caller physical MMX contract", name, err)
			}
			var raw strings.Builder
			raw.WriteString("TEXT probe(SB),4,$0-0\n")
			for _, value := range code {
				fmt.Fprintf(&raw, "BYTE $%d\n", value)
			}
			rawFile, err := Parse(ArchAMD64, raw.String())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(rawFile, options); !errors.Is(err, ErrProbeNeedsContext) ||
				!strings.Contains(err.Error(), "MMX/x87 caller contract") {
				t.Fatal(name, err)
			}
		}
	}
}
