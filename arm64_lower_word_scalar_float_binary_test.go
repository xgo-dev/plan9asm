package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64RawScalarFloatBinaryCompleteArchitectureFamily(t *testing.T) {
	operations := []struct {
		name   string
		opcode uint32
	}{
		{"FADD", 0x2800},
		{"FSUB", 0x3800},
		{"FMUL", 0x0800},
		{"FNMUL", 0x8800},
		{"FDIV", 0x1800},
		{"FMAX", 0x4800},
		{"FMIN", 0x5800},
		{"FMAXNM", 0x6800},
		{"FMINNM", 0x7800},
	}
	widths := []struct {
		name string
		base uint32
	}{
		{"H", 0x1ee00000},
		{"S", 0x1e200000},
		{"D", 0x1e600000},
	}

	var source strings.Builder
	source.WriteString("TEXT rawScalarFloatBinaryFamily(SB),$0-0\n")
	for _, operation := range operations {
		for _, width := range widths {
			word := width.base | operation.opcode | 31<<16 | 30<<5 | 29
			fmt.Fprintf(&source, "\tWORD $%#08x // %s %s\n", word, operation.name, width.name)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)

	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawScalarFloatBinaryFamily": {Name: "rawScalarFloatBinaryFamily", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"fadd half", "fadd float", "fadd double",
				"fsub half", "fmul half", "fdiv half", "fneg half",
				"@llvm.maximum.f16", "@llvm.minimum.f16",
				"@llvm.maxnum.f16", "@llvm.minnum.f16",
				`"target-features"="+fullfp16"`,
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw scalar float binary IR omitted %q:\n%s", want, ir)
				}
			}

			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-scalar-float-binary.ll", "arm64-raw-scalar-float-binary.o", ir)
		})
	}
}

func TestARM64RawScalarFloatBinaryDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x1ea02800, // Reserved type=2 encoding.
		0x1e202c00, // FADD with reserved opcode bits.
		0x1e20c800, // FMADD, a different instruction class.
		0x5e20d400, // Scalar FADDP, a different instruction class.
	} {
		if _, ok := decodeARM64RawScalarFloatBinary(word); ok {
			t.Fatalf("scalar float-binary decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}
