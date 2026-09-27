package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawScalarFloatCompareDecoderCompleteArchitectureFamily(t *testing.T) {
	widths := []struct {
		bits int
		base uint32
	}{
		{bits: 16, base: 0x1ee02000},
		{bits: 32, base: 0x1e202000},
		{bits: 64, base: 0x1e602000},
	}

	count := 0
	for _, width := range widths {
		for _, signaling := range []bool{false, true} {
			for first := 0; first < 32; first++ {
				for second := 0; second < 32; second++ {
					word := width.base | uint32(second)<<16 | uint32(first)<<5
					if signaling {
						word |= 1 << 4
					}
					form, ok := decodeARM64RawScalarFloatCompare(word)
					if !ok {
						t.Fatalf("decoder rejected %#08x", word)
					}
					if form.bits != width.bits || form.signaling != signaling || form.zero ||
						form.first != first || form.second != second {
						t.Fatalf("decode %#08x = %+v", word, form)
					}
					count++
				}
			}

			for first := 0; first < 32; first++ {
				word := width.base | uint32(first)<<5 | 1<<3
				if signaling {
					word |= 1 << 4
				}
				form, ok := decodeARM64RawScalarFloatCompare(word)
				if !ok {
					t.Fatalf("decoder rejected %#08x", word)
				}
				if form.bits != width.bits || form.signaling != signaling || !form.zero ||
					form.first != first || form.second != 0 {
					t.Fatalf("decode %#08x = %+v", word, form)
				}
				count++
			}
		}
	}
	if count != 6336 {
		t.Fatalf("covered %d scalar float-compare encodings, want 6336", count)
	}
}

func TestTranslateARM64RawScalarFloatCompareCompleteArchitectureFamily(t *testing.T) {
	widths := []struct {
		name string
		base uint32
	}{
		{name: "H", base: 0x1ee02000},
		{name: "S", base: 0x1e202000},
		{name: "D", base: 0x1e602000},
	}

	var source strings.Builder
	source.WriteString("TEXT rawScalarFloatCompareFamily(SB),$0-0\n")
	for _, width := range widths {
		for _, signaling := range []bool{false, true} {
			name := "FCMP"
			modifier := uint32(0)
			if signaling {
				name = "FCMPE"
				modifier = 1 << 4
			}
			registerWord := width.base | modifier | 31<<16 | 30<<5
			zeroWord := width.base | modifier | 1<<3 | 29<<5
			fmt.Fprintf(&source, "\tWORD $%#08x // %s %s30, %s31\n", registerWord, name, width.name, width.name)
			fmt.Fprintf(&source, "\tWORD $%#08x // %s %s29, #0.0\n", zeroWord, name, width.name)
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
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawScalarFloatCompareFamily": {Name: "rawScalarFloatCompareFamily", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"fcmp oeq half", "fcmp oeq float", "fcmp oeq double",
				"fcmp uno half", `"target-features"="+fullfp16"`,
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw scalar float-compare IR omitted %q:\n%s", want, ir)
				}
			}
			if got := strings.Count(ir, "fcmp oeq"); got != 12 {
				t.Fatalf("raw scalar float-compare emitted %d equality tests, want 12:\n%s", got, ir)
			}

			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-scalar-float-compare.ll", "arm64-raw-scalar-float-compare.o", ir)
		})
	}
}

func TestARM64RawScalarFloatCompareDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x1ea02000, // Reserved type=2 encoding.
		0x1e212048, // Immediate-zero form with a nonzero Rm field.
		0x1e202001, // Reserved low result-register field.
		0x1e202800, // FADD, a different instruction class.
		0x5e20d400, // Scalar FADDP, a different instruction class.
	} {
		if _, ok := decodeARM64RawScalarFloatCompare(word); ok {
			t.Fatalf("scalar float-compare decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}
