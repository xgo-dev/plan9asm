package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type arm64FixedConversionCase struct {
	toFloat, unsigned                       bool
	gp                                      bool
	floatBits, integerBits, lanes, fraction int
	mnemonic, destination, source           string
}

func arm64FixedConversionCases(allFractions bool) []arm64FixedConversionCase {
	var forms []arm64FixedConversionCase
	registers := []struct {
		letter string
		bits   int
	}{{"h", 16}, {"s", 32}, {"d", 64}}
	for _, toFloat := range []bool{false, true} {
		for _, unsigned := range []bool{false, true} {
			mnemonic := "fcvtzs"
			switch {
			case toFloat && unsigned:
				mnemonic = "ucvtf"
			case toFloat:
				mnemonic = "scvtf"
			case unsigned:
				mnemonic = "fcvtzu"
			}
			add := func(fp, integer string, floatBits, integerBits, lanes int, gp bool) {
				dst, src := integer, fp
				if toFloat {
					dst, src = src, dst
				}
				for fraction := 1; fraction <= integerBits; fraction++ {
					if allFractions || fraction == 1 || fraction == integerBits {
						forms = append(forms, arm64FixedConversionCase{
							toFloat: toFloat, unsigned: unsigned, gp: gp, floatBits: floatBits,
							integerBits: integerBits, lanes: lanes, fraction: fraction,
							mnemonic: mnemonic, destination: dst, source: src,
						})
					}
				}
			}
			for _, fp := range registers {
				add(fp.letter, "w", fp.bits, 32, 1, true)
				add(fp.letter, "x", fp.bits, 64, 1, true)
				add(fp.letter, fp.letter, fp.bits, fp.bits, 1, false)
				for _, width := range []int{64, 128} {
					lanes := width / fp.bits
					if lanes > 1 {
						arrangement := fmt.Sprintf("%d%s", lanes, fp.letter)
						add(arrangement, arrangement, fp.bits, fp.bits, lanes, false)
					}
				}
			}
		}
	}
	return forms
}

func (form arm64FixedConversionCase) instruction(dst, src int) string {
	if form.lanes == 1 {
		return fmt.Sprintf("%s %s%d,%s%d,#%d", form.mnemonic, form.destination, dst, form.source, src, form.fraction)
	}
	return fmt.Sprintf("%s v%d.%s,v%d.%s,#%d", form.mnemonic, dst, form.destination, src, form.source, form.fraction)
}

func TestARM64RawFixedConversionDecoderCompleteFamily(t *testing.T) {
	forms := arm64FixedConversionCases(true)
	if len(forms) != 2240 {
		t.Fatalf("scaled conversion inventory has %d legal immediate forms", len(forms))
	}
	instructions := make([]string, 0, len(forms))
	for _, form := range forms {
		instructions = append(instructions, form.instruction(0, 0))
	}
	encodings := assembleARM64LLVMWords(t, instructions, "+fullfp16")
	for index, form := range forms {
		for _, pair := range [][2]int{{0, 0}, {6, 23}, {31, 0}, {31, 31}} {
			word := encodings[index] | uint32(pair[0])<<5 | uint32(pair[1])
			want := arm64FixedConversionForm{
				toFloat: form.toFloat, unsigned: form.unsigned, gp: form.gp,
				floatBits: form.floatBits, integerBits: form.integerBits, lanes: form.lanes,
				fractionalBits: form.fraction, source: pair[0], destination: pair[1],
			}
			got, ok := decodeARM64RawFixedConversion(word)
			if !ok || got != want {
				t.Fatalf("%s encoding %#08x decoded as %+v, ok=%v; want %+v", instructions[index], word, got, ok, want)
			}
		}
	}
}

func TestARM64RawFixedConversionEndpointObjects(t *testing.T) {
	forms := arm64FixedConversionCases(false)
	if len(forms) != 112 {
		t.Fatalf("scaled conversion endpoint inventory has %d forms", len(forms))
	}
	var original []string
	for _, form := range forms {
		original = append(original, form.instruction(23, 6))
	}
	var source strings.Builder
	source.WriteString("TEXT fixedEndpoints(SB),4,$0-0\n")
	for _, word := range assembleARM64LLVMWords(t, original, "+fullfp16") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-unknown-freebsd", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"fixedEndpoints": {Name: "fixedEndpoints", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, `"target-features"="+fullfp16"`) {
				t.Fatal("fixed-point half conversions omitted +fullfp16")
			}
			compileLLVMToObject(t, llc, triple, "fixed-conversions.ll", "fixed-conversions.o", ir)
		})
	}
}

func TestARM64RawFixedConversionTargetBoundary(t *testing.T) {
	for _, word := range []string{"0x1ed8fcd7", "0x4f28e631"} {
		source := "TEXT conversion(SB),4,$0-0\nWORD $" + word + "\nRET\n"
		for _, api := range []string{"text", "module", "Go"} {
			for _, triple := range []string{"", "aarch64_be-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
				if _, err := arm64ScalarConversionAPI(t, api, source, triple); !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s WORD %s on %q: want target context, got %v", api, word, triple, err)
				}
			}
		}
	}
}

func TestCrossLinuxRuntimeMatrixARM64RawFixedConversion(t *testing.T) {
	forms := arm64FixedConversionCases(false)
	instructions := make([]string, 0, len(forms))
	for _, form := range forms {
		instructions = append(instructions, form.instruction(23, 6))
	}
	encodings := assembleARM64LLVMWords(t, instructions, "+fullfp16")
	cases := make([]arm64NativeConversionCase, 0, len(forms))
	for index, form := range forms {
		inputBits := form.floatBits
		if form.toFloat {
			inputBits = form.integerBits
		}
		cases = append(cases, arm64NativeConversionCase{
			word: encodings[index], instruction: instructions[index], inputBits: inputBits,
			inputGP: form.gp && form.toFloat, outputGP: form.gp && !form.toFloat, inputInt: form.toFloat,
		})
	}
	runARM64NativeConversionCases(t, cases)
}
