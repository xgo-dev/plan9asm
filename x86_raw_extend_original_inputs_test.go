package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86RawExtendOriginalInputSource(t *testing.T, block bool) string {
	t.Helper()
	name := "TestTranslateRawEVEXPackedExtendWeaviateRegression"
	want := "a5c6fa0843f6aa5ce29bd383ca176aa4c00ab8316c9886efb214d3b9ac6447cb"
	if block {
		name = "TestTranslateRawVEXPackedExtendWeaviateBlockRegression"
		want = "c16c5124003d8cf18163d034586f7676da643493c7f4c58fab043a88676e74c3"
	}
	source := x86X87FunctionLiteral(t, "amd64_raw_packed_extend_test.go", name, "source")
	if fmt.Sprintf("%x", sha256.Sum256([]byte(source))) != want {
		t.Fatal("original complete packed-extend block changed", name)
	}
	return source
}

func TestX86RawExtendOriginalMissingInputsRemainContext(t *testing.T) {
	for _, block := range []bool{false, true} {
		source := x86RawExtendOriginalInputSource(t, block)
		file := mustParseX86RawReturn(t, source)
		if len(file.Funcs) != 1 {
			t.Fatal("original packed-extend entry lost its identity")
		}
		name := file.Funcs[0].Sym
		for _, target := range x86RawReturnTargets {
			t.Run(fmt.Sprintf("block=%t/%s", block, target.triple), func(t *testing.T) {
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func "+name+"()", target.arch, target.triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("original bare block invented its native address/vector inputs", api, err)
					}
				}
			})
		}
	}
}

func TestX86RawExtendOriginalInitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, block := range []bool{false, true} {
		original := x86RawExtendOriginalInputSource(t, block)
		header, body, found := strings.Cut(original, "\n")
		if !found || !strings.Contains(header, "$0-0") {
			t.Fatal("original complete packed-extend source lost its TEXT")
		}
		name := mustParseX86RawReturn(t, original).Funcs[0].Sym
		for _, target := range x86RawReturnTargets {
			t.Run(fmt.Sprintf("block=%t/%s", block, target.triple), func(t *testing.T) {
				word, move := 8, "MOVQ"
				if target.arch == "386" {
					word, move = 4, "MOVL"
				}
				// Keep every original opcode and RET. Only this distinct
				// counterpart imports the missing SI/DI pointers, defines the
				// actual AX index and initializes all vector accumulators.
				prefix := fmt.Sprintf("%s\n%s a+0(FP),SI\n%s b+%d(FP),DI\nMOVL $0,AX\nVZEROALL\n",
					strings.Replace(header, "$0-0", fmt.Sprintf("$0-%d", 2*word), 1), move, move, word)
				source := prefix + body
				declaration := "func " + name + "(a,b *[128]byte)"
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete original-byte initialized block lost its paired native reader", api, err)
					}
					if block && strings.Count(ir, "asm sideeffect \"vcvtdq2ps") != 4 {
						t.Fatal("original complete block lost its four floating conversions")
					}
					x86ResultInitializationObject(t, llc, target.triple, ir, "extend-original-"+api)
					x86ResultInitializationObject(t, llc, target.triple, x86SignedIntegerFloatOptimize(t, ir), "extend-original-"+api+"-O2")
				}
			})
		}
	}
}

// Orthogonal raw objects exercise all six unsigned ratios, both source roles
// and all five VEX/EVEX widths. Existing independent encoder and typed-byte
// matrices own the full mask/register/address Cartesian axes separately.
func TestX86RawZeroExtendOrthogonalInitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := 8, "MOVQ"
			if target.arch == "386" {
				word, move = 4, "MOVL"
			}
			var source, declarations strings.Builder
			count := 0
			for opcode := byte(0x30); opcode <= 0x35; opcode++ {
				for shape := 0; shape < 5; shape++ {
					for _, memory := range []bool{false, true} {
						name := fmt.Sprintf("WidenRaw%d", count)
						count++
						code := []byte{0xc4, 0xe2, 0x79 | byte(shape)<<2, opcode, 0xc8}
						if shape >= 2 {
							control := byte(0x09 | (shape-2)<<5)
							if shape == 3 {
								control |= 0x80
							}
							code = []byte{0x62, 0xf2, 0x7d, control, opcode, 0xc8}
						}
						if memory {
							code[len(code)-1] = 0x08 // Exact mN at the imported AX pointer.
						}
						// Only banks 0/1 are read. Their VEX zero producers also
						// define the wider aliases without clearing sixteen banks
						// in every independent object witness.
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nVPXOR Y0,Y0,Y0\nVPXOR Y1,Y1,Y1\nMOVL $5,AX\nKMOVD AX,K1\n%s p+0(FP),AX\n", name, word, move)
						for _, value := range code {
							fmt.Fprintf(&source, "BYTE $%#x\n", value)
						}
						source.WriteString("RET\n")
						fmt.Fprintf(&declarations, "func %s(p *[32]byte)\n", name)
					}
				}
			}
			if count != 60 {
				t.Fatal("incomplete independent raw unsigned widening directory", count)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatal("initialized raw widening family lost its source owner", api, err)
				}
				for _, text := range []string{ir, x86SignedIntegerFloatOptimize(t, ir)} {
					if !strings.Contains(text, "load volatile ") {
						t.Fatal("dead widening results discarded their observable input reads")
					}
					x86ResultInitializationObject(t, llc, target.triple, text, "raw-widen-"+api)
				}
			}
		})
	}
}
