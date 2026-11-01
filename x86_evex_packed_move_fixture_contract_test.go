package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// These two builders mechanically retain the old complete format sources.
// No input producer or native entry contract is implied by their Void headers.
func x86EVEXPackedIntegerMoveOriginalSource(arch string) string {
	zregs := []int{0, 21}
	if arch == "386" {
		zregs = []int{0, 7}
	}
	var src strings.Builder
	src.WriteString("TEXT evexpackedintegermoveforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"VMOVDQA32", "VMOVDQA64", "VMOVDQU8", "VMOVDQU16", "VMOVDQU32", "VMOVDQU64"} {
		for _, width := range []string{"X", "Y"} {
			fmt.Fprintf(&src, "\t%s %s0, %s1\n", op, width, width)
			fmt.Fprintf(&src, "\t%s %s20, (AX)\n", op, width)
			fmt.Fprintf(&src, "\t%s (AX), %s21\n", op, width)
			fmt.Fprintf(&src, "\t%s %s1, K1, %s2\n", op, width, width)
			fmt.Fprintf(&src, "\t%s %s1, K2, (AX)\n", op, width)
			fmt.Fprintf(&src, "\t%s (AX), K3, %s2\n", op, width)
			fmt.Fprintf(&src, "\t%s.Z %s1, K4, %s2\n", op, width, width)
			fmt.Fprintf(&src, "\t%s.Z %s1, K5, (AX)\n", op, width)
			fmt.Fprintf(&src, "\t%s.Z (AX), K6, %s2\n", op, width)
		}
		fmt.Fprintf(&src, "\t%s Z%d, Z%d\n", op, zregs[0], zregs[1])
		fmt.Fprintf(&src, "\t%s Z%d, (AX)\n", op, zregs[0])
		fmt.Fprintf(&src, "\t%s (AX), Z%d\n", op, zregs[1])
		fmt.Fprintf(&src, "\t%s Z%d, K1, Z%d\n", op, zregs[0], zregs[1])
		fmt.Fprintf(&src, "\t%s.Z Z%d, K2, (AX)\n", op, zregs[0])
		fmt.Fprintf(&src, "\t%s.Z (AX), K3, Z%d\n", op, zregs[1])
	}
	src.WriteString("\tRET\n")
	return src.String()
}

func x86EVEXPackedFloat386OriginalSource() string {
	var src strings.Builder
	src.WriteString("TEXT packedfloatmoveforms386(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"VMOVAPD", "VMOVAPS", "VMOVUPD", "VMOVUPS"} {
		for _, width := range []string{"X", "Y"} {
			fmt.Fprintf(&src, "\t%s %s0, %s1\n", op, width, width)
			fmt.Fprintf(&src, "\t%s %s20, %s21\n", op, width, width)
			fmt.Fprintf(&src, "\t%s %s20, (AX)\n", op, width)
			fmt.Fprintf(&src, "\t%s (AX), %s21\n", op, width)
			fmt.Fprintf(&src, "\t%s %s20, K1, %s21\n", op, width, width)
			fmt.Fprintf(&src, "\t%s.Z %s20, K2, (AX)\n", op, width)
			fmt.Fprintf(&src, "\t%s.Z (AX), K3, %s21\n", op, width)
		}
		fmt.Fprintf(&src, "\t%s Z0, Z7\n", op)
		fmt.Fprintf(&src, "\t%s Z7, (AX)\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Z7\n", op)
		fmt.Fprintf(&src, "\t%s Z0, K1, Z7\n", op)
		fmt.Fprintf(&src, "\t%s.Z Z0, K2, (AX)\n", op)
		fmt.Fprintf(&src, "\t%s.Z (AX), K3, Z7\n", op)
	}
	src.WriteString("\tRET\n")
	return src.String()
}

func TestX86EVEXPackedMoveOriginalFormatsNeedActualInputs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			sources := []string{x86EVEXPackedIntegerMoveOriginalSource(target.arch)}
			if target.arch == "386" {
				sources = append(sources, x86EVEXPackedFloat386OriginalSource())
			}
			for _, source := range sources {
				// The real original high-bank source is accepted by Go but has
				// neither numerical inputs nor a physical mode32 bank contract.
				x86UnboundVoidFormatSources(t, source, target.arch, target.triple)
				if target.arch == "386" {
					physical := x86PhysicalMode32ObjectSource(t, source, target.arch)
					x86UnboundVoidFormatSources(t, physical, target.arch, target.triple)
				}
			}
		})
	}
}

// An independent initialized program covers every ordinary direction and
// mask/merge/zero row for all six integer and four floating EVEX move names.
// Memory .Z is deliberately separate: its actual encoding raises #UD, as
// TestX86PackedZeroMemoryStoreActualGoAndLLVM22Encoding independently checks.
var x86EVEXPackedMoveFixtureNames = []string{
	"VMOVDQA32", "VMOVDQA64", "VMOVDQU8", "VMOVDQU16", "VMOVDQU32", "VMOVDQU64",
	"VMOVAPD", "VMOVAPS", "VMOVUPD", "VMOVUPS",
}

func x86EVEXPackedMoveInitializedProgram(arch string) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	var source, declarations strings.Builder
	count := 0
	for _, op := range x86EVEXPackedMoveFixtureNames {
		for _, bank := range []string{"X", "Y", "Z"} {
			fmt.Fprintf(&declarations, "func Move%d(p *[80]byte)\n", count)
			fmt.Fprintf(&source, "TEXT ·Move%d(SB),4,$0-%d\n%s p+0(FP),AX\nMOVL $3,CX\nKMOVD CX,K1\n", count, word, move)
			for _, register := range []int{0, 1, 2} {
				fmt.Fprintf(&source, "VPXORQ Z%d,Z%d,Z%d\n", register, register, register)
			}
			source.WriteString("STC\n")
			fmt.Fprintf(&source, "%s %s0,%s1\n%s %s0,(AX)\n%s (AX),%s1\n", op, bank, bank, op, bank, op, bank)
			fmt.Fprintf(&source, "%s %s0,K1,%s2\n%s %s0,K1,(AX)\n%s (AX),K1,%s2\n", op, bank, bank, op, bank, op, bank)
			fmt.Fprintf(&source, "%s.Z %s0,K1,%s2\n%s.Z (AX),K1,%s2\nSETCS 64(AX)\nRET\n", op, bank, bank, op, bank)
			count++
		}
	}
	return source.String(), declarations.String()
}

func TestX86EVEXPackedMoveInitializedCompleteRowsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required for complete initialized EVEX move objects")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86EVEXPackedMoveInitializedProgram(target.arch)
			if strings.Count(source, "TEXT ") != 30 || strings.Count(source, "SETCS 64(AX)") != 30 {
				t.Fatal("complete 30-kernel / 240-row initialized directory changed")
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, target.triple, "initialized-evex-moves.ll", "initialized-evex-moves.o", ir)
				})
			}
		})
	}
}

func TestX86EVEXPackedMoveMissingInputDoesNotBorrowVoid(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, move, triple := 8, "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "MOVL", "i386-unknown-linux-gnu"
		}
		for _, op := range x86EVEXPackedMoveFixtureNames {
			for _, missing := range []string{"pointer", "source", "mask"} {
				t.Run(arch+"/"+op+"/"+missing, func(t *testing.T) {
					prefix := fmt.Sprintf("%s p+0(FP),AX\nVPXORQ Z0,Z0,Z0\nMOVL $3,CX\nKMOVD CX,K1\n", move)
					switch missing {
					case "pointer":
						prefix = strings.Replace(prefix, move+" p+0(FP),AX\n", "", 1)
					case "source":
						prefix = strings.Replace(prefix, "VPXORQ Z0,Z0,Z0\n", "", 1)
					case "mask":
						prefix = strings.Replace(prefix, "KMOVD CX,K1\n", "", 1)
					}
					source := fmt.Sprintf("TEXT ·Move(SB),4,$0-%d\n%s%s X0,K1,(AX)\nRET\n", word, prefix, op)
					// Syntactically valid original bytes precede every rejection;
					// missing tools, malformed source or cleanup are never Context.
					x86LEAActualTargetGoObject(t, arch, triple, source)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Move(p *[80]byte)", arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("missing actual EVEX move input acquired a value/address", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86EVEXPackedMoveOriginalSourceDirectoryRemainsExact(t *testing.T) {
	// Filled from the unchanged complete pre-extraction format builders, not
	// from decoder/lowerer tables or from an emitted LLVM representation.
	for _, test := range []struct{ name, source, hash string }{
		{"integer-amd64", x86EVEXPackedIntegerMoveOriginalSource("amd64"), "acf762edc733f65e7870e0ddfd61142804e97907e3885780cca3fc9ca5c53080"},
		{"integer-386", x86EVEXPackedIntegerMoveOriginalSource("386"), "b63d779762db243a58a3f038f6257419b90ada7385a75d48c431524afcb09f5e"},
		{"float-386", x86EVEXPackedFloat386OriginalSource(), "d509224c1e23e5a95863b4157ef8cf2c563f9811467f24cb07a747d4ba058b0f"},
	} {
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(test.source))); got != test.hash {
			t.Fatal("original complete move source changed", test.name, got, test.hash)
		}
	}
}
