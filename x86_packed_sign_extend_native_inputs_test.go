package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Exact-width volatile and conditional-lane IR witnesses are object/source
// obligations, not a claim that original AVX512 instructions ran on this host.
func TestX86PackedSignExtendE5DeadReadsAndActualNativeInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, triple := 8, "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, triple = 4, "MOVL", "i386-unknown-linux-gnu"
		}
		type example struct {
			name, source, missing string
			tuple, bits           int
			masked                bool
		}
		var examples []example
		var prior strings.Builder
		for _, ratio := range x86PackedSignExtendOracleRatios {
			for _, shape := range []struct {
				prefix, bank, mode string
				width              int
			}{
				{"P", "X", "plain", 16}, {"VP", "X", "plain", 16},
				{"VP", "Y", "plain", 32}, {"VP", "Z", "plain", 64},
				{"VP", "Z", "merge", 64}, {"VP", "Z", "zero", 64},
			} {
				for _, missing := range []string{"none", "pointer", "index", "mask", "old"} {
					if missing == "mask" && shape.mode == "plain" || missing == "old" && shape.mode != "merge" {
						continue
					}
					name := fmt.Sprint("Native", len(examples))
					var source strings.Builder
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+%d(FP),DI\n", name, 2*word+4, move, word)
					if missing != "pointer" {
						fmt.Fprintf(&source, "%s p+0(FP),BX\n", move)
					}
					if missing != "old" {
						source.WriteString("VPXORD Z1,Z1,Z1\n")
					}
					if missing != "mask" {
						fmt.Fprintf(&source, "MOVL mask+%d(FP),AX\nKMOVD AX,K1\n", 2*word)
					}
					op, memory, mask := shape.prefix+"MOVSX"+ratio.suffix, "(BX)", ""
					if missing == "index" {
						memory = "(BX)(SI*2)"
					}
					if shape.mode != "plain" {
						mask = "K1,"
						if shape.mode == "zero" {
							op += ".Z"
						}
					}
					fmt.Fprintf(&source, "%s %s,%s%s1\n", op, memory, mask, shape.bank)
					if missing == "old" {
						// A real complete-width consumer observes inactive merge bytes;
						// dead unknown bytes alone do not justify an input rejection.
						source.WriteString("VMOVUPS Z1,(DI)\n")
					}
					source.WriteString("RET\n")
					prior.WriteString(source.String())
					examples = append(examples, example{name, source.String(), missing,
						shape.width * ratio.input / ratio.output, ratio.input * 8, shape.mode != "plain"})
				}
			}
		}
		x86LEAActualTargetGoObject(t, arch, triple, prior.String())
		for _, row := range examples {
			t.Run(arch+"/"+row.name+"/"+row.missing, func(t *testing.T) {
				declaration := fmt.Sprintf("func %s(p,out *[64]byte,mask uint32)", row.name)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, row.source, declaration, arch, triple, api)
					if row.missing != "none" {
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("dead/E5 widening invented a pointer/index/mask/observed merge input", api, err)
						}
						continue
					}
					if err != nil || ir == "" {
						t.Fatal("complete original native signed shrinking tuple rejected", api, err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						body := x86StringMemoryFunction(t, text, row.name)
						witness := fmt.Sprintf("load volatile <%d x i8>", row.tuple)
						if row.masked {
							witness = fmt.Sprintf("load volatile i%d", row.bits)
							if !strings.Contains(body, "br i1") {
								t.Fatal("E5 did not retain actual conditional input-lane fault suppression", api)
							}
						}
						if !strings.Contains(body, witness) {
							t.Fatal("dead result lost its exact shrinking native input access", api, witness)
						}
					}
				}
			})
		}
	}
}
