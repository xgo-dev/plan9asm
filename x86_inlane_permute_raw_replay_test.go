package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Raw VPERMIL is not a newly authorized source role. Its existing physical
// decoder and private format objects stay separate from initialized named
// programs. Erasing only a private origin cannot turn the sealed former into
// the latter; a standalone instruction cannot observe this whole-Func fact.
func TestX86InLanePermuteOriginOnlyWholeSourceReplay(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"VPERMILPS", "VPERMILPD"} {
			for _, bank := range []string{"X", "Y", "Z"} {
				for _, immediate := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/immediate=%t", arch, op, bank, immediate), func(t *testing.T) {
						operation := fmt.Sprintf("%s %s0,%s1,%s2", op, bank, bank, bank)
						if immediate {
							operation = fmt.Sprintf("%s $0x1b,%s1,%s2", op, bank, bank)
						}
						code, pcs := x86NumericalBoundaryGoBytes(t, arch, operation+"\nRET")
						if len(pcs) != 2 || pcs[1] != int64(len(code)-1) || code[len(code)-1] != 0xc3 ||
							(bank == "Z") != (code[0] == 0x62) {
							t.Fatal("independent Go bytes/PCs lost the complete low-bank VEX X/Y or EVEX Z instruction", pcs, code)
						}
						zero := "VPXOR"
						if bank == "Z" {
							zero = "VPXORD"
						}
						prefix := "TEXT ·Value(SB),4,$0-4\n"
						for register := 0; register < 3; register++ {
							prefix += fmt.Sprintf("%s %s%d,%s%d,%s%d\n", zero, bank, register, bank, register, bank, register)
						}
						suffix := "MOVL X2,ret+0(FP)\nRET\n"
						namedSource := prefix + operation + "\n" + suffix
						rawSource := prefix + x86RawDisplacementDirectives(code[:pcs[1]]) + suffix
						x86LEAActualTargetGoObject(t, arch, x86AddressMemoryTargets(arch)[0],
							strings.Replace(namedSource, "·Value", "·ReplayNamed", 1)+rawSource)
						strict, check := x86RegisterReplayConsumers(t, arch, namedSource)
						named := mustParseX86RawReturn(t, namedSource).Funcs[0]
						if named.x86RawReplay != nil || strict(named) != nil || check(named) != nil {
							t.Fatal("independent initialized named control must pass its actual strict and lowering consumers")
						}
						file, err := normalizeX86RawFile(mustParseX86RawReturn(t, rawSource), arch)
						if err != nil {
							t.Fatal("actual complete raw VPERMIL normalization prerequisite", err)
						}
						original, ordinal := file.Funcs[0], -1
						for index, ins := range original.Instrs {
							if ins.Op == Op(op) && ins.x86SourceRaw != nil {
								if ordinal >= 0 || ins.x86Encoded {
									t.Fatal("raw VPERMIL origin-only prerequisite lost its unique nonencoded instruction")
								}
								ordinal = index
							}
						}
						if ordinal < 0 || original.x86RawReplay == nil || original.x86RawReplay.validate(original, arch) != nil {
							t.Fatal("complete physical source lost its independently sealed replay")
						}
						if !errors.Is(strict(original), ErrProbeNeedsContext) || !errors.Is(check(original), ErrProbeNeedsContext) {
							t.Fatal("untouched raw source unexpectedly borrowed the named initialized-source role")
						}
						changed := original
						changed.Instrs = cloneX86ReplayInstrs(original.Instrs)
						changed.Instrs[ordinal].x86SourceRaw = nil // The sole mutation; do not also change generation.
						if !x86ResultNamedPredicateInstruction(changed.Instrs[ordinal]) || strict(changed) != nil {
							t.Fatal("origin-only mutation did not reach the actual strict-numerical-success shortcut")
						}
						if changed.x86RawReplay != original.x86RawReplay ||
							!errors.Is(changed.x86RawReplay.validate(changed, arch), ErrProbeNeedsContext) ||
							original.x86RawReplay.validate(original, arch) != nil {
							t.Fatal("origin-only clone changed the original source or failed to retain its restriction")
						}
						if err := check(changed); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("real whole-source consumer accepted an erased raw VPERMIL origin", err)
						}
					})
				}
			}
		}
	}
}
