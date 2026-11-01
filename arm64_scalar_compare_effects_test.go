package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestARM64ScalarCompareNativeEffectsRemainSourceBound(t *testing.T) {
	for _, row := range arm64CompareCases([]int{0, 31}, false) {
		if row.dead {
			continue
		}
		for _, initialized := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/initialized=%t", row.instruction(), initialized), func(t *testing.T) {
				ctx, flow := arm64FlagScratchBankFixture()
				flow.used, flow.entry = true, &ARM64GoRegisterABI{}
				ctx.vRegSlot = map[int]string{row.left: "%left", row.right: "%right"}
				if initialized {
					ctx.recordMachineRegister(Reg(fmt.Sprintf("F%d", row.left)), row.bits, true)
					if !row.zero {
						ctx.recordMachineRegister(Reg(fmt.Sprintf("F%d", row.right)), row.bits, true)
					}
				}
				file, err := Parse(ArchARM64, "TEXT effect(SB),4,$0-0\n"+row.instruction()+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				instruction := file.Funcs[0].Instrs[0]
				if instruction.Op == OpTEXT {
					instruction = file.Funcs[0].Instrs[1]
				}
				before, start := len(flow.blocks[0].effects), ctx.b.Len()
				matched, _, err := ctx.lowerARM64ScalarFloatCompare(instruction.Op, instruction)
				if !matched || err != nil {
					t.Fatalf("typed native lowerer: matched=%t err=%v", matched, err)
				}
				ctx.recordMachineOpaqueIR(start, instruction)
				reads, flags := 0, arm64FlagMask(0)
				for _, effect := range flow.blocks[0].effects[before:] {
					if effect.opaque || effect.store || effect.unavailable {
						t.Fatalf("native compare gained an unrelated effect: %+v", effect)
					}
					if effect.nzcv != 0 {
						if !effect.write {
							t.Fatal("compare read an incoming NZCV bit")
						}
						flags |= effect.nzcv
					} else {
						if effect.write || !strings.HasPrefix(effect.register, "V") || effect.width != row.bits {
							t.Fatalf("compare changed source width or wrote a register: %+v", effect)
						}
						reads++
					}
				}
				wantReads := 2
				if row.zero {
					wantReads = 1
				}
				if reads != wantReads || flags != arm64FlagAll {
					t.Fatalf("got reads=%d flags=%x", reads, flags)
				}
				err = flow.validate()
				if initialized && err != nil || !initialized && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("native compare invented initialized source registers: %v", err)
				}
				// The exact paired callout is not a whitelist for another native
				// callout, even if it appears in the same source instruction.
				start = ctx.b.Len()
				fmt.Fprintln(ctx.b, `  call void asm sideeffect "nop", ""()`)
				ctx.recordMachineOpaqueIR(start, instruction)
				if !flow.blocks[0].effects[len(flow.blocks[0].effects)-1].opaque {
					t.Fatal("compare callout proof leaked to unrelated native IR")
				}
			})
		}
	}
}
