package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestARM64ConditionalCompareSourceBoundEffects(t *testing.T) {
	for _, bits := range []int{16, 32, 64} {
		for _, signaling := range []bool{false, true} {
			for _, condition := range []int{0, 8, 10, 12, 14, 15} {
				form, known := decodeARM64RawConditionalCompare(arm64ConditionalTestWord(bits, condition, 10, 0, 31, signaling))
				if !known {
					t.Fatal("complete typed raw family missing")
				}
				// Every potential input byte is required even when the source
				// predicate happens to be false; it cannot grant caller data.
				for hole := -1; hole < 2*bits/8; hole++ {
					ctx, flow := arm64FlagScratchBankFixture()
					ctx.targetTriple = "aarch64-unknown-linux-gnu"
					ctx.vRegSlot = map[int]string{0: "%left", 31: "%right"}
					flow.used, flow.entry = true, &ARM64GoRegisterABI{}
					for _, slot := range []string{ctx.flagsNSlot, ctx.flagsZSlot, ctx.flagsCSlot, ctx.flagsVSlot} {
						ctx.storeFlag(slot, "false")
					}
					for source, register := range []string{"V0", "V31"} {
						for offset := 0; offset < bits; offset += 8 {
							if hole == source*bits/8+offset/8 {
								continue
							}
							flow.blocks[0].effects = append(flow.blocks[0].effects, arm64MachineEffect{
								register: register, width: 8, vectorOffset: offset, vectorSpan: true, write: true,
							})
						}
					}
					before, start := len(flow.blocks[0].effects), ctx.b.Len()
					if err := ctx.lowerARM64ConditionalCompare(form); err != nil {
						t.Fatal(err)
					}
					ctx.recordMachineOpaqueIR(start, Instr{})
					reads, flagsRead, flagsWritten := 0, arm64FlagMask(0), arm64FlagMask(0)
					for _, effect := range flow.blocks[0].effects[before:] {
						if effect.opaque || effect.store || effect.unavailable {
							t.Fatalf("conditional compare gained unrelated effects: %+v", effect)
						}
						if effect.nzcv != 0 {
							if effect.write {
								flagsWritten |= effect.nzcv
							} else {
								flagsRead |= effect.nzcv
							}
						} else {
							if effect.write || effect.width != bits || effect.register != "V0" && effect.register != "V31" {
								t.Fatalf("conditional compare changed SIMD role: %+v", effect)
							}
							reads++
						}
					}
					wantRead := []arm64FlagMask{arm64FlagZ, arm64FlagC | arm64FlagZ, arm64FlagN | arm64FlagV, arm64FlagN | arm64FlagV | arm64FlagZ, 0, 0}
					index := map[int]int{0: 0, 8: 1, 10: 2, 12: 3, 14: 4, 15: 5}[condition]
					if reads != 2 || flagsWritten != arm64FlagAll || flagsRead != wantRead[index] {
						t.Fatalf("wrong typed reads/effects: reads=%d flags=%x/%x", reads, flagsRead, flagsWritten)
					}
					err := flow.validate()
					if hole < 0 && err != nil || hole >= 0 && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("input byte hole %d width %d condition %d: %v", hole, bits, condition, err)
					}
					start = ctx.b.Len()
					fmt.Fprintln(ctx.b, `  call void asm sideeffect "nop", ""()`)
					ctx.recordMachineOpaqueIR(start, Instr{})
					if !flow.blocks[0].effects[len(flow.blocks[0].effects)-1].opaque {
						t.Fatal("native conditional compare proof leaked to another instruction")
					}
				}
			}
		}
	}
}

func TestARM64ConditionalCompareFlagsFollowWholeCFG(t *testing.T) {
	for _, api := range []string{"text", "module", "Go"} {
		for condition, spelling := range arm64ConditionalTestConditions {
			for _, raw := range []bool{false, true} {
				row := arm64ConditionalTestCase{32, condition, 10, 0, 31, false, raw, false, false}
				for _, complete := range []bool{false, true} {
					prefix := ""
					if complete {
						prefix = "CMP R0,R0\n"
					}
					source := "TEXT comparison(SB),4,$0-0\n" + prefix + "CBZ R0,use\nCMP R0,R0\nuse:\n" + row.instruction() + "\nRET\n"
					present, err := arm64CompareTargetAPI(t, api, source, "aarch64-unknown-linux-gnu")
					if complete || condition >= 14 {
						if !present || err != nil {
							t.Fatalf("%s %s defined CFG rejected: %v", api, spelling, err)
						}
					} else if present || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s %s missing predecessor flags gained output: %t %v", api, spelling, present, err)
					}
				}
			}
		}
	}
}

func TestARM64ConditionalCompareDirectHelperBoundaries(t *testing.T) {
	for _, target := range []string{"", "x86_64-unknown-linux-gnu", "aarch64_be-unknown-linux-gnu"} {
		ctx, _ := arm64FlagScratchBankFixture()
		ctx.targetTriple = target
		instruction := arm64ImmediateTestInstruction(t, "FCCMPS AL,F0,F1,$0")
		known, _, err := ctx.lowerARM64FloatConditionalCompare(instruction.Op, instruction)
		if !known || !errors.Is(err, ErrProbeNeedsContext) || ctx.b.Len() != 0 {
			t.Fatalf("direct helper bypassed target before IR: %t %v", known, err)
		}
	}
	ctx, _ := arm64FlagScratchBankFixture()
	instruction := arm64ImmediateTestInstruction(t, "FCCMPD AL,F0,F1,$0")
	if known, _, err := ctx.lowerARM64FloatConditionalCompare("FADDD", instruction); known || err != nil || ctx.b.Len() != 0 {
		t.Fatal("conditional family claimed an unrelated dispatch operation")
	}
	for _, condition := range []string{"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE"} {
		ctx, _ := arm64FlagScratchBankFixture()
		ctx.targetTriple, ctx.flagsKnown, ctx.flagsWritten = "aarch64-unknown-linux-gnu", 0, false
		instruction := arm64ImmediateTestInstruction(t, "FCCMPS "+condition+",F0,F1,$0")
		known, _, err := ctx.lowerARM64FloatConditionalCompare(instruction.Op, instruction)
		if !known || !errors.Is(err, ErrProbeNeedsContext) || strings.Contains(ctx.b.String(), "asm sideeffect") {
			t.Fatalf("direct helper fabricated source NZCV for %s: %v", condition, err)
		}
	}
}

func TestARM64ConditionalCompareRawPoolRevokesEarlierIntegerFlags(t *testing.T) {
	for _, bits := range []int{16, 32, 64} {
		for _, signaling := range []bool{false, true} {
			for condition := 0; condition < 16; condition++ {
				for flags := 0; flags < 16; flags++ {
					word := arm64ConditionalTestWord(bits, condition, flags, 0, 31, signaling)
					writes, known := arm64RawPoolGPWrites(word)
					if !known || writes != 0 {
						t.Fatalf("raw conditional comparison changed its GP domain: %#08x %x %t", word, writes, known)
					}
					// CMP X1,#7; FCCMP; NOP. The float comparison may write
					// either computed or immediate NZCV, so an old integer bound
					// must not survive merely because there are no GP writes.
					flow := &arm64RawPoolValues{
						words:  []uint32{0xf1001c3f, word, 0xd503201f},
						before: [][]int{{-1}, {0}, {1}},
					}
					if _, _, _, valid := flow.affineFlagSourceBefore(2); valid {
						t.Fatalf("raw FCCMP retained an unrelated integer address bound: %#08x", word)
					}
				}
			}
		}
	}
}
