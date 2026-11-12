package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independent sibling inventory: MOVS/STOS/LODS share the existing twenty
// Go ynone rows, but not the comparison family's FLAGS or conditional exit.
func TestX86StringLoadStorePairedEffectsCompleteFamily(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		widths := "BWLQ"
		if arch == "386" {
			widths = "BWL"
		}
		for _, stem := range []string{"MOVS", "STOS", "LODS"} {
			for index, suffix := range widths {
				width := []int{1, 2, 4, 8}[index]
				for _, prefix := range []string{"", "REP", "REPN"} {
					for _, count := range []x86ResultStringCount{x86StringCountUnknown, x86StringCountZero, x86StringCountNonzero} {
						for _, direction := range []x86ResultDirection{x86ResultDirectionForward, x86ResultDirectionBackward, x86ResultDirectionEither} {
							t.Run(fmt.Sprintf("%s/%s%c/%s/count%d/DF%d", arch, stem, suffix, prefix, count, direction), func(t *testing.T) {
								source := "TEXT strings(SB),4,$0-0\n"
								if prefix != "" {
									source += prefix + "\n"
								}
								file, err := Parse(ArchAMD64, source+stem+string(suffix)+"\nRET\n")
								if err != nil {
									t.Fatal(err)
								}
								plan, err := x86ResultStringMemorySourcePlan(file.Funcs[0], arch)
								if err != nil || plan == nil || len(plan.bodies) != 1 {
									t.Fatal("shared typed string grammar omitted the complete load/store sibling", err)
								}
								for ordinal, site := range plan.bodies {
									state := x86ResultState{flags: x86ByteFlagCF | x86ByteFlagAF, direction: direction, stringCount: count}
									state.gp[0], state.gp[1], state.gp[3] = 0xff, 0xff, 0x55
									if stem == "LODS" {
										state.gp[0] = 0xf0 // Unspecified accumulator low bytes stay unspecified on count0.
									}
									state.canonicalGP[0] = 0xa0
									for _, register := range []int{6, 7} {
										state.pointerGP[register], state.callerAddressGP[register] = true, true
										state.callerAddressOrigin[register] = uint16(register + 1)
									}
									expected := state.clone()
									if prefix == "" || count != x86StringCountZero {
										indexes := []int{7}
										if stem == "LODS" {
											indexes = []int{6}
											mask := uint8((uint16(1) << uint(width)) - 1)
											if prefix == "" || count == x86StringCountNonzero {
												expected.gp[0] |= mask
											}
											expected.canonicalGP[0] &^= mask
											if width == 4 && (prefix == "" || count == x86StringCountNonzero) {
												expected.gp[0] |= 0xf0
												expected.canonicalGP[0] |= 0xf0
											}
										} else if stem == "MOVS" {
											indexes = append(indexes, 6)
										}
										for _, register := range indexes {
											expected.pointerGP[register] = false
										}
										if prefix != "" {
											// Unlike SCAS/CMPS, every completed repeated transfer
											// consumes the entire counter; no predicate exits early.
											expected.gp[1], expected.canonicalGP[1] = 0xff, 0xff
											expected.stringCount = x86StringCountZero
										}
									}
									if accepted, known := plan.transfer(ordinal, site.instruction, &state, arch); !accepted || !known || !reflect.DeepEqual(state, expected) {
										t.Fatal("native transfer lost conditional bytes, zero counter or independent FLAGS/DF", accepted, known)
									}
								}
							})
						}
					}
				}
			}
		}
	}
}

// Each operation owns at most 48 functions, below the existing 64-function
// object batch bound. The independent effect matrix above owns sparse-byte,
// count and direction semantics; these are actual initialized public entries.
func TestX86StringLoadStoreInitializedFiveTargetThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		word, move, widths := 8, "MOVQ", "BWLQ"
		if target.arch == "386" {
			word, move, widths = 4, "MOVL", "BWL"
		}
		for _, stem := range []string{"MOVS", "STOS", "LODS"} {
			t.Run(target.triple+"/"+stem, func(t *testing.T) {
				var source, declaration strings.Builder
				count := 0
				for _, suffix := range widths {
					for _, prefix := range []string{"", "REP", "REPN"} {
						for _, iterations := range []int{0, 3} {
							for _, backward := range []bool{false, true} {
								name := fmt.Sprintf("%s%c_%s_%d_%t", stem, suffix, prefix, iterations, backward)
								fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s src+0(FP),SI\n%s dst+%d(FP),DI\n%s value+%d(FP),AX\n%s $%d,CX\n",
									name, 4*word, move, move, word, move, 2*word, move, iterations)
								if backward {
									source.WriteString("STD\n")
								} else {
									source.WriteString("CLD\n")
								}
								if prefix != "" {
									source.WriteString(prefix + "\n")
								}
								fmt.Fprintf(&source, "%s%c\nCLD\n%s AX,ret+%d(FP)\nRET\n", stem, suffix, move, 3*word)
								fmt.Fprintf(&declaration, "func %s(src,dst *byte,value uintptr) uintptr\n", name)
								count++
							}
						}
					}
				}
				if count != len(widths)*12 || count > 64 {
					t.Fatal("complete independent string object inventory changed", count)
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declaration.String(), target.arch, target.triple, api)
					if err != nil {
						t.Fatal("initialized string sibling lost its complete source proof", api, err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				}
			})
		}
	}
}
