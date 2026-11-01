package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func x86StringCompareModelSite(t *testing.T, arch, opcode, prefix string) (*x86ResultStringMemoryPlan, int, Instr) {
	t.Helper()
	body := "TEXT compare(SB),4,$0-0\n"
	if prefix != "" {
		body += prefix + "\n"
	}
	file, err := Parse(ArchAMD64, body+opcode+"\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := x86ResultStringMemorySourcePlan(file.Funcs[0], arch)
	if err != nil || plan == nil || len(plan.bodies) != 1 {
		t.Fatal("complete source model lost its typed compare", err)
	}
	for ordinal, site := range plan.bodies {
		return plan, ordinal, site.instruction
	}
	t.Fatal("missing source comparison")
	return nil, 0, Instr{}
}

func TestX86StringCompareTypedContinuationChangesOnlyActualOutputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		widths := "BWLQ"
		if arch == "386" {
			widths = "BWL"
		}
		for _, stem := range []string{"SCAS", "CMPS"} {
			for _, width := range widths {
				for _, prefix := range []string{"", "REP", "REPN"} {
					for _, count := range []x86ResultStringCount{x86StringCountUnknown, x86StringCountZero, x86StringCountNonzero} {
						for _, direction := range []x86ResultDirection{x86ResultDirectionForward, x86ResultDirectionBackward, x86ResultDirectionEither} {
							t.Run(fmt.Sprintf("%s/%s%c/%s/%d/%d", arch, stem, width, prefix, count, direction), func(t *testing.T) {
								plan, ordinal, ins := x86StringCompareModelSite(t, arch, stem+string(width), prefix)
								state := x86ResultState{flags: x86ByteFlagCF | x86ByteFlagAF, direction: direction, stringCount: count}
								state.gp[0], state.gp[1], state.gp[3] = 0xff, 0xff, 0x55
								state.canonicalGP[0], state.canonicalGP[1], state.canonicalGP[3] = 0xa5, 0xff, 0x55
								for _, index := range []int{3, 6, 7} {
									state.pointerGP[index], state.callerAddressGP[index], state.callerAddressOrigin[index] = true, true, uint16(index+1)
									state.resultAddressGP[index] = x86ResultSlotAddress{start: 4, end: 8, valid: true}
								}
								expected := state.clone()
								if prefix == "" || count != x86StringCountZero {
									indexes := []int{7}
									if stem == "CMPS" {
										indexes = append(indexes, 6)
									}
									for _, index := range indexes {
										expected.gp[index], expected.canonicalGP[index] = 0, 0
										expected.pointerGP[index] = false
										expected.resultAddressGP[index] = x86ResultSlotAddress{}
									}
									if prefix == "" || count == x86StringCountNonzero {
										expected.flags = x86ByteFlagsAll
									}
									if prefix != "" {
										expected.stringCount, expected.canonicalGP[1] = x86StringCountUnknown, 0
										if arch == "386" {
											expected.canonicalGP[1] = 0xf0
										}
									}
								}
								if accepted, known := plan.transfer(ordinal, ins, &state, arch); !accepted || !known || !reflect.DeepEqual(state, expected) {
									t.Fatal("conditional native comparison changed another byte, identity or FLAGS/DF domain", accepted, known)
								}
								// The shared post-consumer must retain exactly the paired
								// transfer's surviving caller identities and origins.
								before := [16]bool{3: true, 6: true, 7: true}
								origins := [16]uint16{3: 4, 6: 7, 7: 8}
								addresses := x86ResultCallerAddressesAfterTransfer(ins, before, state.callerAddressGP, nil, arch)
								if addresses != expected.callerAddressGP {
									t.Fatal("post-consumer changed the actual conditional caller footprint")
								}
								entry := map[int64]bool{0: true}
								if got := x86ResultCallerOriginsAfter(ins, origins, addresses, entry, arch); got != expected.callerAddressOrigin {
									t.Fatal("revoked caller origins did not match the final address domain")
								}
								transferred := state.callerAddressGP
								transferred[0] = true
								if got := x86ResultCallerAddressesAfterTransfer(ins, before, transferred, nil, arch); got[0] {
									t.Fatal("post-consumer introduced an identity absent before the transfer")
								}
							})
						}
					}
				}
			}
		}
		for _, row := range []struct {
			name, source string
			change       func(*Instr)
		}{
			{name: "operands", source: "SCASB AX"},
			{name: "unrelated-string", source: "MOVSB"},
			{name: "raw", source: "SCASB", change: func(ins *Instr) { ins.x86Encoded = true }},
			{name: "address-override", source: "CMPSB", change: func(ins *Instr) { ins.x86AddressBits = 32 }},
		} {
			t.Run(arch+"/post-consumer/"+row.name, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.source)
				if row.change != nil {
					row.change(&ins)
				}
				before := [16]bool{1: true, 3: true, 6: true, 7: true}
				want := [16]bool{}
				if row.name == "unrelated-string" {
					// MOVS is now independently registered. This post-consumer
					// intersects already accepted reaching facts, not permissions.
					want = before
				}
				if got := x86ResultCallerAddressesAfterTransfer(ins, before, before, nil, arch); got != want {
					t.Fatal("unbound source borrowed the paired string footprint")
				}
			})
		}
	}
}

func TestX86StringCompareCountFactsRevokeAndIntersect(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		move, xor := "MOVL", "XORL"
		if arch == "amd64" {
			move, xor = "MOVQ", "XORQ"
		}
		for _, row := range []struct {
			source string
			want   x86ResultStringCount
		}{
			{move + " $0,CX", x86StringCountZero},
			{move + " $1,CX", x86StringCountNonzero},
			{"MOVL $0,CX", x86StringCountZero},
			{"MOVB $0,CL", x86StringCountUnknown},
			{"MOVB $0,CH", x86StringCountUnknown},
			{"MOVW $0,CX", x86StringCountUnknown},
			{"MOVW AX,CX", x86StringCountUnknown},
			{"MOVL AX,CX", x86StringCountUnknown},
			{xor + " CX,CX", x86StringCountZero},
			{"XORW CX,CX", x86StringCountUnknown},
			{"INCL CX", x86StringCountUnknown},
			{"POPL CX", x86StringCountUnknown},
			{"CALL other(SB)", x86StringCountUnknown},
			{"CMPL AX,AX", x86StringCountNonzero},
			{"MOVL $8,BX", x86StringCountNonzero},
			{"CLD", x86StringCountNonzero},
			{"STD", x86StringCountNonzero},
		} {
			t.Run(arch+"/"+row.source, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.source)
				if got := x86ResultStringCountAfter(ins, x86StringCountNonzero, x86StringCountNonzero, arch); got != row.want {
					t.Fatal("counter fact was inferred from partial or overwritten bytes", got, row.want)
				}
				ins.x86Encoded = true
				if got := x86ResultStringCountAfter(ins, x86StringCountZero, x86StringCountZero, arch); got != x86StringCountUnknown {
					t.Fatal("raw source retained a counter value")
				}
			})
		}
	}
	for _, left := range []x86ResultStringCount{x86StringCountUnknown, x86StringCountZero, x86StringCountNonzero} {
		for _, right := range []x86ResultStringCount{x86StringCountUnknown, x86StringCountZero, x86StringCountNonzero} {
			state := x86ResultState{stringCount: left}
			copy := state.clone()
			copy.stringCount = right
			want := x86StringCountUnknown
			if left == right {
				want = left
			}
			if state.stringCount != left || state.intersect(copy).stringCount != want {
				t.Fatal("counter join created a zero/nonzero value or clone mutated its parent")
			}
		}
	}
}

func TestX86StringComparePlanBindsOriginalPrefixAndBody(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, prefix := range []string{"REP", "REPN"} {
			for _, shape := range []string{"adjacent", "fallthrough-label-chain", "branch-to-prefix", "pc-to-prefix",
				"conditional-bypass", "unreachable-prefix", "backedge-to-body", "pc-bypass", "unknown-indirect"} {
				t.Run(arch+"/"+prefix+"/"+shape, func(t *testing.T) {
					source := "TEXT compare(SB),4,$0-0\n" + x86StringRepeatCFGBody("SCASB", prefix, shape) + "RET\n"
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					plan, err := x86ResultStringMemorySourcePlan(file.Funcs[0], arch)
					positive := shape == "adjacent" || shape == "fallthrough-label-chain" || shape == "branch-to-prefix" || shape == "pc-to-prefix"
					if !positive {
						if err == nil {
							t.Fatal("a branch borrowed its skipped source prefix")
						}
						return
					}
					if err != nil || plan == nil || len(plan.prefixes) != 1 || len(plan.bodies) != 1 {
						t.Fatal("unique complete source binding was lost", err)
					}
					for ordinal, site := range plan.bodies {
						state := x86ResultState{shapeOnly: true}
						if accepted, known := plan.transfer(ordinal, site.instruction, &state, arch); !accepted || !known {
							t.Fatal("bound shape was lost")
						}
						changed := site.instruction
						changed.Raw += " changed"
						if accepted, _ := plan.transfer(ordinal, changed, &state, arch); accepted {
							t.Fatal("another original instruction borrowed the source ordinal")
						}
						if accepted, _ := plan.transfer(ordinal+1, site.instruction, &state, arch); accepted {
							t.Fatal("comparison borrowed another source ordinal")
						}
					}
				})
			}
		}
	}
}
