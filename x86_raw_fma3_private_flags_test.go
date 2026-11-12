package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The saved FLAGS are live across the actual instruction, not synthesized
// after it. FMA changes vector data and MXCSR, but not DF or private storage.
func TestX86RawFMA3PrivateFlagsSpanNativeInstruction(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		suffix := "Q"
		if arch == "386" {
			suffix = "L"
		}
		var original strings.Builder
		var cases []struct{ name, source, declaration, control string }
		for _, row := range []x86RawFMA3SourceCase{
			{op: "VFMADD132PS", opcode: 0x98, bank: "X"},
			{op: "VFNMADD231SD", opcode: 0xbd, bank: "X", evex: true},
		} {
			for _, control := range []string{"named", "raw", "first", "second", "old"} {
				name := row.op + control
				source, declaration := x86RawFMA3InitializedSource(row, arch, name, control, true)
				push := "PUSHF" + suffix + "\n"
				if strings.Count(source, push) != 1 || strings.Count(source, "STD\n") != 1 {
					t.Fatal("saved FLAGS witness lost its exact placement")
				}
				source = strings.Replace(source, push, "", 1)
				source = strings.Replace(source, "STD\n", "STD\n"+push, 1)
				original.WriteString(source)
				cases = append(cases, struct{ name, source, declaration, control string }{name, source, declaration, control})
			}
		}
		// These are original complete programs, including missing-register
		// negatives; Go's assembler permits those encodings but supplies no values.
		x86LEAActualTargetGoObject(t, arch, x86AddressMemoryTargets(arch)[0], original.String())
		for _, row := range cases {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+row.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, row.source, row.declaration, arch, x86AddressMemoryTargets(arch)[0], api)
					if row.control == "named" || row.control == "raw" {
						if err != nil || ir == "" {
							t.Fatal("initialized FMA revoked saved FLAGS or the independently defined DF", err)
						}
					} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("saved FLAGS or an exact origin supplied an absent FMA arithmetic input", err)
					}
				})
			}
		}

		t.Run(arch+"/complete-physical-family-state", func(t *testing.T) {
			push := x86ScalarLaneInstruction(t, "PUSHF"+suffix)
			for index, row := range x86RawFMA3SourceCases() {
				if arch == "386" && row.high {
					continue // The independently checked physical directory excludes these banks.
				}
				ins := x86RawMoveObservedInstruction(t, arch, row.code())
				for _, direction := range []x86ResultDirection{
					x86ResultDirectionUnknown, x86ResultDirectionForward,
					x86ResultDirectionBackward, x86ResultDirectionEither,
				} {
					state := x86FMA3ResultInputState()
					state.pointerGP[0], state.direction = true, direction
					state.valueStack = &x86ResultValueStack{id: true}
					first, second, destination := row.registers()
					for _, register := range []int{first, second, destination} {
						state.writeVector(register, 64, ^uint64(0), false)
					}
					if accepted, known := x86ResultValueStackStep(push, &state, nil, 0, arch); !known || !accepted {
						t.Fatal("independent initialized FLAGS push prerequisite failed")
					}
					before := state.clone()
					if !x86ResultValueStackContinuation(ins, &state, arch) ||
						x86ResultDirectionAfterSource(ins, state.direction, arch) != direction ||
						x86PreservesNumericalSourceState(ins) {
						t.Fatal("exact FMA lost private control or acquired an inert-data role", arch, index, row.instruction(), direction)
					}
					accepted, known := x86ResultFMA3Step(ins, &state, nil, arch, true)
					if !known || !accepted || state.flags != before.flags || state.direction != before.direction ||
						!reflect.DeepEqual(state.valueStack, before.valueStack) {
						t.Fatal("FMA changed saved bytes, ID, FLAGS or DF", arch, index, row.instruction())
					}
					for _, missing := range []int{first, second, destination} {
						if row.memory && missing == first {
							continue // That ordered source is the independently supplied native memory.
						}
						unknown := before.clone()
						unknown.writeVector(missing, 64, 0, false)
						unchanged := unknown.clone()
						accepted, known := x86ResultFMA3Step(ins, &unknown, nil, arch, true)
						if !known || accepted || !reflect.DeepEqual(unknown, unchanged) {
							t.Fatalf("saved FLAGS initialized an absent vector source: %s row=%d register=%d", arch, index, missing)
						}
					}
				}
			}
		})
	}
}
