package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86RawFMA3PhysicalSnapshotRejectsAbsentAndEditedIdentity(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86RawFMA3ObjectCases()[:60] {
			original := x86RawMoveObservedInstruction(t, arch, row.code())
			if !x86RawFMA3Source(original, arch) {
				t.Fatal("original physical source lost its complete FMA identity", arch, row.op)
			}
			for _, mutation := range []string{
				"origin", "snapshot", "snapshot mode", "snapshot generation", "snapshot grammar",
				"generation", "physical generation absent", "grammar", "both generations absent", "vector width", "operand",
			} {
				t.Run(arch+"/"+row.op+"/"+mutation, func(t *testing.T) {
					changed := cloneX86ReplayInstrs([]Instr{original})[0]
					switch mutation {
					case "origin":
						changed.x86SourceRaw = nil
					case "snapshot":
						changed.x86SourceRaw.fma3 = x86RawFMA3Identity{}
					case "snapshot mode":
						changed.x86SourceRaw.fma3.arch = "arm64"
					case "snapshot generation":
						changed.x86SourceRaw.fma3.encoding = x86RawFMA3Absent
					case "snapshot grammar":
						changed.x86SourceRaw.fma3.encoded = !changed.x86SourceRaw.fma3.encoded
					case "generation":
						changed.x86FMA3Encoding = x86RawFMA3VEX
						if original.x86FMA3Encoding == changed.x86FMA3Encoding {
							changed.x86FMA3Encoding = x86RawFMA3EVEX
						}
					case "grammar":
						changed.x86Encoded = !changed.x86Encoded
					case "physical generation absent":
						changed.x86FMA3Encoding = x86RawFMA3Absent
					case "both generations absent":
						changed.x86FMA3Encoding = x86RawFMA3Absent
						changed.x86SourceRaw.fma3.encoding = x86RawFMA3Absent
					case "vector width":
						changed.x86VectorBytes = 7
					case "operand":
						changed.Args[1].Reg = "X7"
					}
					if x86RawFMA3EncodingSource(changed, arch) || x86RawFMA3Source(changed, arch) {
						t.Fatal("absent or edited physical snapshot supplied an original FMA source")
					}
					if !x86RawFMA3Source(original, arch) {
						t.Fatal("mutating a clone corrupted its independent original snapshot")
					}
				})
			}
		}
	}
}

// This batch authorizes matching-x86 original opcodes only. A complete raw
// producer is not a portable MXCSR/dead-read certificate, and cannot borrow
// the ordinary named mathematical fallback or raw-only FP16 owner.
func TestX86RawFMA3InitializedNonmatchingTargetKeepsNativeBoundary(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []x86RawFMA3SourceCase{
			{op: "VFMADD132PS", opcode: 0x98, bank: "X"},
			{op: "VFMADD213SD", opcode: 0xa9, bank: "X", evex: true},
		} {
			for _, memory := range []bool{false, true} {
				row.memory = memory
				source, declaration := x86RawFMA3InitializedSource(row, arch, "Value", "", true)
				// Establish a real matching native owner for the identical source;
				// negative controls cannot pass merely due to absent raw support.
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/memory=%t/%s", arch, row.op, memory, api), func(t *testing.T) {
						if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, x86AddressMemoryTargets(arch)[0], api); err != nil || ir == "" {
							t.Fatal("complete matching native raw FMA positive failed", err)
						}
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, "aarch64-unknown-linux-gnu", api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), row.op) {
							t.Fatal("raw original FMA silently entered the cross-ISA pure arithmetic/dead-read path", err)
						}
					})
				}
			}
		}
	}
}
