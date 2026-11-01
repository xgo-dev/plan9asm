package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// Independent of the production maps: six compress and six inverse-expand
// opcodes, including floating spellings whose lanes are transported as bits.
var x86CompactExpandResultMembers = []string{
	"VCOMPRESSPS", "VCOMPRESSPD", "VPCOMPRESSB", "VPCOMPRESSW", "VPCOMPRESSD", "VPCOMPRESSQ",
	"VEXPANDPS", "VEXPANDPD", "VPEXPANDB", "VPEXPANDW", "VPEXPANDD", "VPEXPANDQ",
}

func x86CompactExpandResultInstruction(op, bank, mode string) string {
	if mode == "unmasked" {
		return fmt.Sprintf("%s %s0,%s1", op, bank, bank)
	}
	if mode == "zero" {
		op += ".Z"
	}
	return fmt.Sprintf("%s %s0,K1,%s1", op, bank, bank)
}

func TestX86PackedCompactExpandRegisterAvailability(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86CompactExpandResultMembers {
			for _, width := range []struct {
				bank  string
				bytes int
			}{{"X", 16}, {"Y", 32}, {"Z", 64}} {
				for _, mode := range []string{"unmasked", "merge", "zero"} {
					t.Run(arch+"/"+op+"/"+width.bank+"/"+mode, func(t *testing.T) {
						ins := x86ScalarLaneInstruction(t, x86CompactExpandResultInstruction(op, width.bank, mode))
						state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
						state.writeVector(0, 64, ^uint64(0), false)
						if mode == "merge" {
							state.writeVector(1, 64, ^uint64(0), false)
						}
						state.masks[1] = mode != "unmasked"
						before := state.clone()
						if !x86ResultTransfer(ins, &state, nil, 0, arch) {
							t.Fatal("complete Go register compaction/expansion lacks a numerical effect", ins.Raw)
						}
						before.writeVector(1, width.bytes, x86CallerVectorByteMask(int64(width.bytes)), false)
						if !reflect.DeepEqual(state, before) {
							t.Fatal("vector result failed to clear wider aliases or changed mask/FLAGS/DF", ins.Raw)
						}
					})
				}
			}
		}
	}
}

func TestX86PackedCompactExpandMissingInputsRemainUnknown(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86CompactExpandResultMembers {
			for _, width := range []struct {
				bank  string
				bytes int
			}{{"X", 16}, {"Y", 32}, {"Z", 64}} {
				t.Run(arch+"/"+op+"/"+width.bank, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, x86CompactExpandResultInstruction(op, width.bank, "merge"))
					for _, unknown := range []string{"source", "mask", "merge"} {
						for missing := 0; missing < width.bytes; missing++ {
							state := x86ResultState{masks: [8]bool{1: unknown != "mask"}}
							for index := 0; index < 2; index++ {
								bits := ^uint64(0)
								if index == 0 && unknown == "source" || index == 1 && unknown == "merge" {
									bits &^= uint64(1) << uint(missing)
								}
								state.writeVector(index, 64, bits, false)
							}
							before := state.clone()
							if x86ResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
								t.Fatalf("unknown %s/%d became a vector value", unknown, missing)
							}
						}
					}
				})
			}
		}
	}
}

func TestX86PackedCompactExpandResultThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range x86CompactExpandResultMembers {
			for _, bank := range []string{"X", "Y", "Z"} {
				for _, mode := range []string{"unmasked", "merge", "zero"} {
					row := x86CompactExpandResultInstruction(op, bank, mode)
					source := "TEXT ·Value(SB),4,$0-4\nMOVL $7,AX\nKMOVD AX,K1\n" +
						"VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n" + row +
						"\nPEXTRD $0,X1,AX\nMOVL AX,ret+0(FP)\nRET\n"
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(target.triple+"/"+op+"/"+bank+"/"+mode+"/"+api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32", target.arch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("complete initialized register form rejected", err)
							}
							if !x86CompactExpandZeroReturn(t, ir) {
								t.Fatal("complete constant compact/expand fixture does not return zero")
							}
						})
					}
				}
			}
		}
	}
}

func TestX86PackedCompactExpandCannotBypassWholeSourceProof(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range x86CompactExpandResultMembers {
			for _, unknown := range []string{"source", "mask", "result"} {
				setup := "VPXORD Z1,Z1,Z1\n"
				if unknown != "source" {
					setup += "VPXORD Z0,Z0,Z0\n"
				}
				if unknown != "mask" {
					setup += "MOVL $7,AX\nKMOVD AX,K1\n"
				}
				source := "TEXT ·Value(SB),4,$0-0\n" + setup + op + " Z0,K1,Z1\nRET\n"
				decl := "func Value()"
				if unknown == "result" {
					source = "TEXT ·Value(SB),4,$0-4\n" + setup + op + " Z0,K1,Z1\nRET\n"
					decl = "func Value() uint32"
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+op+"/"+unknown+"/"+api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, decl, target.arch, target.triple, api)
						if err == nil || ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("unknown input/result bypassed complete numerical proof", err)
						}
					})
				}
			}
		}
	}
}
