package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86MaskBlendVoidAndUnusedBoolNeverSupplyInputs(t *testing.T) {
	for _, row := range x86MaskBlendIndependentRows("amd64") {
		for _, unusedBool := range []bool{false, true} {
			declaration, extent := "func Missing()", 0
			if unusedBool {
				declaration, extent = "func Missing(unused bool)", 1
			}
			source := fmt.Sprintf("TEXT ·Missing(SB),4,$0-%d\n%s\nRET\n", extent, row)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("Void or unused bool supplied unbound blend inputs", row, unusedBool, api, err)
				}
			}
		}
	}
}

// Independent Go _yvblendmpd inventory: six width/mask rows per member,
// register or memory source, with per-opcode broadcast and zeroing attributes.
func x86MaskBlendIndependentRows(arch string) []string {
	var rows []string
	for _, member := range []struct {
		op        string
		broadcast bool
	}{
		{"VBLENDMPS", true}, {"VBLENDMPD", true},
		{"VPBLENDMB", false}, {"VPBLENDMW", false},
		{"VPBLENDMD", true}, {"VPBLENDMQ", true},
	} {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, first := range []string{bank + "0", "(SI)"} {
				rows = append(rows, member.op+" "+first+","+bank+"1,"+bank+"2")
				if arch == "amd64" {
					rows = append(rows, member.op+" "+first+","+bank+"1,K1,"+bank+"2",
						member.op+".Z "+first+","+bank+"1,K1,"+bank+"2")
				}
			}
			if member.broadcast {
				rows = append(rows, member.op+".BCST (SI),"+bank+"1,"+bank+"2")
				if arch == "amd64" {
					rows = append(rows, member.op+".BCST (SI),"+bank+"1,K1,"+bank+"2",
						member.op+".BCST.Z (SI),"+bank+"1,K1,"+bank+"2")
				}
			}
		}
	}
	return rows
}

func TestX86MaskBlendCompleteIndependentGoRows(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		rows := x86MaskBlendIndependentRows(arch)
		want := 48
		if arch == "amd64" {
			want = 144
		}
		if len(rows) != want {
			t.Fatal("independent mask-blend row denominator changed", arch, len(rows))
		}
		requireX86GoAssemblerResult(t, arch,
			"TEXT forms(SB),4,$0-0\n"+strings.Join(rows, "\n")+"\nRET\n", true)
	}
}

func TestX86MaskBlendInitializedNamedFamilyFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("mask-blend complete objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := 8, "MOVQ"
			if target.arch == "386" {
				word, move = 4, "MOVL"
			}
			rows := x86MaskBlendIndependentRows(target.arch)
			for start := 0; start < len(rows); start += 48 {
				end := start + 48
				if end > len(rows) {
					end = len(rows)
				}
				t.Run(fmt.Sprintf("batch-%04d", start), func(t *testing.T) {
					var source, declarations strings.Builder
					for index := start; index < end; index++ {
						name := fmt.Sprintf("Blend%d", index)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),SI\n"+
							"VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\nMOVL $85,CX\nKMOVD CX,K1\n"+
							"%s\nVPEXTRD $0,X2,CX\nMOVL CX,ret+%d(FP)\nRET\n",
							name, word+4, move, rows[index], word)
						fmt.Fprintf(&declarations, "func %s(p *byte) uint32\n", name)
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("initialized full mask-blend family lost its public result", err)
							}
							for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
								for _, level := range []string{"-O0", "-O2"} {
									x86PackedStringCompileObject(t, llc, target.triple, text, level)
								}
							}
						})
					}
				})
			}
		})
	}
}

func TestX86MaskBlendSelectedInputsAndIndependentState(t *testing.T) {
	for _, row := range x86MaskBlendIndependentRows("amd64") {
		ins := x86ScalarLaneInstruction(t, row)
		if ins.Args[0].Kind != OpReg {
			continue // Native memory keeps a separate paired-load obligation.
		}
		width := amd64VectorByteWidth(ins.Args[0].Reg)
		secondRequired := len(ins.Args) == 4 && !strings.HasSuffix(string(ins.Op), ".Z")
		for missingRegister := 0; missingRegister < 2; missingRegister++ {
			for missingByte := 0; missingByte < 64; missingByte++ {
				for _, consumer := range x86ResultGPSIMDConsumers {
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.writeVector(0, 64, ^uint64(0), false)
					state.writeVector(1, 64, ^uint64(0), false)
					state.writeVector(missingRegister, 64, ^uint64(0)&^(uint64(1)<<uint(missingByte)), false)
					state.masks[1] = true
					before := state.clone()
					want := missingByte >= width || missingRegister == 1 && !secondRequired
					if got := consumer.step(ins, &state, nil, 0, "amd64"); got != want {
						t.Fatal("mask blend source selection supplied or demanded unrelated bytes", row, consumer.name, missingRegister, missingByte, got, want)
					}
					if !want {
						if !reflect.DeepEqual(state, before) {
							t.Fatal("rejected mask blend modified source state", row)
						}
						continue
					}
					if state.vectorBytes(2) != ^uint64(0) || state.flags != before.flags || state.gp != before.gp || state.masks != before.masks {
						t.Fatal("mask blend lost upper-zero aliases or unrelated GP/FLAGS/masks", row)
					}
				}
			}
		}
	}
}
