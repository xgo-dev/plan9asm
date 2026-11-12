package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86ConflictFunnelCompleteIndependentGoRows(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts, total := make(map[string]int), 0
	for _, row := range x86ConflictFunnelRows() {
		for _, rule := range rules {
			if rule.Opcode != row.op {
				continue
			}
			index := counts[row.op]
			counts[row.op]++
			total++
			ytab, zcase := "_yvblendmpd", "Zevex_rm_v_r"
			classes := []string{"YxmEvex,YxrEvex,YxrEvex", "YxmEvex,YxrEvex,Yknot0,YxrEvex",
				"YymEvex,YyrEvex,YyrEvex", "YymEvex,YyrEvex,Yknot0,YyrEvex", "Yzm,Yzr,Yzr", "Yzm,Yzr,Yknot0,Yzr"}
			if index%2 != 0 {
				zcase = "Zevex_rm_v_k_r"
			}
			if row.unary {
				ytab = "_yvexpandpd"
				classes = []string{"YxmEvex,YxrEvex", "YxmEvex,Yknot0,YxrEvex",
					"YymEvex,YyrEvex", "YymEvex,Yknot0,YyrEvex", "Yzm,Yzr", "Yzm,Yknot0,Yzr"}
				if index%2 != 0 {
					zcase = "Zevex_rm_k_r"
				}
			} else if !row.variable {
				ytab, zcase = "_yvalignd", "Zevex_i_rm_v_r"
				if index%2 != 0 {
					zcase = "Zevex_i_rm_v_k_r"
				}
				for i := range classes {
					classes[i] = "Yu8," + classes[i]
				}
			}
			mapName, opcode, w := "evex0F38", "0xC4", 0
			if row.bits != 32 {
				w = 1
			}
			if !row.unary {
				number := 0x70
				if row.bits != 16 {
					number++
				}
				if strings.HasPrefix(row.op, "VPSHR") {
					number += 2
				}
				opcode = fmt.Sprintf("0x%X", number)
				if !row.variable {
					mapName = "evex0F3A"
				}
			}
			var attributes []string
			for _, width := range []int{128, 256, 512} {
				memory := fmt.Sprintf("evexN%d", width/8)
				if row.bits != 16 {
					memory += fmt.Sprintf(" | evexBcstN%d", row.bits/8)
				}
				memory += " | evexZeroingEnabled"
				attributes = append(attributes,
					fmt.Sprintf("avxEscape | evex%d | evex66 | %s | evexW%d", width, mapName, w), memory, opcode)
			}
			if index >= 6 || rule.RowIndex != index || rule.Ytab != ytab || rule.Prefix != "Pavx" ||
				rule.ZCase != zcase || rule.ZOffset != index%2*3 || rule.EncodingOffset != index/2*3 ||
				strings.Join(rule.Classes, ",") != classes[index] || !reflect.DeepEqual(rule.OpBytes, attributes) {
				t.Fatal("complete independent encoder row or opcode attributes changed", row.op, rule)
			}
		}
		if counts[row.op] != 6 {
			t.Fatal("incomplete independent family row inventory", row.op, counts[row.op])
		}
	}
	if len(counts) != 14 || total != 84 {
		t.Fatal("complete conflict/funnel family changed", len(counts), total)
	}
}

func TestX86ConflictFunnelMaskAndOldDestinationRoles(t *testing.T) {
	for _, row := range x86ConflictFunnelRows() {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, mode := range []string{"plain", "merge", "zero"} {
				op, mask := row.op, ""
				if mode != "plain" {
					mask = "K1,"
				}
				if mode == "zero" {
					op += ".Z"
				}
				ins := x86ScalarLaneInstruction(t, x86ConflictFunnelInstruction(op, bank, bank+"0", mask, row.unary, row.variable))
				for _, missing := range []string{"none", "mask", "old"} {
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
					state.writeVector(0, 64, ^uint64(0), false)
					state.writeVector(1, 64, ^uint64(0), false)
					state.masks[1] = missing != "mask"
					if missing != "old" {
						state.writeVector(2, 64, ^uint64(0), false)
					}
					before := state.clone()
					want := !(missing == "mask" && mode != "plain" || missing == "old" && (row.variable || mode == "merge"))
					if accepted := x86ResultTransfer(ins, &state, nil, 0, "amd64"); accepted != want {
						t.Fatal("mask merge and old data inputs were conflated", row.op, bank, mode, missing, accepted, want)
					}
					if !want && !reflect.DeepEqual(state, before) {
						t.Fatal("rejected input mutated reaching numerical state")
					}
				}
				effect, known, err := x86TypedConflictFunnelByteEffect(ins.Op, ins, "amd64")
				if !known || err != nil || !effect.requiresResultProof {
					t.Fatal("complete typed byte shape omitted an input obligation", row.op, err)
				}
				writes := 0
				for _, operand := range effect.operands {
					if operand.write {
						writes++
						if operand.read != (row.variable || mode == "merge") || operand.width != int64(amd64VectorByteWidth(Reg(bank+"0"))) {
							t.Fatal("typed numerical destination role changed", row.op, mode, operand)
						}
					}
				}
				if writes != 1 {
					t.Fatal("unexpected typed destination inventory", writes)
				}
			}
		}
	}
}

func TestX86ConflictFunnelRejectsUnresolvedShapesBeforeIR(t *testing.T) {
	for _, row := range x86ConflictFunnelRows() {
		for _, mutation := range []string{"suffix", "offset", "extension", "segment", "index", "absolute", "dispatch", "float", "unresolved"} {
			if row.unary || row.variable {
				if mutation == "float" || mutation == "unresolved" {
					continue
				}
			}
			t.Run(row.op+"/"+mutation, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, x86ConflictFunnelInstruction(row.op, "X", "(AX)", "", row.unary, row.variable))
				source := 0
				if !row.unary && !row.variable {
					source = 1
				}
				op := ins.Op
				switch mutation {
				case "suffix":
					op += ".SAE"
					ins.Op = op
				case "offset":
					ins.Args[source].Mem.OffRaw = "UNKNOWN"
				case "extension":
					ins.Args[source].Mem.IndexExt = "UXTW"
				case "segment":
					ins.Args[source].Mem.Segment = "DS"
				case "index":
					ins.Args[source].Mem.Index, ins.Args[source].Mem.Scale = SP, 2
				case "absolute":
					ins.Args[source] = Operand{Kind: OpSym, Sym: "4294967296"}
				case "dispatch":
					ins.Op = "VPXORD"
				case "float":
					ins.Args[0].ImmIsFloat = true
				case "unresolved":
					ins.Args[0].ImmRaw = "UNKNOWN"
				}
				var ir strings.Builder
				consumer := &amd64Ctx{b: &ir, goarch: "amd64"}
				var known bool
				var err error
				if row.unary {
					known, _, err = consumer.lowerPackedConflict(op, ins)
				} else {
					known, _, err = consumer.lowerFunnelShift(op, ins)
				}
				if !known || err == nil || ir.Len() != 0 {
					t.Fatal("invalid original shape reached IR or an unknown dispatch", known, err, ir.String())
				}
			})
		}
	}
}

func TestX86ConflictFunnelNativeContinuationKeepsAddressAndOriginBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ConflictFunnelRows() {
			if arch == "386" && !row.unary && !row.variable {
				continue
			}
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, x86ConflictFunnelInstruction(row.op, "X", "-1(SI)(BX*2)", "", row.unary, row.variable))
				state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				state.writeVector(1, 64, ^uint64(0), false)
				state.writeVector(2, 64, ^uint64(0), false)
				state.pointerGP[6], state.gp[3] = true, 0xff
				before := state.clone()
				if accepted := x86ResultTransfer(ins, &state, nil, 0, arch); accepted || !reflect.DeepEqual(state, before) {
					t.Fatal("standalone observer acquired a paired native read")
				}
				want := before.clone()
				want.writeVector(2, 16, 0xffff, false)
				accepted, known := x86LoweredFixedVectorNativeRead(ins, &state, nil, arch)
				if !accepted || !known || !reflect.DeepEqual(state, want) {
					t.Fatal("paired native read lost its exact output or changed independent state", accepted, known)
				}
				for _, mutation := range []string{"pointer", "index", "pointer-index", "raw", "encoded", "address", "segment", "raw-return"} {
					input, changed := before.clone(), ins
					switch mutation {
					case "pointer":
						input.pointerGP[6] = false
					case "index":
						input.gp[3] = 1
					case "pointer-index":
						input.pointerGP[3], input.gp[3] = true, 0
					case "raw":
						changed.x86SourceRaw = new(x86SourceRawInstruction)
					case "encoded":
						changed.x86Encoded = true
					case "address":
						changed.x86AddressBits = 32
					case "segment":
						changed.x86SegmentPrefix = 0x64
					case "raw-return":
						changed.x86RawNearReturn = new(x86RawNearReturnForm)
					}
					original := input.clone()
					if accepted, _ := x86LoweredFixedVectorNativeRead(changed, &input, nil, arch); accepted || !reflect.DeepEqual(input, original) {
						t.Fatal("unproved source or address acquired native result bytes", mutation)
					}
				}
			})
		}
	}
}

func TestX86ConflictFunnelZeroMasksRetainDistinctNativeReads(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, move := goWordSize(target.arch), "MOVQ"
		if word == 4 {
			move = "MOVL"
		}
		for _, row := range x86ConflictFunnelRows() {
			if target.arch == "386" && !row.unary && !row.variable {
				continue
			}
			for _, bank := range []string{"X", "Y", "Z"} {
				for _, broadcast := range []bool{false, true} {
					if broadcast && row.bits == 16 {
						continue
					}
					op, mask := row.op, "K1,"
					if broadcast {
						op += ".BCST"
					}
					masked := target.arch != "386" || row.unary
					if masked {
						op += ".Z"
					} else {
						mask = ""
					}
					instruction := x86ConflictFunnelInstruction(op, bank, "(AX)", mask, row.unary, row.variable)
					width := amd64VectorByteWidth(Reg(bank + "0"))
					t.Run(target.triple+"/"+strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
						source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s p+0(FP),AX\n"+
							"MOVL $0,BX\nKMOVD BX,K1\nVPXORD Z1,Z1,Z1\nVPXORD Z2,Z2,Z2\n%s\nRET\n", word, move, instruction)
						x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *[64]byte)", target.arch, target.triple, api)
							if err != nil {
								t.Fatal("complete dead native source rejected", api, err)
							}
							optimized := x86DwordProductIROptimize(t, ir)
							if !row.unary && masked {
								if !strings.Contains(ir, fmt.Sprintf("load volatile i%d", row.bits)) || strings.Contains(optimized, "load volatile") {
									t.Fatal("E4 zero mask failed to suppress only its native lane reads", api)
								}
							} else {
								bytes := width
								if broadcast {
									bytes = row.bits / 8
								}
								load := fmt.Sprintf("load volatile <%d x i8>", bytes)
								if strings.Count(ir, load) != 1 || strings.Count(optimized, load) != 1 {
									t.Fatal("E4NF or unmasked source lost its exact complete tuple", api, load)
								}
							}
						}
					})
				}
			}
		}
	}
}
