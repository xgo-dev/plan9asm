package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86IncomingPointerResidueMasksRolesAndByteAliases(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct {
			op    string
			width int64
		}{{"ANDB", 1}, {"ANDW", 2}, {"ANDL", 4}, {"ANDQ", 8}} {
			if arch == "386" && row.width == 8 {
				continue
			}
			for _, register := range strings.Fields("AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R14 R15 AL AH BL BH CL CH DL DH BPB SIB DIB R8B R9B R10B R11B R12B R13B R14B R15B") {
				for _, mask := range []int64{0, 1, 3, 7, 5, -1, 0x107, 0x10007, 0x7fffffff, 0xffffffff} {
					ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s $%d,%s", row.op, mask, register))
					// Byte identity is the separately validated existing grammar;
					// the expectation below independently selects role/mask bits.
					form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch)
					if !known || err != nil {
						continue
					}
					index, byteMask, valid := x86ResultGP(form.destination.Reg, row.width, arch)
					if !valid {
						continue // Physical SP/amd64 BP and mode32 high banks have no role.
					}
					for _, caller := range []bool{false, true} {
						for _, pointer := range []bool{false, true} {
							state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
							state.pointerGP[index], state.callerAddressGP[index] = pointer, caller
							before := state.clone()
							encoded, all := int64(int32(mask)), uint64(0xffffffff)
							if row.width == 1 {
								encoded, all = int64(int8(mask)), 255
							} else if row.width == 2 {
								encoded, all = int64(int16(mask)), 65535
							} else if row.width == 8 {
								all = ^uint64(0)
							}
							lowMask := uint64(encoded)
							positive := caller && pointer && encoded >= 0 && lowMask < all && lowMask&(lowMask+1) == 0
							got := x86ScalarFPResultTransfer(ins, &state, nil, 0, arch)
							if got != positive {
								t.Fatalf("%s %s %s mask=%d caller=%t pointer=%t: got=%t want=%t", arch, row.op, register, mask, caller, pointer, got, positive)
							}
							if positive {
								before.gp[index] = byteMask
								if row.width >= 4 {
									before.gp[index] = 255
								}
								before.pointerGP[index], before.callerAddressGP[index] = false, false
								before.flags = x86ByteFlagsAll &^ x86ByteFlagAF
							}
							if !reflect.DeepEqual(state, before) {
								t.Fatal("projection changed unrelated bytes/flags/DF or retained address authority", arch, ins.Raw)
							}
						}
					}
				}
			}
		}
	}
	for _, origin := range []string{"named", "raw", "decoded", "address", "unbound-address", "segment"} {
		ins := x86ScalarLaneInstruction(t, "ANDQ $7,AX")
		switch origin {
		case "raw":
			ins.x86SourceRaw = new(x86SourceRawInstruction)
		case "decoded":
			ins.x86Encoded = true
		case "address":
			ins.x86AddressBits = 32
		case "unbound-address":
			ins.x86UnboundAddressOverride = true
		case "segment":
			ins.x86SegmentPrefix = 0x64
		}
		state := x86ResultState{flags: x86ByteFlagsAll}
		for _, index := range []int{0, 3} {
			state.pointerGP[index], state.callerAddressGP[index], state.callerAddressOrigin[index] = true, true, 42
			state.canonicalGP[index] = 255
			state.resultAddressGP[index] = x86ResultSlotAddress{start: 8, end: 12, offset: 8, valid: true}
		}
		state.predicate = x86ResultPredicate{kind: x86ResultNonzeroMaskGP, register: 0, width: 8}
		before := state.clone()
		accepted := x86ScalarFPResultTransfer(ins, &state, nil, 0, "amd64")
		if accepted != (origin == "named") {
			t.Fatal("residue borrowed another source role", origin, accepted)
		}
		if accepted {
			before.gp[0], before.pointerGP[0], before.callerAddressGP[0] = 255, false, false
			before.callerAddressOrigin[0], before.canonicalGP[0] = 0, 0
			before.resultAddressGP[0], before.predicate = x86ResultSlotAddress{}, x86ResultPredicate{}
			before.flags &^= x86ByteFlagAF
		}
		if !reflect.DeepEqual(state, before) {
			t.Fatal("residue retained overwritten authority or changed another register", origin)
		}
	}
}

func TestX86IncomingPointerResidueWholeSourceThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, copy := goWordSize(target.arch), "MOVQ"
		if target.arch == "386" {
			copy = "MOVL"
		}
		for _, row := range []struct {
			op, store, typ string
			width          int
		}{{"ANDB", "MOVB", "uint8", 1}, {"ANDW", "MOVW", "uint16", 2}, {"ANDL", "MOVL", "uint32", 4}, {"ANDQ", "MOVQ", "uint64", 8}} {
			if target.arch == "386" && row.width == 8 {
				continue // No Go Q instruction in this source mode.
			}
			for _, scenario := range []string{"actual-pointer", "copied-pointer", "unknown", "all-bits", "sparse-mask"} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+row.op+"/"+scenario+"/"+api, func(t *testing.T) {
						body := ""
						if scenario != "unknown" {
							body = copy + " p+0(FP),AX\n"
						}
						if scenario == "copied-pointer" {
							body += copy + " AX,BX\n"
							body += copy + " BX,AX\n"
						}
						mask := "7"
						if scenario == "all-bits" {
							mask = "-1"
						} else if scenario == "sparse-mask" {
							mask = "5"
						}
						body += row.op + " $" + mask + ",AX\n" + fmt.Sprintf("%s AX,ret+%d(FP)\nRET\n", row.store, word)
						source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", word+row.width, body)
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *byte) "+row.typ, target.arch, target.triple, api)
						positive := scenario == "actual-pointer" || scenario == "copied-pointer"
						if positive && (err != nil || ir == "") {
							t.Fatal("actual pointer low-bit projection did not produce a defined scalar", err)
						}
						if !positive && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
							t.Fatal("unregistered pointer representation became general NUM", scenario, err)
						}
					})
				}
			}
		}
		for _, row := range []struct{ name, params, body string }{
			{"native-after-projection", "p *byte", copy + " p+0(FP),SI\nAND" + strings.TrimPrefix(copy, "MOV") + " $7,SI\nMOVL $0,AX\nCRC32B (SI),AX\n"},
			{"numeric-native-address", "p uintptr", copy + " p+0(FP),SI\nAND" + strings.TrimPrefix(copy, "MOV") + " $7,SI\nMOVL $0,AX\nCRC32B (SI),AX\n"},
			{"unknown-join", "p *byte", "MOVL $0,CX\nCMPL CX,$0\nJE unknown\n" + copy + " p+0(FP),AX\nJMP join\nunknown:\nNOP\njoin:\nAND" + strings.TrimPrefix(copy, "MOV") + " $7,AX\n"},
			{"result-address", "p *byte", "LEA" + strings.TrimPrefix(copy, "MOV") + fmt.Sprintf(" ret+%d(FP),AX\n", word) + "AND" + strings.TrimPrefix(copy, "MOV") + " $7,AX\n"},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+row.name+"/"+api, func(t *testing.T) {
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%sMOVL AX,ret+%d(FP)\nRET\n", word+4, row.body, word)
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value("+row.params+") uint32", target.arch, target.triple, api)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("residue manufactured an address/unknown/padding authority", err)
					}
				})
			}
		}
		for _, qType := range []string{"*byte", "uintptr"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/joined-"+qType+"/"+api, func(t *testing.T) {
					body := fmt.Sprintf("MOVL flag+%d(FP),CX\nCMPL CX,$0\nJE second\n%s p+0(FP),AX\nJMP join\nsecond:\n%s q+%d(FP),AX\njoin:\nAND%s $7,AX\nMOVL AX,ret+%d(FP)\nRET\n", 2*word, copy, copy, word, strings.TrimPrefix(copy, "MOV"), 3*word)
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s", 3*word+4, body)
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *byte,q "+qType+",flag uint32) uint32", target.arch, target.triple, api)
					if qType == "*byte" && (err != nil || ir == "") {
						t.Fatal("two actual caller origins need no common-origin witness for a unary projection", err)
					}
					if qType != "*byte" && (!errors.Is(err, ErrProbeNeedsContext) || ir != "") {
						t.Fatal("NUM/caller join supplied an actual pointer identity", err)
					}
				})
			}
		}
	}
}
