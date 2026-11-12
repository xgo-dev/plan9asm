package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86PackedRotateCompleteIndependentGoRows(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range x86PackedRotateTestFamilies {
		classes := []string{"YxmEvex,YxrEvex", "YxmEvex,Yknot0,YxrEvex",
			"YymEvex,YyrEvex", "YymEvex,Yknot0,YyrEvex", "Yzm,Yzr", "Yzm,Yknot0,Yzr"}
		table, plain, masked, stride := "_yvprold", "Zevex_i_rm_vo", "Zevex_i_rm_k_vo", 4
		for index, class := range classes {
			if family.variable {
				parts := strings.Split(class, ",")
				classes[index] = parts[0] + "," + parts[len(parts)-1] + "," + strings.Join(parts[1:], ",")
			} else {
				classes[index] = "Yu8," + class
			}
		}
		if family.variable {
			table, plain, masked, stride = "_yvblendmpd", "Zevex_rm_v_r", "Zevex_rm_v_k_r", 3
		}
		var attributes []string
		for _, width := range []int{128, 256, 512} {
			mapName, opcode := "evex0F", "0x72"
			if family.variable {
				mapName, opcode = "evex0F38", "0x14"
				if family.left {
					opcode = "0x15"
				}
			}
			attributes = append(attributes,
				fmt.Sprintf("avxEscape | evex%d | evex66 | %s | evexW%d", width, mapName, family.bits/32-1),
				fmt.Sprintf("evexN%d | evexBcstN%d | evexZeroingEnabled", width/8, family.bits/8), opcode)
			if !family.variable {
				direction := "00"
				if family.left {
					direction = "01"
				}
				attributes = append(attributes, direction)
			}
		}
		count := 0
		for _, rule := range rules {
			if rule.Opcode != family.op {
				continue
			}
			zcase := plain
			if count%2 != 0 {
				zcase = masked
			}
			if count >= 6 || rule.RowIndex != count || rule.Ytab != table || rule.Prefix != "Pavx" ||
				rule.ZCase != zcase || rule.ZOffset != count%2*stride || rule.EncodingOffset != count/2*stride ||
				strings.Join(rule.Classes, ",") != classes[count] || !reflect.DeepEqual(rule.OpBytes, attributes) {
				t.Fatal("independent rotate Go encoding row changed", family.op, rule)
			}
			count++
		}
		if count != 6 {
			t.Fatal("incomplete rotate Go encoding inventory", family.op, count)
		}
	}
}

func TestX86PackedRotateExactNumericalInputs(t *testing.T) {
	for _, family := range x86PackedRotateTestFamilies {
		for _, bank := range []string{"X", "Y", "Z"} {
			width := amd64VectorByteWidth(Reg(bank + "0"))
			for mode := 0; mode < 3; mode++ {
				op, mask := family.op, ""
				if mode != 0 {
					mask = "K1,"
				}
				if mode == 2 {
					op += ".Z"
				}
				args := "$7," + bank + "1,"
				if family.variable {
					args = bank + "0," + bank + "1,"
				}
				ins := x86ScalarLaneInstruction(t, op+" "+args+mask+bank+"2")
				for missingRegister := 0; missingRegister < 4; missingRegister++ {
					for missingByte := -1; missingByte < 64; missingByte++ {
						state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
						for register := 0; register < 4; register++ {
							bytes := ^uint64(0)
							if register == missingRegister && missingByte >= 0 {
								bytes &^= 1 << uint(missingByte)
							}
							state.writeVector(register, 64, bytes, false)
						}
						state.masks[1] = missingRegister != 3 || missingByte != 0
						before, want := state.clone(), state.clone()
						required := missingRegister == 1 || missingRegister == 0 && family.variable || missingRegister == 2 && mode == 1
						accepted := !(required && missingByte >= 0 && missingByte < width || mode != 0 && !state.masks[1])
						if accepted {
							want.writeVector(2, width, x86CallerVectorByteMask(int64(width)), false)
						}
						if got := x86ResultTransfer(ins, &state, nil, 0, "amd64"); got != accepted || !reflect.DeepEqual(state, want) {
							t.Fatal("rotate fabricated input bytes, lost upper zeroing or changed unrelated state", ins.Raw, missingRegister, missingByte, got, accepted, before, state)
						}
					}
				}
			}
		}
	}
}

func TestX86PackedRotateRejectsUnresolvedShapesBeforeIR(t *testing.T) {
	for _, family := range x86PackedRotateTestFamilies {
		for _, mutation := range []string{"suffix", "offset", "extension", "segment", "index", "absolute", "dispatch", "address", "float", "unresolved"} {
			if family.variable && (mutation == "float" || mutation == "unresolved") {
				continue
			}
			t.Run(family.op+"/"+mutation, func(t *testing.T) {
				args, source := "$7,(AX),X2", 1
				if family.variable {
					args, source = "(AX),X1,X2", 0
				}
				ins := x86ScalarLaneInstruction(t, family.op+" "+args)
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
				case "address":
					ins.x86AddressBits = 32
				case "float":
					ins.Args[0].ImmIsFloat = true
				case "unresolved":
					ins.Args[0].ImmRaw = "UNKNOWN"
				}
				var ir strings.Builder
				consumer := &amd64Ctx{b: &ir, goarch: "amd64"}
				known, _, err := consumer.lowerPackedRotate(op, ins)
				if !known || err == nil || ir.Len() != 0 {
					t.Fatal("invalid rotate shape reached IR", known, err, ir.String())
				}
			})
		}
	}
}

func TestX86PackedRotateNativeReadKeepsOwnership(t *testing.T) {
	for _, family := range x86PackedRotateTestFamilies {
		args := "$7,-1(SI)(BX*2),X2"
		if family.variable {
			args = "-1(SI)(BX*2),X1,X2"
		}
		ins := x86ScalarLaneInstruction(t, family.op+" "+args)
		for _, missing := range []string{"none", "pointer", "index", "pointer index", "raw", "address"} {
			t.Run(fmt.Sprint(family.op, "/", missing), func(t *testing.T) {
				state, changed := x86ResultState{}, ins
				state.writeVector(1, 64, ^uint64(0), false)
				state.pointerGP[6], state.gp[3] = true, 0xff
				switch missing {
				case "pointer":
					state.pointerGP[6] = false
				case "index":
					state.gp[3] = 1
				case "pointer index":
					state.pointerGP[3], state.gp[3] = true, 0
				case "raw":
					changed.x86Encoded = true
				case "address":
					changed.x86AddressBits = 32
				}
				before := state.clone()
				if x86ResultTransfer(changed, &state, nil, 0, "amd64") || !reflect.DeepEqual(before, state) {
					t.Fatal("standalone transfer invented a native memory contract")
				}
				accepted, _ := x86LoweredFixedVectorNativeRead(changed, &state, nil, "amd64")
				want := before.clone()
				if missing == "none" {
					want.writeVector(2, 16, 0xffff, false)
				}
				if accepted != (missing == "none") || !reflect.DeepEqual(state, want) {
					t.Fatal("paired rotate read changed pointer, NUM or independent state", accepted, state, want)
				}
			})
		}
	}
}
