package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86QwordLookupCompleteIndependentGoRows(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, rule := range rules {
		if rule.Opcode != "VPMULTISHIFTQB" && rule.Opcode != "VPSHUFBITQMB" {
			continue
		}
		index := counts[rule.Opcode]
		counts[rule.Opcode]++
		classes := []string{"YxmEvex,YxrEvex,YxrEvex", "YxmEvex,YxrEvex,Yknot0,YxrEvex",
			"YymEvex,YyrEvex,YyrEvex", "YymEvex,YyrEvex,Yknot0,YyrEvex", "Yzm,Yzr,Yzr", "Yzm,Yzr,Yknot0,Yzr"}
		ytab, opcode, w := "_yvblendmpd", "0x83", 1
		if rule.Opcode == "VPSHUFBITQMB" {
			ytab, opcode, w = "_yvpshufbitqmb", "0x8F", 0
			classes = []string{"YxmEvex,YxrEvex,Yk", "YxmEvex,YxrEvex,Yknot0,Yk",
				"YymEvex,YyrEvex,Yk", "YymEvex,YyrEvex,Yknot0,Yk", "Yzm,Yzr,Yk", "Yzm,Yzr,Yknot0,Yk"}
		}
		var bytes []string
		for _, width := range []int{128, 256, 512} {
			attributes := fmt.Sprintf("evexN%d", width/8)
			if rule.Opcode == "VPMULTISHIFTQB" {
				attributes += " | evexBcstN8 | evexZeroingEnabled"
			}
			bytes = append(bytes, fmt.Sprintf("avxEscape | evex%d | evex66 | evex0F38 | evexW%d", width, w), attributes, opcode)
		}
		zcase, offset := "Zevex_rm_v_r", 0
		if index%2 != 0 {
			zcase, offset = "Zevex_rm_v_k_r", 3
		}
		if index >= 6 || rule.RowIndex != index || rule.Ytab != ytab || rule.Prefix != "Pavx" ||
			rule.ZCase != zcase || rule.ZOffset != offset || rule.EncodingOffset != index/2*3 ||
			strings.Join(rule.Classes, ",") != classes[index] || !reflect.DeepEqual(rule.OpBytes, bytes) {
			t.Fatal("independent complete qword lookup encoder row/attributes changed", rule)
		}
	}
	if len(counts) != 2 || counts["VPMULTISHIFTQB"] != 6 || counts["VPSHUFBITQMB"] != 6 {
		t.Fatal("complete qword lookup row inventory changed", counts)
	}
}

func TestX86QwordLookupEveryInputByteAndIndependentState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range []string{"VPMULTISHIFTQB", "VPSHUFBITQMB"} {
			for _, bank := range []string{"X", "Y", "Z"} {
				destination := bank + "2"
				if name == "VPSHUFBITQMB" {
					destination = "K3"
				}
				ins := x86ScalarLaneInstruction(t, name+" "+bank+"0,"+bank+"1,"+destination)
				width := amd64VectorByteWidth(ins.Args[0].Reg)
				for input := 0; input < 2; input++ {
					for missing := -1; missing < width; missing++ {
						state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionEither}
						for register := 0; register < 3; register++ {
							state.writeVector(register, 64, ^uint64(0), false)
						}
						state.pointerGP[6], state.gp[3], state.masks[1] = true, 0x55, true
						if missing >= 0 {
							state.writeVector(input, 64, state.vectorBytes(input)&^(uint64(1)<<uint(missing)), false)
						}
						want := state.clone()
						if missing < 0 {
							if name == "VPSHUFBITQMB" {
								want.masks[3] = true
							} else {
								want.writeVector(2, width, x86CallerVectorByteMask(int64(width)), false)
							}
						}
						accepted, known := x86ResultQwordLookupStep(ins, &state, nil, arch, false)
						if !known || accepted != (missing < 0) || !reflect.DeepEqual(state, want) {
							t.Fatal("qword lookup invented missing input bytes or changed independent state", arch, name, bank, input, missing)
						}
					}
				}
			}
		}
	}
}

func TestX86QwordLookupMaskResultsAreWriteOnlyAndZeroingNeedsNoMerge(t *testing.T) {
	for _, row := range []string{"VPSHUFBITQMB X0,X1,K3", "VPSHUFBITQMB X0,X1,K1,K3", "VPMULTISHIFTQB.Z X0,X1,K1,X2"} {
		ins := x86ScalarLaneInstruction(t, row)
		state := x86ResultState{flags: x86ByteFlagsAll}
		state.writeVector(0, 64, ^uint64(0), false)
		state.writeVector(1, 64, ^uint64(0), false)
		state.masks[1] = true
		if accepted, known := x86ResultQwordLookupStep(ins, &state, nil, "amd64", false); !known || !accepted {
			t.Fatal("write-only K destination or zeroing result demanded old bytes", row)
		}
	}
	ins := x86ScalarLaneInstruction(t, "VPMULTISHIFTQB X0,X1,K1,X2")
	state := x86ResultState{}
	state.writeVector(0, 64, ^uint64(0), false)
	state.writeVector(1, 64, ^uint64(0), false)
	state.masks[1] = true
	if accepted, known := x86ResultQwordLookupStep(ins, &state, nil, "amd64", false); !known || accepted {
		t.Fatal("merging byte result invented its old destination")
	}
}
