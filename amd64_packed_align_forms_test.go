package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86PackedAlignCompleteIndependentGoRows(t *testing.T) {
	legacy, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{"{APALIGNR, ypalignr, Pq, opBytes{0x3a, 0x0f}}", "var ypalignr = []ytab{\n\t{Zibm_r, 2, argList{Yu8, Yxm, Yxr}},\n}"} {
		if !strings.Contains(string(legacy), row) {
			t.Fatal("complete legacy align table changed", row)
		}
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, rule := range rules {
		if rule.Opcode != "VPALIGNR" && rule.Opcode != "VALIGND" && rule.Opcode != "VALIGNQ" {
			continue
		}
		index := counts[rule.Opcode]
		counts[rule.Opcode]++
		classes := []string{"Yu8,YxmEvex,YxrEvex,YxrEvex", "Yu8,YxmEvex,YxrEvex,Yknot0,YxrEvex",
			"Yu8,YymEvex,YyrEvex,YyrEvex", "Yu8,YymEvex,YyrEvex,Yknot0,YyrEvex", "Yu8,Yzm,Yzr,Yzr", "Yu8,Yzm,Yzr,Yknot0,Yzr"}
		offsets, advances := []int{0, 0, 3, 3, 6, 6}, []int{0, 3, 0, 3, 0, 3}
		ytab, opcode, w, zcase := "_yvalignd", "0x03", 0, "Zevex_i_rm_v_r"
		if rule.Opcode == "VALIGNQ" {
			w = 1
		}
		var attributes []string
		if rule.Opcode == "VPALIGNR" {
			ytab, opcode = "_yvgf2p8affineinvqb", "0x0F"
			classes = append([]string{"Yu8,Yxm,Yxr,Yxr", "Yu8,Yym,Yyr,Yyr"}, classes...)
			offsets, advances = []int{0, 2, 4, 4, 7, 7, 10, 10}, []int{2, 2, 0, 3, 0, 3, 0, 3}
			attributes = []string{"avxEscape | vex128 | vex66 | vex0F3A | vexW0", opcode,
				"avxEscape | vex256 | vex66 | vex0F3A | vexW0", opcode}
		}
		for _, bits := range []int{128, 256, 512} {
			memory := fmt.Sprintf("evexN%d", bits/8)
			if rule.Opcode != "VPALIGNR" {
				memory += fmt.Sprintf(" | evexBcstN%d", 4*(w+1))
			}
			memory += " | evexZeroingEnabled"
			attributes = append(attributes, fmt.Sprintf("avxEscape | evex%d | evex66 | evex0F3A | evexW%d", bits, w), memory, opcode)
		}
		if rule.Opcode == "VPALIGNR" && index < 2 {
			zcase = "Zvex_i_rm_v_r"
		} else if index%2 != 0 {
			zcase = "Zevex_i_rm_v_k_r"
		}
		if index >= len(classes) || rule.RowIndex != index || rule.Ytab != ytab || rule.Prefix != "Pavx" ||
			rule.ZCase != zcase || rule.ZOffset != advances[index] || rule.EncodingOffset != offsets[index] ||
			strings.Join(rule.Classes, ",") != classes[index] || !reflect.DeepEqual(rule.OpBytes, attributes) {
			t.Fatal("independent complete align encoder row or attributes changed", rule)
		}
	}
	if !reflect.DeepEqual(counts, map[string]int{"VPALIGNR": 8, "VALIGND": 6, "VALIGNQ": 6}) {
		t.Fatal("complete twenty AVX plus one legacy row inventory changed", counts)
	}
}

func TestX86PackedAlignNativeCarrierAndSourceBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		ins := x86ScalarLaneInstruction(t, "PALIGNR $255,(AX),X2")
		fn := Func{Instrs: []Instr{ins}}
		features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, fn)
		if features != "+sse2,+ssse3" {
			t.Fatal("isolated native PALIGNR borrowed another function's features", arch, features)
		}
		state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
		state.pointerGP[0] = true
		before := state.clone()
		if accepted, known := x86ResultPackedAlignStep(ins, &state, nil, arch, false); !known || accepted || !reflect.DeepEqual(state, before) {
			t.Fatal("standalone observer acquired a native read")
		}
		if accepted, known := x86ResultPackedAlignStep(ins, &state, nil, arch, true); !known || !accepted || state.vectorBytes(2)&0xffff != 0xffff {
			t.Fatal("continuing past the native opcode lost the large-count known-zero result")
		}
		for _, mutation := range []string{"pointer", "encoded", "raw", "segment", "address", "raw-return"} {
			changed, input := ins, before.clone()
			switch mutation {
			case "pointer":
				input.pointerGP[0] = false
			case "encoded":
				changed.x86Encoded = true
			case "raw":
				changed.x86SourceRaw = new(x86SourceRawInstruction)
			case "segment":
				changed.x86SegmentPrefix = 0x64
			case "address":
				changed.x86AddressBits = 32
			case "raw-return":
				changed.x86RawNearReturn = new(x86RawNearReturnForm)
			}
			original := input.clone()
			if accepted, _ := x86ResultPackedAlignStep(changed, &input, nil, arch, true); accepted || !reflect.DeepEqual(input, original) {
				t.Fatal("native continuation invented an address or physical origin", arch, mutation)
			}
		}
	}
}

func TestX86PackedAlignMode32ImmediateUsesGoConstantClass(t *testing.T) {
	for _, immediate := range []int64{0, 255, 4294967296, 4294967551} {
		row := fmt.Sprintf("PALIGNR $%d,X0,X2", immediate)
		goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
		ins := x86ScalarLaneInstruction(t, row)
		form, known, err := x86PackedAlignProperties(ins.Op, ins, "386")
		if !known || err != nil || form.immediate != byte(immediate) {
			t.Fatal("mode32 source class did not preserve Go's actual imm8", immediate, form, err)
		}
	}
}
