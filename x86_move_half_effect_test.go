package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Independent source directory: Go shares yxmov with other operations, but
// the ISA's half selectors and numerical permissions are not a whole-X copy.
var x86MoveHalfOracle = []struct {
	op           string
	high, vector bool
}{
	{"MOVLPS", false, false}, {"MOVHPS", true, false},
	{"MOVLPD", false, false}, {"MOVHPD", true, false},
	{"VMOVLPS", false, true}, {"VMOVHPS", true, true},
	{"VMOVLPD", false, true}, {"VMOVHPD", true, true},
}

func TestX86MoveHalfCompleteIndependentGoRowsAndTypedEffects(t *testing.T) {
	legacy, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(legacy), "var yxmov = []ytab{\n\t{Zm_r_xm, 1, argList{Yxm, Yxr}},\n\t{Zr_m_xm, 1, argList{Yxr, Yxm}},\n}") {
		t.Fatal("complete original Go legacy half-move rows changed")
	}
	for _, row := range x86MoveHalfOracle[:4] {
		prefix, code := "Pm", "0x12, 0x13"
		if strings.HasSuffix(row.op, "PD") {
			prefix = "Pe"
		}
		if row.high {
			code = "0x16, 0x17"
		}
		if want := fmt.Sprintf("{A%s, yxmov, %s, opBytes{%s}}", row.op, prefix, code); !strings.Contains(string(legacy), want) {
			t.Fatal("independent legacy half-move encoding changed", want)
		}
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, rule := range rules {
		if rule.Opcode != "VMOVLPS" && rule.Opcode != "VMOVHPS" && rule.Opcode != "VMOVLPD" && rule.Opcode != "VMOVHPD" {
			continue
		}
		index := counts[rule.Opcode]
		counts[rule.Opcode]++
		classes := []string{"Yxr,Ym", "Ym,Yxr,Yxr", "YxrEvex,Ym", "Ym,YxrEvex,YxrEvex"}
		zcase := []string{"Zvex_r_v_rm", "Zvex_rm_v_r", "Zevex_r_v_rm", "Zevex_rm_v_r"}
		offsets, advances := []int{0, 2, 4, 7}, []int{2, 2, 3, 3}
		prefix, w, load, store := "", 0, "0x12", "0x13"
		if strings.HasSuffix(rule.Opcode, "PD") {
			prefix, w = " | vex66", 1
		}
		if strings.Contains(rule.Opcode, "H") {
			load, store = "0x16", "0x17"
		}
		attributes := []string{
			"avxEscape | vex128" + prefix + " | vex0F | vexW0", store,
			"avxEscape | vex128" + prefix + " | vex0F | vexW0", load,
			fmt.Sprintf("avxEscape | evex128%s | evex0F | evexW%d", strings.ReplaceAll(prefix, "vex66", "evex66"), w), "evexN8", store,
			fmt.Sprintf("avxEscape | evex128%s | evex0F | evexW%d", strings.ReplaceAll(prefix, "vex66", "evex66"), w), "evexN8", load,
		}
		if index >= 4 || rule.RowIndex != index || rule.Ytab != "_yvmovhpd" || rule.Prefix != "Pavx" ||
			rule.ZCase != zcase[index] || rule.ZOffset != advances[index] || rule.EncodingOffset != offsets[index] ||
			strings.Join(rule.Classes, ",") != classes[index] || !reflect.DeepEqual(rule.OpBytes, attributes) {
			t.Fatal("independent complete half-move AVX row or N8/W attributes changed", rule)
		}
	}
	if !reflect.DeepEqual(counts, map[string]int{"VMOVLPS": 4, "VMOVHPS": 4, "VMOVLPD": 4, "VMOVHPD": 4}) {
		t.Fatal("complete sixteen AVX half-move rows changed", counts)
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86MoveHalfOracle {
			for _, store := range []bool{false, true} {
				t.Run(fmt.Sprint(arch, "/", row.op, "/store=", store), func(t *testing.T) {
					args := "value+0(FP),X2"
					if row.vector {
						args = "value+0(FP),X1,X2"
					}
					if store {
						args = "X1,value+0(FP)"
					}
					ins := x86ScalarLaneInstruction(t, row.op+" "+args)
					effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
					if !known || err != nil || !effect.requiresResultProof || effect.dynamicMemory ||
						effect.flagsRead != 0 || effect.flagsDefined != 0 || effect.flagsKilled != 0 || len(effect.operands) != len(ins.Args) {
						t.Fatal("complete half-move source/merge/store effect missing", effect, known, err)
					}
					for index, operand := range effect.operands {
						width, read, write := int64(16), index < len(ins.Args)-1, index == len(ins.Args)-1
						if ins.Args[index].Kind == OpFP {
							width = 8
						}
						if !row.vector && !store && write {
							read = true // The untouched half remains an independent old input.
						}
						if operand.index != index || !reflect.DeepEqual(operand.operand, ins.Args[index]) || operand.width != width || operand.read != read || operand.write != write {
							t.Fatal("typed envelope does not retain exact memory/selected-register roles", index, operand)
						}
					}
				})
			}
		}
	}
}

func TestX86MoveHalfSelectedBytesUpperAliasesAndState(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86MoveHalfOracle {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				args, base := "value+0(FP),X2", 2
				if row.vector {
					args, base = "value+0(FP),X1,X2", 1
				}
				ins := x86ScalarLaneInstruction(t, row.op+" "+args)
				inputOwned := []bool{true, true, true, true, true, true, true, true}
				for missing := -1; missing < 16; missing++ {
					initial := x86ResultState{fp: make([]bool, 8), flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
					for offset := int64(0); offset < 8; offset++ {
						initial.fp[offset] = true
					}
					initial.xmm[base] = 0xffff
					if missing >= 0 {
						initial.xmm[base] &^= 1 << uint(missing)
					}
					initial.vectorUpper[2] = 0x0055aa55ffff0000
					before, want := initial.clone(), initial.clone()
					lane := uint(0)
					if row.high {
						lane = 8
					}
					mask := uint16(0xff) << lane
					want.xmm[2] = initial.xmm[base]&^mask | mask
					if row.vector {
						want.vectorUpper[2] = ^uint64(0xffff)
					}
					if !x86ResultTransfer(ins, &initial, inputOwned, 0, arch) || !reflect.DeepEqual(initial, want) {
						t.Fatal("selected-byte propagation invented unknown merge bytes, lost upper alias, or changed unrelated state", missing, before, initial, want)
					}
				}
				for missing := -1; missing < 16; missing++ {
					ins := x86ScalarLaneInstruction(t, row.op+" X1,ret0+8(FP)")
					state := x86ResultState{fp: make([]bool, 16), flags: x86ByteFlagsAll}
					state.xmm[1] = 0xffff
					if missing >= 0 {
						state.xmm[1] &^= 1 << uint(missing)
					}
					before := state.clone()
					owned := make([]bool, 16)
					for offset := 8; offset < 16; offset++ {
						owned[offset] = true
					}
					selectedMissing := missing >= 0 && (missing >= 8) == row.high
					accepted := x86ResultTransfer(ins, &state, owned, 8, arch)
					if accepted == selectedMissing || selectedMissing && !reflect.DeepEqual(state, before) {
						t.Fatal("half store borrowed unselected bytes or lost a selected input", missing, accepted)
					}
					if accepted {
						for offset := int64(8); offset < 16; offset++ {
							before.fp[offset] = true
						}
						if !reflect.DeepEqual(state, before) {
							t.Fatal("half store changed unrelated vector/FLAGS/storage state")
						}
					}
				}
			})
		}
	}
}

func TestX86MoveHalfInitializedPublicAPIsAndMissingNativeInputs(t *testing.T) {
	for _, row := range x86MoveHalfOracle {
		t.Run(row.op, func(t *testing.T) {
			args := "(DX),X2"
			if row.vector {
				args = "(DX),X1,X2"
			}
			body := "MOVQ out+0(FP),AX\nMOVQ base+8(FP),CX\nMOVQ half+16(FP),DX\nMOVUPS (CX),X1\nMOVUPS X1,X2\nSTC\n" +
				row.op + " " + args + "\nMOVUPS X2,(AX)\n" + row.op + " X2,16(AX)\nSETCS 24(AX)\nRET\n"
			source := "TEXT ·Value(SB),4,$0-24\n" + body
			declaration := "func Value(out *[32]byte,base *[16]byte,half *uint64)\n"
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					if _, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
						t.Fatal("complete initialized valid half-move source rejected", err)
					}
					missing := strings.Replace(source, "MOVQ half+16(FP),DX\n", "", 1)
					if _, err := x86ScalarFPBitViewAPI(t, missing, declaration, "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("Void half move lost its actual native read input", err)
					}
					missing = strings.Replace(source, "MOVQ out+0(FP),AX\n", "", 1)
					if _, err := x86ScalarFPBitViewAPI(t, missing, declaration, "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("Void half move lost its actual native write input", err)
					}
				})
			}
		})
	}
}
