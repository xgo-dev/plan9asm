package goasmrules

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Membership is independent of both the formatter and translator registries.
func x86GPBMIOfficialTestRules(t *testing.T) []X86AVXRule {
	t.Helper()
	names := strings.Fields(`ANDNL ANDNQ BEXTRL BEXTRQ BLSIL BLSIQ BLSMSKL BLSMSKQ BLSRL BLSRQ
		BZHIL BZHIQ MULXL MULXQ PDEPL PDEPQ PEXTL PEXTQ RORXL RORXQ SARXL SARXQ SHLXL SHLXQ SHRXL SHRXQ`)
	selected := make(map[string]bool)
	for _, name := range names {
		if selected[name] {
			t.Fatal("duplicate independent GP member", name)
		}
		selected[name] = true
	}
	if len(selected) != 26 {
		t.Fatal("complete GP namespace changed", len(selected))
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var rules []X86AVXRule
	seen, tables := make(map[string]int), make(map[string]int)
	for _, rule := range avx {
		if selected[rule.Opcode] {
			rules = append(rules, rule)
			seen[rule.Opcode]++
			tables[rule.Ytab]++
		}
	}
	for name := range selected {
		want := 1
		if strings.HasPrefix(name, "RORX") {
			want = 2
		}
		if seen[name] != want {
			t.Fatal("complete original member rows changed", name, seen[name], want)
		}
	}
	if len(rules) != 28 || len(tables) != 4 || tables["_yandnl"] != 8 || tables["_ybextrl"] != 10 || tables["_yblsil"] != 6 || tables["_yrorxl"] != 4 {
		t.Fatal("complete original source tables changed", len(rules), tables)
	}
	return rules
}

func TestX86GPBMICompleteOfficialSourceWitnesses(t *testing.T) {
	for _, rule := range x86GPBMIOfficialTestRules(t) {
		t.Run(fmt.Sprintf("%s/%d", rule.Opcode, rule.RowIndex), func(t *testing.T) {
			witnesses, err := x86PackedAVXRowWitnesses(rule)
			if err != nil || len(witnesses) != 2 {
				t.Fatal("original row lacks its register and memory witness", len(witnesses), err)
			}
			for index, w := range witnesses {
				if w.Generation != "vex" || w.Width != 32 && w.Width != 64 || w.Memory != (index == 1) ||
					w.Masked || w.Zeroing || w.Broadcast || w.MaskResult || len(w.Encoding) == 0 {
					t.Fatal("GP transport gained vector controls or lost an operand alternative", w)
				}
			}
		})
	}
}

func TestX86GPBMISourceTransportByteAnchors(t *testing.T) {
	anchors := map[string]string{
		"ANDNL AX,CX,BX":    "c4e270f2d8",
		"ANDNQ (AX),CX,BX":  "c4e2f0f218",
		"BEXTRQ CX,AX,BX":   "c4e2f0f7d8",
		"BLSIQ AX,CX":       "c4e2f0f3d8",
		"BLSMSKL (AX),CX":   "c4e270f310",
		"MULXQ AX,CX,BX":    "c4e2f3f6d8",
		"RORXL $1,AX,BX":    "c4e37bf0d801",
		"RORXQ $-1,(AX),BX": "c4e3fbf018ff",
	}
	for _, rule := range x86GPBMIOfficialTestRules(t) {
		witnesses, err := x86PackedAVXRowWitnesses(rule)
		if err != nil {
			t.Fatal("valid original before byte controls", err)
		}
		for _, w := range witnesses {
			if encoded, ok := anchors[w.Instruction]; ok {
				want, err := hex.DecodeString(encoded)
				if err != nil || !bytes.Equal(w.Encoding, want) {
					t.Fatal("independent operand/extension/vvvv/imm8 anchor", w, encoded, err)
				}
				delete(anchors, w.Instruction)
			}
		}
	}
	if len(anchors) != 0 {
		t.Fatal("missing independent GP transport anchors", anchors)
	}
}

func TestX86GPBMIRejectsMutatedSourceMetadata(t *testing.T) {
	for _, rule := range x86GPBMIOfficialTestRules(t) {
		t.Run(fmt.Sprintf("%s/%d", rule.Opcode, rule.RowIndex), func(t *testing.T) {
			if witnesses, err := x86PackedAVXRowWitnesses(rule); err != nil || len(witnesses) != 2 {
				t.Fatal("valid original before rejection controls", err)
			}
			for _, axis := range []string{"prefix", "row", "zoffset", "offset", "roles", "zcase", "header", "length", "W", "opcode-byte", "extra-payload"} {
				t.Run(axis, func(t *testing.T) {
					changed := rule
					changed.Classes = append([]string(nil), rule.Classes...)
					changed.OpBytes = append([]string(nil), rule.OpBytes...)
					switch axis {
					case "prefix":
						changed.Prefix = "Pm"
					case "row":
						changed.RowIndex += 10
					case "zoffset":
						changed.ZOffset += 10
					case "offset":
						changed.EncodingOffset++
					case "roles":
						changed.Classes[len(changed.Classes)-1] = "Yxr"
					case "zcase":
						changed.ZCase = "Zevex_rm_v_r"
					case "header":
						changed.OpBytes[0] += "|vexInventedPermission"
					case "length":
						changed.OpBytes[0] = strings.Replace(changed.OpBytes[0], "vex128", "vex256", 1)
					case "W":
						changed.OpBytes[0] = strings.NewReplacer("vexW0", "vexW1", "vexW1", "vexW0").Replace(changed.OpBytes[0])
					case "opcode-byte":
						changed.OpBytes[1] = "0x100"
					case "extra-payload":
						changed.OpBytes = append(changed.OpBytes, "0")
					}
					if _, err := x86PackedAVXRowWitnesses(changed); err == nil {
						t.Fatal("corrupt original metadata granted a physical GP format", axis, changed)
					}
				})
			}
		})
	}
}
