package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86FloatingHelperCompleteIndependentGoRows(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	members := make(map[string]x86FloatingHelperOracleMember)
	for _, member := range x86FloatingHelperOracleMembers() {
		members[member.name] = member
	}
	counts := make(map[string]int)
	for _, rule := range rules {
		member, wanted := members[rule.Opcode]
		if !wanted {
			continue
		}
		ordinal := counts[rule.Opcode]
		counts[rule.Opcode]++
		widths := []int{512, 128, 256}
		if member.scalar {
			widths = []int{128}
		} else if member.maskResult {
			widths = []int{map[string]int{"X": 128, "Y": 256, "Z": 512}[member.bank]}
		}
		if ordinal >= len(widths)*2 {
			t.Fatal("unexpected extra floating-helper Go row", rule)
		}
		bits, word := 32, "0"
		if strings.Contains(member.name, "PD") || strings.HasSuffix(member.name, "SD") {
			bits, word = 64, "1"
		}
		family, opcode, opcodeScalar, encodingMap := "", "", "", "evex0F3A"
		switch {
		case strings.HasPrefix(member.name, "VGETEXP"):
			family, opcode, opcodeScalar, encodingMap = "_yvcvtpd2qq", "0x42", "0x43", "evex0F38"
		case strings.HasPrefix(member.name, "VGETMANT"):
			family, opcode, opcodeScalar = "_yvgetmantpd", "0x26", "0x27"
		case strings.HasPrefix(member.name, "VSCALEF"):
			family, opcode, opcodeScalar, encodingMap = "_yvscalefpd", "0x2C", "0x2D", "evex0F38"
		case strings.HasPrefix(member.name, "VRANGE"):
			family, opcode, opcodeScalar = "_yvfixupimmpd", "0x50", "0x51"
		case strings.HasPrefix(member.name, "VFIXUPIMM"):
			family, opcode, opcodeScalar = "_yvfixupimmpd", "0x54", "0x55"
		case strings.HasPrefix(member.name, "VRNDSCALE"):
			family, opcode, opcodeScalar = "_yvgetmantpd", "0x08", "0x0A"
			if bits == 64 {
				opcode, opcodeScalar = "0x09", "0x0B"
			}
		case strings.HasPrefix(member.name, "VREDUCE"):
			family, opcode, opcodeScalar = "_yvgetmantpd", "0x56", "0x57"
		case member.maskResult:
			family = "_yvfpclasspd" + strings.ToLower(member.bank)
			opcode, opcodeScalar = "0x66", "0x67"
		}
		if member.scalar {
			family, opcode = "_yvgetexpsd", opcodeScalar
			if member.immediate {
				family = "_yvfixupimmsd"
			}
			if member.maskResult {
				family = "_yvfpclasspdx"
			}
		}
		var bytes []string
		for _, width := range widths {
			tuple := width / 8
			if member.scalar {
				tuple = bits / 8
			}
			attributes := fmt.Sprintf("evexN%d", tuple)
			if !member.scalar {
				attributes += fmt.Sprintf(" | evexBcstN%d", bits/8)
			}
			if !member.maskResult {
				if width == 512 || member.scalar {
					control := "evexSaeEnabled"
					if strings.HasPrefix(member.name, "VSCALEF") {
						control = "evexRoundingEnabled"
					}
					attributes += " | " + control
				}
				attributes += " | evexZeroingEnabled"
			}
			bytes = append(bytes, fmt.Sprintf("avxEscape | evex%d | evex66 | %s | evexW%s", width, encodingMap, word), attributes, opcode)
		}
		width := widths[ordinal/2]
		memory, vector := "YxmEvex", "YxrEvex"
		if width == 256 {
			memory, vector = "YymEvex", "YyrEvex"
		} else if width == 512 {
			memory, vector = "Yzm", "Yzr"
		}
		var classes []string
		zcase := "Zevex_"
		if member.immediate {
			classes = append(classes, "Yu8")
			zcase += "i_"
		}
		classes = append(classes, memory)
		zcase += "rm_"
		if !member.maskResult && (member.second || member.scalar) {
			classes = append(classes, vector)
			zcase += "v_"
		} else if !member.immediate && ordinal%2 == 0 {
			zcase += "v_"
		}
		offset := 0
		if ordinal%2 != 0 {
			classes = append(classes, "Yknot0")
			zcase += "k_"
			offset = 3
		}
		zcase += "r"
		destination := vector
		if member.maskResult {
			destination = "Yk"
		}
		classes = append(classes, destination)
		if rule.RowIndex != ordinal || rule.Ytab != family || rule.Prefix != "Pavx" ||
			rule.ZCase != zcase || rule.ZOffset != offset || rule.EncodingOffset != ordinal/2*3 ||
			!reflect.DeepEqual(rule.Classes, classes) || !reflect.DeepEqual(rule.OpBytes, bytes) {
			t.Fatal("complete independent floating-helper Go row/attribute changed", rule,
				"want", family, zcase, classes, bytes)
		}
	}
	for name, member := range members {
		want := 6
		if member.scalar || member.maskResult {
			want = 2
		}
		if counts[name] != want {
			t.Fatal("floating-helper family row denominator changed", name, counts[name], want)
		}
	}
}
