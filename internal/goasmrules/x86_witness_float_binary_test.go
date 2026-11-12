package goasmrules

import (
	"bytes"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

const x86AVXFloatBinaryMembers = `VADDPS VADDPD VADDSS VADDSD VSUBPS VSUBPD VSUBSS VSUBSD
	VMULPS VMULPD VMULSS VMULSD VDIVPS VDIVPD VDIVSS VDIVSD
	VMINPS VMINPD VMINSS VMINSD VMAXPS VMAXPD VMAXSS VMAXSD`

func TestX86AVXFloatBinaryRowsCompleteControls(t *testing.T) {
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	members := regexp.MustCompile(`^V(ADD|SUB|MUL|DIV|MIN|MAX)(PS|PD|SS|SD)$`)
	official := 0
	for _, rule := range avx {
		if members.MatchString(rule.Opcode) {
			official++
		}
	}
	if official != 132 {
		t.Fatal("complete original AVX floating row denominator changed", official)
	}
	build := func(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
		return x86PackedBinaryRows(legacy, avx, x86AVXFloatBinaryMembers)
	}
	inventory := x86CheckPackedRowInventory(t, build, members.String(), `P[SD]$`, x86PackedRowCounts{
		names: 24, broadcast: 108,
		rows: [3]int{0, 36, 96}, formats: [3]int{0, 72, 612}, widths: [3]int{336, 132, 216},
	})
	rounding, sae, zeroing, formats := 0, 0, 0, 0
	for _, row := range inventory.rows {
		minmax := strings.HasPrefix(row.Opcode, "VMIN") || strings.HasPrefix(row.Opcode, "VMAX")
		for _, witness := range row.Witnesses {
			formats++
			operation := strings.Fields(witness.Instruction)[0]
			if strings.Contains(operation, "_SAE") {
				rounding++
				if minmax || witness.Memory || witness.Width != 512 && !strings.HasSuffix(row.Opcode, "SS") && !strings.HasSuffix(row.Opcode, "SD") {
					t.Fatal("embedded rounding escaped its original arithmetic register shape", row.ID, witness)
				}
			}
			if strings.Contains(operation, ".SAE") {
				sae++
				if !minmax || witness.Memory || witness.Width != 512 && !strings.HasSuffix(row.Opcode, "SS") && !strings.HasSuffix(row.Opcode, "SD") {
					t.Fatal("SAE escaped its original MIN/MAX register shape", row.ID, witness)
				}
			}
			if witness.Zeroing {
				zeroing++
			}
		}
	}
	if formats != 684 || rounding != 192 || sae != 24 || zeroing != 204 {
		t.Fatal("full floating control witness inventory changed", formats, rounding, sae, zeroing)
	}
	x86CheckPackedEncodingAnchors(t, inventory.rows, []x86PackedEncodingAnchor{
		{"VADDSD X0,X1,X2", []byte{0xc5, 0xf3, 0x58, 0xd0}},
		{"VADDSS X0,X1,X2", []byte{0xc5, 0xf2, 0x58, 0xd0}},
		{"VDIVSD.RD_SAE X16,X17,X18", []byte{0x62, 0xa1, 0xf7, 0x30, 0x5e, 0xd0}},
		{"VMINPD.SAE Z16,Z17,Z18", []byte{0x62, 0xa1, 0xf5, 0x50, 0x5d, 0xd0}},
		{"VMINSD.SAE X16,X17,X18", []byte{0x62, 0xa1, 0xf7, 0x10, 0x5d, 0xd0}},
		{"VMAXSS.SAE.Z X16,X17,K1,X18", []byte{0x62, 0xa1, 0x76, 0x91, 0x5f, 0xd0}},
	})
}

func TestX86AVXFloatBinarySAEKeepsVectorLength(t *testing.T) {
	rule := X86AVXRule{Opcode: "VMINPD", Ytab: "_yvaddpd", Prefix: "Pavx",
		Classes: []string{"Yzm", "Yzr", "Yzr"}, ZCase: "Zevex_rm_v_r",
		OpBytes: []string{"avxEscape | evex512 | evex66 | evex0F | evexW1", "evexN64 | evexBcstN8 | evexSaeEnabled | evexZeroingEnabled", "0x5D"}}
	witnesses, err := x86PackedAVXRowWitnesses(rule)
	if err != nil || len(witnesses) != 4 || witnesses[3].Instruction != "VMINPD.SAE Z16,Z17,Z18" ||
		!bytes.Equal(witnesses[3].Encoding, []byte{0x62, 0xa1, 0xf5, 0x50, 0x5d, 0xd0}) {
		t.Fatal("SAE reused RC's LL replacement or lost its complete original row", witnesses, err)
	}
	for _, edit := range []func(*X86AVXRule){
		func(r *X86AVXRule) { r.OpBytes[1] += " | evexRoundingEnabled" },
		func(r *X86AVXRule) { r.OpBytes[0] += " | evexF2" },
		func(r *X86AVXRule) { r.Ytab = "_yvandnpd" },
		func(r *X86AVXRule) {
			r.Classes = []string{"YxmEvex", "YxrEvex", "YxrEvex"}
			r.OpBytes[0] = strings.Replace(r.OpBytes[0], "evex512", "evex128", 1)
			r.OpBytes[1] = strings.Replace(r.OpBytes[1], "evexN64", "evexN16", 1)
		},
	} {
		local := rule
		local.OpBytes = append([]string(nil), rule.OpBytes...)
		edit(&local)
		if witnesses, err := x86PackedAVXRowWitnesses(local); err == nil || len(witnesses) != 0 {
			t.Fatal("unknown SAE, width, PP or conflicting ER metadata acquired witnesses", witnesses, err)
		}
	}
}

func TestX86AVXFloatBinaryScalarPPDoesNotWidenIntegerBinary(t *testing.T) {
	for _, prefix := range []string{"vexF2", "vexF3"} {
		rule := X86AVXRule{Opcode: "VPMULLD", Ytab: "_yvandnpd", Prefix: "Pavx",
			Classes: []string{"Yxm", "Yxr", "Yxr"}, ZCase: "Zvex_rm_v_r", ZOffset: 2,
			OpBytes: []string{"avxEscape | vex128 | " + prefix + " | vex0F38 | vexW0", "0x40"}}
		if witnesses, err := x86PackedAVXRowWitnesses(rule); err == nil || len(witnesses) != 0 {
			t.Fatal("floating scalar pp widened integer binary grammar", witnesses, err)
		}
	}
}
