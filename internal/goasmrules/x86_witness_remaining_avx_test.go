package goasmrules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// This tests source-row grammar only. A witness is not stock-Go selection,
// a public translated function, an LLVM object or executed semantics.
func TestX86RemainingAVXSemanticClosuresExistingWitnesses(t *testing.T) {
	groups := []struct {
		name    string
		rows    int
		members string
	}{
		{"FP-unary-scaled-rounding", 90, `
			VEXP2PD VEXP2PS VGETEXPPD VGETEXPPS VGETEXPSD VGETEXPSS
			VRCP28PD VRCP28PS VRCP28SD VRCP28SS VRCPPS VRCPSS
			VROUNDPD VROUNDPS VROUNDSD VROUNDSS VRSQRT28PD VRSQRT28PS
			VRSQRT28SD VRSQRT28SS VRSQRTPS VRSQRTSS VSCALEFPD VSCALEFPS
			VSCALEFSD VSCALEFSS VSQRTPD VSQRTPS VSQRTSD VSQRTSS
		`},
		{"indexed-memory", 80, `
			VGATHERDPD VGATHERDPS VGATHERPF0DPD VGATHERPF0DPS VGATHERPF0QPD VGATHERPF0QPS
			VGATHERPF1DPD VGATHERPF1DPS VGATHERPF1QPD VGATHERPF1QPS VGATHERQPD VGATHERQPS
			VPGATHERDD VPGATHERDQ VPGATHERQD VPGATHERQQ VPSCATTERDD VPSCATTERDQ
			VPSCATTERQD VPSCATTERQQ VSCATTERDPD VSCATTERDPS VSCATTERPF0DPD VSCATTERPF0DPS
			VSCATTERPF0QPD VSCATTERPF0QPS VSCATTERPF1DPD VSCATTERPF1DPS VSCATTERPF1QPD VSCATTERPF1QPS
			VSCATTERQPD VSCATTERQPS
		`},
		{"FP-compare-class", 46, `
			VCMPPD VCMPPS VCMPSD VCMPSS VCOMISD VCOMISS
			VFPCLASSPDX VFPCLASSPDY VFPCLASSPDZ VFPCLASSPSX VFPCLASSPSY VFPCLASSPSZ
			VFPCLASSSD VFPCLASSSS VUCOMISD VUCOMISS
		`},
		{"horizontal-blend-dot-SAD", 37, `
			VADDSUBPD VADDSUBPS VBLENDPD VBLENDPS VBLENDVPD VBLENDVPS
			VDPPD VDPPS VHADDPD VHADDPS VHSUBPD VHSUBPS
			VMPSADBW VPBLENDD VPBLENDVB VPBLENDW VPHMINPOSUW VPSADBW
		`},
		{"GP-BMI", 28, `
			ANDNL ANDNQ BEXTRL BEXTRQ BLSIL BLSIQ
			BLSMSKL BLSMSKQ BLSRL BLSRQ BZHIL BZHIQ
			MULXL MULXQ PDEPL PDEPQ PEXTL PEXTQ
			RORXL RORXQ SARXL SARXQ SHLXL SHLXQ
			SHRXL SHRXQ
		`},
		{"crypto", 28, `
			VAESDEC VAESDECLAST VAESENC VAESENCLAST VAESIMC VAESKEYGENASSIST
			VPCLMULQDQ
		`},
		{"four-register-special", 12, `
			V4FMADDPS V4FMADDSS V4FNMADDPS V4FNMADDSS VP4DPWSSD VP4DPWSSDS
		`},
		{"packed-string-compare", 8, `
			VPCMPESTRI VPCMPESTRM VPCMPISTRI VPCMPISTRM
		`},
		{"bit-shuffle-to-K", 6, `
			VPSHUFBITQMB
		`},
		{"vector-test-FLAGS", 6, `
			VPTEST VTESTPD VTESTPS
		`},
		{"state-control", 4, `
			VLDMXCSR VSTMXCSR VZEROALL VZEROUPPER
		`},
	}
	if len(groups) != 11 {
		t.Fatal("complete remaining semantic closure changed", len(groups))
	}
	selected := make(map[string]int)
	for index, group := range groups {
		for _, name := range strings.Fields(group.members) {
			if _, duplicate := selected[name]; duplicate {
				t.Fatal("source member belongs to more than one remaining closure", name)
			}
			selected[name] = index
		}
	}
	if len(selected) != 147 {
		t.Fatal("complete remaining source namespace changed", len(selected))
	}
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	type originalRow struct {
		id   string
		rule X86AVXRule
	}
	rows := make([][]originalRow, len(groups))
	seen := make(map[string]bool)
	total := 0
	for index, rule := range rules {
		group, retained := selected[rule.Opcode]
		if !retained {
			continue
		}
		id := fmt.Sprintf("avx/%d/%s/%s/%d", index, rule.Opcode, rule.Ytab, rule.RowIndex)
		rows[group] = append(rows[group], originalRow{id, rule})
		seen[rule.Opcode] = true
		total++
	}
	if total != 345 || len(seen) != 147 {
		t.Fatal("retain all original rows and members, without shadow/direction filtering", total, len(seen))
	}
	for index, group := range groups {
		if len(rows[index]) != group.rows {
			t.Fatal("complete original semantic family row count changed", group.name, len(rows[index]), group.rows)
		}
		t.Run(group.name, func(t *testing.T) {
			for _, original := range rows[index] {
				t.Run(original.id, func(t *testing.T) {
					// Preserve the full literal row, including ordinal, payload,
					// offset and source classes. Never rebuild it from a witness.
					before, err := json.Marshal(original.rule)
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("original_source_id=%s original_rule=%s", original.id, before)
					// A panic is a failing row too; retain later rows in this
					// discovery run rather than losing the remaining directory.
					defer func() {
						if failure := recover(); failure != nil {
							t.Errorf("existing witness helper panicked for original row %s: %v", original.id, failure)
						}
					}()
					witnesses, err := x86PackedAVXRowWitnesses(original.rule)
					after, encodeErr := json.Marshal(original.rule)
					if encodeErr != nil || !bytes.Equal(before, after) {
						t.Fatal("witness helper changed the original source metadata", original.id, encodeErr)
					}
					if err != nil || len(witnesses) == 0 {
						t.Fatal("original row has no complete current witness grammar; not evidence of translator/ISA rejection", original.id, err)
					}
					for _, witness := range witnesses {
						if witness.Instruction == "" || len(witness.Encoding) == 0 {
							t.Fatal("existing witness lost a complete source or expected encoding", original.id, witness)
						}
					}
				})
			}
		})
	}
}
