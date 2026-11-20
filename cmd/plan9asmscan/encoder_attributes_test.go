package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

const x86EncoderAttributeFixture = `package x86
var shared = []ytab{
	{zcase: Zvex_rm_v_r, zoffset: 2, args: argList{Yxm, Yxr, Yxr}},
	{zcase: Zevex_rm_v_r, zoffset: 0, args: argList{Yzm, Yzr, Yzr}},
	{zcase: Zevex_rm_v_k_r, zoffset: 3, args: argList{Yzm, Yzr, Yknot0, Yzr}},
}
var avxOptab = [...]Optab{
	{as: AVPMULLW, ytab: shared, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xD5,
		avxEscape | evex512 | evex66 | evex0F | evexW0,
		evexN64 | evexZeroingEnabled, 0xD5,
	}},
}
`

var x86EncoderAttributeMutations = []struct {
	name, before, after string
}{
	{"width", "evex512", "evex256"},
	{"broadcast", "evexN64 | evexZeroingEnabled", "evexN64 | evexBcstN4 | evexZeroingEnabled"},
	{"zeroing", "evexN64 | evexZeroingEnabled", "evexN64"},
	{"rounding", "evexN64 | evexZeroingEnabled", "evexN64 | evexRoundingEnabled"},
	{"sae", "evexN64 | evexZeroingEnabled", "evexN64 | evexSaeEnabled"},
	{"tuple", "evexN64", "evexN32"},
	{"w", "evexW0", "evexW1"},
	{"opcode", "0xD5", "0xE5"},
	{"prefix", "prefix: Pavx", "prefix: Pq4"},
	{"zcase", "zcase: Zevex_rm_v_r", "zcase: Zevex_r_v_rm"},
	{"offset", "zoffset: 2", "zoffset: 3"},
}

func loadX86EncoderAttributeFixture(t *testing.T, source string) []encoderFormReport {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "src", "cmd", "internal", "obj", "x86", "avx_optabs.go")
	writeEncoderFixture(t, path, source)
	forms, err := loadEncoderForms(root, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(forms) != 3 {
		t.Fatalf("operand-class denominator changed: %d", len(forms))
	}
	return forms
}

func TestX86EncoderCatalogRetainsEncodingRulesBeyondOperandClasses(t *testing.T) {
	const source = x86EncoderAttributeFixture
	before := loadX86EncoderAttributeFixture(t, source)
	beforeJSON, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range x86EncoderAttributeMutations {
		t.Run(mutation.name, func(t *testing.T) {
			if !strings.Contains(source, mutation.before) {
				t.Fatal("mutation must change an original encoding rule")
			}
			after := loadX86EncoderAttributeFixture(t, strings.Replace(source, mutation.before, mutation.after, 1))
			for i := range before {
				if before[i].Form != after[i].Form {
					t.Fatal("this regression must retain identical operand classes")
				}
			}
			afterJSON, err := json.Marshal(after)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(beforeJSON, afterJSON) {
				t.Fatal("encoder catalog discarded an encoding rule despite identical operand classes")
			}
		})
	}
}

func TestX86EncoderEncodingFingerprintRetainsRuleAttributes(t *testing.T) {
	read := func(source string) (report, string) {
		var rep report
		attachEncoderCatalog(&rep, nil, loadX86EncoderAttributeFixture(t, source))
		data, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		var fingerprint string
		if raw := fields["encoder_rule_fingerprint"]; raw != nil {
			if err := json.Unmarshal(raw, &fingerprint); err != nil {
				t.Fatal(err)
			}
		}
		return rep, fingerprint
	}
	before, fingerprint := read(x86EncoderAttributeFixture)
	for _, mutation := range x86EncoderAttributeMutations {
		t.Run(mutation.name, func(t *testing.T) {
			after, changed := read(strings.Replace(x86EncoderAttributeFixture, mutation.before, mutation.after, 1))
			if before.EncoderFingerprint != after.EncoderFingerprint {
				t.Fatal("legacy operand-class fingerprint must remain compatible")
			}
			if changed == "" || fingerprint == changed {
				t.Fatal("rule fingerprint omitted an independent encoding attribute")
			}
		})
	}
}

func TestX86EncoderCatalogRetainsZeroOffsetRuleOrderAcrossClassBuckets(t *testing.T) {
	// Zero-offset rows share opcode bytes; their order must survive class
	// grouping. This is a source-inventory fixture, not accepted Go machine code.
	source := strings.Replace(x86EncoderAttributeFixture, "zoffset: 2", "zoffset: 0", 1)
	source = strings.Replace(source, "zoffset: 3", "zoffset: 0", 1)
	rows := strings.Split(source, "\n")
	if !strings.Contains(rows[2], "Zvex_rm_v_r") || !strings.Contains(rows[3], "Zevex_rm_v_r") {
		t.Fatal("independent source fixture layout changed")
	}
	rows[2], rows[3] = rows[3], rows[2]
	before, err := json.Marshal(loadX86EncoderAttributeFixture(t, source))
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(loadX86EncoderAttributeFixture(t, strings.Join(rows, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("catalog discarded rule ordering when every encoding offset stayed equal")
	}
}

func TestX86EncoderRuleFingerprintCountsAndScopeAreIndependent(t *testing.T) {
	catalog := loadX86EncoderAttributeFixture(t, x86EncoderAttributeFixture)
	count, fingerprint := fingerprintEncoderRules(catalog)
	if count != 3 || len(fingerprint) != 64 {
		t.Fatalf("retained source rows have no complete fingerprint: %d/%q", count, fingerprint)
	}
	// Presentation order and observed corpus hits are not encoding changes.
	catalog[0], catalog[2] = catalog[2], catalog[0]
	catalog[0].Tables = []string{"presentation-only"}
	rep := report{SupportedForms: 17, ContextForms: 4}
	attachEncoderCatalog(&rep, map[string]*opStat{"VPMULLW": {}}, catalog)
	if rep.EncoderRules != count || rep.EncoderRuleFingerprint != fingerprint ||
		rep.SupportedForms != 17 || rep.ContextForms != 4 {
		t.Fatal("encoding inventory depends on observation or changed tested coverage")
	}
	// Repeated rows must not be deduplicated away, and absent metadata is not
	// a certificate of an empty or completely implemented official table.
	catalog = append(catalog, catalog[0])
	duplicateCount, duplicateFingerprint := fingerprintEncoderRules(catalog)
	if duplicateCount <= count || duplicateFingerprint == fingerprint {
		t.Fatal("duplicate source rows disappeared from the fingerprint")
	}
	for i := range catalog {
		catalog[i].EncodingRules = nil
	}
	if count, fingerprint := fingerprintEncoderRules(catalog); count != 0 || fingerprint != "" {
		t.Fatal("unretained tables fabricated a rule certificate")
	}
}
