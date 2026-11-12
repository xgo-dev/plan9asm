package gostaticstorage

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func asmTextSourceOrderFixture() ([]byte, ASMDataMember) {
	source := []byte(`TEXT foreign·Entry<ABIInternal>(SB),4,$0-0
RET
TEXT private<>(SB),4,$0-0
RET
TEXT ·Own<ABI0>(SB),4,$0-0
RET
TEXT other<>(SB),4,$0-0
RET
TEXT foreign·Second<ABI0>(SB),4,$0-0
RET
`)
	member := ASMDataMember{Flags: 4, Texts: []TextRecord{
		{Name: "private", ABI: 65535, Namespace: TextSymbolSelf, Index: 0, Relative: 0, Kind: 1, Size: 1, Code: []byte{0xc3}},
		{Name: "other", ABI: 65535, Namespace: TextSymbolSelf, Index: 1, Relative: 1, Kind: 1, Size: 1, Code: []byte{0xc3}},
		{Name: "foreign.Entry", ABI: 1, Namespace: TextSymbolNonpkgDefinition, Index: 20, Relative: 0, Kind: 1, Size: 1, Code: []byte{0xc3}},
		{Name: "fixture.Own", ABI: 0, Namespace: TextSymbolNonpkgDefinition, Index: 21, Relative: 1, Kind: 1, Size: 1, Code: []byte{0xc3}},
		{Name: "foreign.Second", ABI: 0, Namespace: TextSymbolNonpkgDefinition, Index: 22, Relative: 2, Kind: 1, Size: 1, Code: []byte{0xc3}},
	}}
	return source, member
}

func TestASMSourceTextOrderPreservesPhysicalRecords(t *testing.T) {
	source, member := asmTextSourceOrderFixture()
	before, _ := json.Marshal(member)
	order, err := ASMSourceTextOrder(source, "fixture", member)
	if err != nil || len(order) != len(member.Texts) {
		t.Fatal("complete mixed-bank association", err)
	}
	var indices []int
	for ordinal, association := range order {
		indices = append(indices, association.ObjectOrdinal)
		record := member.Texts[association.ObjectOrdinal]
		if association.SourceOrdinal != ordinal || association.Name != record.Name || association.ABI != record.ABI ||
			association.Namespace != record.Namespace || association.Relative != record.Relative || association.Index != record.Index {
			t.Fatal("association lost an exact source/physical identity", association, record)
		}
	}
	after, _ := json.Marshal(member)
	if !reflect.DeepEqual(indices, []int{2, 0, 3, 1, 4}) || !bytes.Equal(before, after) {
		t.Fatal("source association sorted/rewrote physical evidence", indices)
	}
}

func TestASMSourceTextOrderCompleteIdentityGuards(t *testing.T) {
	for _, row := range []struct {
		name   string
		mutate func(*[]byte, *ASMDataMember)
	}{
		{"missing", func(_ *[]byte, m *ASMDataMember) { m.Texts = m.Texts[:4] }},
		{"duplicate-record", func(_ *[]byte, m *ASMDataMember) { m.Texts[4] = m.Texts[3] }},
		{"duplicate-source", func(s *[]byte, _ *ASMDataMember) {
			*s = bytes.Replace(*s, []byte("foreign·Second<ABI0>"), []byte("foreign·Entry<ABIInternal>"), 1)
		}},
		{"wrong-ABI", func(s *[]byte, _ *ASMDataMember) {
			*s = bytes.Replace(*s, []byte("Own<ABI0>"), []byte("Own<ABIInternal>"), 1)
		}},
		{"wrong-static-role", func(s *[]byte, _ *ASMDataMember) { *s = bytes.Replace(*s, []byte("private<>"), []byte("private"), 1) }},
		{"unknown-name", func(_ *[]byte, m *ASMDataMember) { m.Texts[2].Name = "foreign.Unknown" }},
		{"unknown-ABI", func(_ *[]byte, m *ASMDataMember) { m.Texts[2].ABI = 9 }},
		{"unknown-kind", func(_ *[]byte, m *ASMDataMember) { m.Texts[2].Kind = 3 }},
		{"hashed-role", func(_ *[]byte, m *ASMDataMember) { m.Texts[2].Namespace = TextSymbolHashed }},
		{"reference-role", func(_ *[]byte, m *ASMDataMember) { m.Texts[2].Namespace = TextSymbolNonpkgReference }},
		{"wrong-static-namespace", func(_ *[]byte, m *ASMDataMember) { m.Texts[0].Namespace = TextSymbolNonpkgDefinition }},
		{"wrong-named-namespace", func(_ *[]byte, m *ASMDataMember) { m.Texts[2].Namespace = TextSymbolSelf }},
		{"duplicate-index", func(_ *[]byte, m *ASMDataMember) { m.Texts[3].Index = m.Texts[2].Index }},
		{"wrong-relative", func(_ *[]byte, m *ASMDataMember) { m.Texts[3].Relative++ }},
		{"physical-order", func(_ *[]byte, m *ASMDataMember) { m.Texts[0], m.Texts[1] = m.Texts[1], m.Texts[0] }},
		{"source-order-in-bank", func(s *[]byte, _ *ASMDataMember) {
			*s = []byte(strings.NewReplacer("private<>", "other<>", "other<>", "private<>").Replace(string(*s)))
		}},
		{"compiler-not-ASM", func(_ *[]byte, m *ASMDataMember) { m.Flags = 16 }},
	} {
		t.Run(row.name, func(t *testing.T) {
			source, member := asmTextSourceOrderFixture()
			row.mutate(&source, &member)
			if _, err := ASMSourceTextOrder(source, "fixture", member); !errors.Is(err, ErrContext) {
				t.Fatal("unknown/duplicate/missing/exchanged identity acquired an association", err)
			}
		})
	}
}
