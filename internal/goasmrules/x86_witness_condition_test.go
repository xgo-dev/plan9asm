package goasmrules

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestX86ConditionalCompleteRowsAndLayouts(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := X86ConditionalRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		names, ids := map[string]bool{}, map[string]bool{}
		branches, sets, forms := 0, 0, 0
		for _, row := range rows {
			if row.ID == "" || ids[row.ID] {
				t.Fatal("lost ordered source ID", row)
			}
			ids[row.ID], names[row.Opcode] = true, true
			want := 3
			if row.Branch {
				want = 4
				branches++
			} else {
				sets++
			}
			if len(row.Witnesses) != want {
				t.Fatal("lost complete control/byte layouts", row)
			}
			seen := map[string]bool{}
			for _, w := range row.Witnesses {
				if seen[w.Layout] || !strings.HasPrefix(w.Instruction, row.Opcode+" ") || len(w.Encoding) == 0 {
					t.Fatal("duplicate/empty physical layout", row, w)
				}
				seen[w.Layout] = true
				forms++
			}
		}
		if len(rows) != 64 || len(names) != 32 || branches != 48 || sets != 16 || forms != 240 {
			t.Fatal("complete condition family changed", arch, len(rows), len(names), branches, sets, forms)
		}
	}
	if _, err := X86ConditionalRows(catalog, "arm64"); err == nil {
		t.Fatal("foreign source mode admitted")
	}
	if _, err := X86ConditionalRows(X86LegacyCatalog{}, "amd64"); err == nil {
		t.Fatal("empty source treated as successful coverage")
	}
}

func TestX86ConditionalIndependentEncodingAnchors(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []struct {
		arch, instruction, layout string
		code                      []byte
	}{
		{"amd64", "JNE taken", "short-forward", []byte{0x75, 3}},
		{"amd64", "JNE $0,taken", "near-forward", []byte{0x0f, 0x85, 0x83, 0, 0, 0}},
		{"amd64", "JNE $1,taken", "short-backward", []byte{0x75, 0xf6}},
		{"amd64", "JNE taken", "near-backward", []byte{0x0f, 0x85, 0x6f, 0xff, 0xff, 0xff}},
		{"386", "JNE taken", "short-forward", []byte{0x75, 2}},
		{"386", "JNE $0,taken", "near-forward", []byte{0x0f, 0x85, 0x82, 0, 0, 0}},
		{"386", "JNE $1,taken", "short-backward", []byte{0x75, 0xf8}},
		{"386", "JNE taken", "near-backward", []byte{0x0f, 0x85, 0x71, 0xff, 0xff, 0xff}},
		{"amd64", "SETCC AX", "AX", []byte{0x0f, 0x93, 0xc0}},
		{"386", "SETEQ AH", "AH", []byte{0x0f, 0x94, 0xc4}},
		{"amd64", "SETPS 0(SI)", "0(SI)", []byte{0x0f, 0x9a, 6}},
	} {
		t.Run(a.arch+"/"+a.instruction+"/"+a.layout, func(t *testing.T) {
			rows, err := X86ConditionalRows(catalog, a.arch)
			if err != nil {
				t.Fatal(err)
			}
			matches := 0
			for _, r := range rows {
				for _, w := range r.Witnesses {
					if w.Instruction == a.instruction && w.Layout == a.layout {
						matches++
						if !bytes.Equal(w.Encoding, a.code) {
							t.Fatalf("code=%x want=%x", w.Encoding, a.code)
						}
					}
				}
			}
			if matches != 1 {
				t.Fatal("anchor lost unique original row/layout", matches)
			}
		})
	}
}

func TestX86ConditionalRejectsChangedSchemaBeforeProjection(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, opcode := range []string{"JCC", "SETCC"} {
		for _, entry := range catalog.Optab {
			if entry.Opcode != opcode {
				continue
			}
			for _, m := range []struct {
				name   string
				change func(*X86LegacyOpcode)
			}{
				{"kind", func(e *X86LegacyOpcode) { e.Kind = "special" }},
				{"prefix", func(e *X86LegacyOpcode) { e.Prefix = "Pq" }},
				{"table", func(e *X86LegacyOpcode) { e.Ytab = "unknown" }},
				{"escape", func(e *X86LegacyOpcode) { e.EscapeAdjustment ^= 1 }},
				{"row-count", func(e *X86LegacyOpcode) { e.Rows = e.Rows[:len(e.Rows)-1] }},
				{"row-order", func(e *X86LegacyOpcode) { e.Rows[0].RowIndex = 9 }},
				{"classes", func(e *X86LegacyOpcode) { e.Rows[0].Classes = []string{"Yi8", "Ybr"} }},
				{"zcase", func(e *X86LegacyOpcode) { e.Rows[0].ZCase = "Zjmp" }},
				{"stride", func(e *X86LegacyOpcode) { e.Rows[0].ZOffset++ }},
				{"offset", func(e *X86LegacyOpcode) { e.Rows[0].UnmatchedOffset++ }},
				{"extra-payload", func(e *X86LegacyOpcode) { e.OpBytes = append(e.OpBytes, "0") }},
				{"symbol-payload", func(e *X86LegacyOpcode) { e.OpBytes[0] = "opcode" }},
				{"nonzero-tail", func(e *X86LegacyOpcode) { e.OpBytes[len(e.OpBytes)-1] = "1" }},
			} {
				t.Run(opcode+"/"+m.name, func(t *testing.T) {
					branch := opcode == "JCC"
					if _, err := x86ConditionPayload(entry, branch); err != nil {
						t.Fatal("valid original failed before mutation", err)
					}
					changed := entry
					changed.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
					changed.OpBytes = append([]string(nil), entry.OpBytes...)
					m.change(&changed)
					if _, err := x86ConditionPayload(changed, branch); err == nil {
						t.Fatal("changed physical source axis admitted")
					}
				})
			}
		}
	}
}
