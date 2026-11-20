package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

// The absent SIB index leaves its encoded scale inactive. x86asm retains
// 1/2/4/8 even then, whereas Go source has no multiplier and the parser keeps
// zero. Compare only this source/physical representation difference on copies;
// every active index and all other operand fields remain exact. Independent
// original-byte tests must still check the decoder's physical scale itself.
// This is a test oracle, never a source normalization or memory certificate.
func x86RawOperandsMatchGoSource(decoded, source []Operand) bool {
	if len(decoded) != len(source) {
		return false
	}
	copyDecoded := append([]Operand(nil), decoded...)
	for i := range copyDecoded {
		actual, expected := &copyDecoded[i], source[i]
		if actual.Kind != OpMem || expected.Kind != OpMem || actual.Mem.Index != "" ||
			expected.Mem.Index != "" || expected.Mem.Scale != 0 {
			continue
		}
		switch actual.Mem.Scale {
		case 0, 1, 2, 4, 8:
			actual.Mem.Scale = 0
		default:
			return false
		}
	}
	return reflect.DeepEqual(copyDecoded, source)
}

func TestX86RawSourceOperandComparison(t *testing.T) {
	source := []Operand{{Kind: OpMem, Mem: MemRef{Base: SP, Off: 8192}}, {Kind: OpReg, Reg: "X0"}}
	before := fmt.Sprintf("%#v", source)
	for _, scale := range []int64{0, 1, 2, 4, 8} {
		decoded := append([]Operand(nil), source...)
		decoded[0].Mem.Scale = scale
		physical := fmt.Sprintf("%#v", decoded)
		if !x86RawOperandsMatchGoSource(decoded, source) || physical != fmt.Sprintf("%#v", decoded) {
			t.Errorf("inactive scale %d comparison failed or changed physical fields: decoded=%#v source=%#v", scale, decoded, source)
		}
	}
	mutations := []struct {
		name string
		edit func(*Operand)
	}{
		{"invalid scale", func(a *Operand) { a.Mem.Scale = 3 }},
		{"base", func(a *Operand) { a.Mem.Base = BP }},
		{"index", func(a *Operand) { a.Mem.Index = CX }},
		{"offset", func(a *Operand) { a.Mem.Off++ }},
		{"segment", func(a *Operand) { a.Mem.Segment = FS }},
		{"symbol", func(a *Operand) { a.Mem.Sym = "slot" }},
		{"unresolved offset", func(a *Operand) { a.Mem.OffRaw = "unknown" }},
		{"index extension", func(a *Operand) { a.Mem.IndexExt = ExtendUXTW }},
		{"operand role", func(a *Operand) { a.Kind = OpFP }},
		{"unrelated field", func(a *Operand) { a.Imm = 1 }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			decoded := append([]Operand(nil), source...)
			mutation.edit(&decoded[0])
			if x86RawOperandsMatchGoSource(decoded, source) {
				t.Fatalf("ignored a real operand difference: %#v", decoded)
			}
		})
	}
	indexed := append([]Operand(nil), source...)
	indexed[0].Mem.Index, indexed[0].Mem.Scale = CX, 4
	for _, scale := range []int64{0, 1, 2, 3, 8} {
		decoded := append([]Operand(nil), indexed...)
		decoded[0].Mem.Scale = scale
		if x86RawOperandsMatchGoSource(decoded, indexed) {
			t.Fatalf("ignored active index scale %d", scale)
		}
	}
	if !x86RawOperandsMatchGoSource(indexed, indexed) || before != fmt.Sprintf("%#v", source) {
		t.Fatal("comparison lost exact indexed equality or mutated its source")
	}
	if x86RawOperandsMatchGoSource(source[:1], source) || x86RawOperandsMatchGoSource(source, source[:1]) {
		t.Fatal("comparison ignored a missing/extra operand")
	}
}
