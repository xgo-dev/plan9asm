package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type x86PackedPhysicalTestFamily struct {
	names  string
	parse  func(Op, Instr, string) (x86PackedBinaryForm, Operand, bool, error)
	decode func([]byte, int) (Instr, int, bool, error)
	rawOp  string
}

func x86PackedPhysicalTestFamilies() []x86PackedPhysicalTestFamily {
	return []x86PackedPhysicalTestFamily{
		{"PAVGB PAVGW VPAVGB VPAVGW", func(op Op, ins Instr, arch string) (x86PackedBinaryForm, Operand, bool, error) {
			form, known, err := x86PackedAverageProperties(op, ins, arch)
			return form.x86PackedBinaryForm, form.source, known, err
		}, decodedX86PackedAverageInstruction, "VPAVGB"},
		{"PMULLW PMULHW PMULHUW PMULHRSW VPMULLW VPMULHW VPMULHUW VPMULHRSW", func(op Op, ins Instr, arch string) (x86PackedBinaryForm, Operand, bool, error) {
			form, known, err := x86PackedWordMultiplyProperties(op, ins, arch)
			return form.x86PackedBinaryForm, form.source, known, err
		}, decodedX86PackedMultiplyInstruction, "VPMULLW"},
		{"PMULDQ PMULULQ VPMULDQ VPMULUDQ", func(op Op, ins Instr, arch string) (x86PackedBinaryForm, Operand, bool, error) {
			form, known, err := x86DwordProductProperties(op, ins, arch)
			return form.x86PackedBinaryForm, form.source, known, err
		}, decodedX86DwordToQwordMultiplyInstruction, "VPMULDQ"},
		{"PMADDWL PMADDUBSW VPMADDWD VPMADDUBSW", func(op Op, ins Instr, arch string) (x86PackedBinaryForm, Operand, bool, error) {
			form, known, err := x86PackedMultiplyAddProperties(op, ins, arch)
			return form.x86PackedBinaryForm, form.source, known, err
		}, decodedX86EVEXPackedMADDInstruction, "VPMADDWD"},
	}
}

func x86PackedPhysicalTestInstruction(name string, memory bool) Instr {
	ins := Instr{Op: Op(name), Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}}}
	if strings.HasPrefix(name, "V") {
		ins.Args = append(ins.Args, Operand{Kind: OpReg, Reg: "X2"})
	}
	if memory {
		ins.Args[0] = Operand{Kind: OpMem, Mem: MemRef{Base: AX, Off: 16}}
	}
	return ins
}

func x86PackedPhysicalTestMMX(name string) bool {
	return strings.Contains(" PAVGB PAVGW PMULLW PMULHW PMULHUW PMULULQ PMADDWL ", " "+name+" ")
}

func TestX86PackedPhysicalPropertiesPreserveOperands(t *testing.T) {
	for _, family := range x86PackedPhysicalTestFamilies() {
		for _, name := range strings.Fields(family.names) {
			t.Run(name, func(t *testing.T) {
				for _, memory := range []bool{false, true} {
					ins := x86PackedPhysicalTestInstruction(name, memory)
					before := append([]Operand(nil), ins.Args...)
					form, source, known, err := family.parse(ins.Op, ins, "amd64")
					if !known || err != nil || form.byteWidth != 16 || !reflect.DeepEqual(source, before[0]) {
						t.Fatal("complete original form changed", form, source, err)
					}
					if !reflect.DeepEqual(ins.Args, before) {
						t.Fatal("successful grammar observation mutated source operands")
					}
					if _, _, known, err := family.parse(ins.Op, ins, "arm64"); !known || err == nil {
						t.Fatal("foreign source mode became a matching form", err)
					}
					changed := ins
					changed.Op = "NOP"
					if _, _, known, err := family.parse(ins.Op, changed, "amd64"); !known || err == nil {
						t.Fatal("dispatch/source mismatch acquired a form", err)
					}
					if !reflect.DeepEqual(ins.Args, before) {
						t.Fatal("rejected grammar observation mutated source operands")
					}
				}
				if !x86PackedPhysicalTestMMX(name) {
					return
				}
				for _, alias := range []struct{ source, physical Reg }{{AX, "M0"}, {SP, "M4"}} {
					ins := Instr{Op: Op(name), Args: []Operand{{Kind: OpReg, Reg: alias.source}, {Kind: OpReg, Reg: "M1"}}}
					before := append([]Operand(nil), ins.Args...)
					form, source, known, err := family.parse(ins.Op, ins, "amd64")
					if !known || err != nil || !form.mmx || form.byteWidth != 8 || source.Reg != alias.physical {
						t.Fatal("original GP spelling lost its distinct MMX bank", form, source, err)
					}
					if !reflect.DeepEqual(ins.Args, before) {
						t.Fatal("MMX projection overwrote the original GP spelling")
					}
					if _, _, known, err := family.parse(ins.Op, ins, "386"); !known || err == nil {
						t.Fatal("named mode32 source acquired an MMX row", err)
					}
				}
			})
		}
	}
}

func TestX86PackedPhysicalPropertiesRetainDecoderBoundaries(t *testing.T) {
	for _, family := range x86PackedPhysicalTestFamilies() {
		t.Run(family.rawOp, func(t *testing.T) {
			code := x86PackedShiftActualGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+
				family.rawOp+" 16(AX),X1,K1,X2\nRET\n")
			if len(code) < 2 || code[len(code)-1] != 0xc3 {
				t.Fatal("original instruction bytes lack the terminal RET", code)
			}
			code = code[:len(code)-1]
			ins, length, known, err := family.decode(code, 32)
			if !known || err != nil || length != len(code) || !ins.x86Encoded {
				t.Fatal("actual mode32 physical decode failed", ins, length, err)
			}
			before := append([]Operand(nil), ins.Args...)
			form, source, known, err := family.parse(ins.Op, ins, "386")
			if !known || err != nil || form.mask < 0 || form.memory != 0 || source.Mem.Base != AX {
				t.Fatal("physical masked form lost its original decoder identity", form, source, err)
			}
			text := ins
			text.x86Encoded = false
			if _, _, _, err := family.parse(text.Op, text, "386"); err == nil {
				t.Fatal("named four-operand source borrowed decoder admission")
			}
			for _, bits := range []int{16, 32, 64} {
				changed := ins
				changed.x86AddressBits = bits
				if _, _, _, err := family.parse(changed.Op, changed, "386"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("address-size override lost its independent context requirement", bits, err)
				}
			}
			changed := ins
			changed.x86UnboundAddressOverride = true
			if _, _, _, err := family.parse(changed.Op, changed, "386"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unbound address override acquired a grammar-only authority", err)
			}
			if !reflect.DeepEqual(ins.Args, before) {
				t.Fatal("physical or rejected observations modified original operands")
			}
		})
	}
}

func TestX86PackedPhysicalPropertiesAvoidRedundantCopies(t *testing.T) {
	for _, family := range x86PackedPhysicalTestFamilies() {
		for _, name := range strings.Fields(family.names) {
			t.Run(name, func(t *testing.T) {
				for _, memory := range []bool{false, true} {
					ins := x86PackedPhysicalTestInstruction(name, memory)
					_, _, known, err := family.parse(ins.Op, ins, "amd64")
					if !known || err != nil {
						t.Fatal("allocation fixture must be accepted", err)
					}
					allocations := testing.AllocsPerRun(100, func() {
						_, _, known, err = family.parse(ins.Op, ins, "amd64")
					})
					limit := 0.0
					if x86PackedPhysicalTestMMX(name) {
						limit = 1 // Existing MMX bank adapter owns its source projection.
					}
					if !known || err != nil || allocations > limit {
						t.Errorf("memory=%v: %.0f allocations, want at most %.0f; known=%v err=%v", memory, allocations, limit, known, err)
					}
				}
			})
		}
	}
}

func BenchmarkX86PackedPhysicalProperties(b *testing.B) {
	for _, family := range x86PackedPhysicalTestFamilies() {
		for _, name := range strings.Fields(family.names) {
			for _, memory := range []bool{false, true} {
				kind := "register"
				if memory {
					kind = "memory"
				}
				ins := x86PackedPhysicalTestInstruction(name, memory)
				b.Run(name+"/"+kind, func(b *testing.B) {
					b.ReportAllocs()
					for n := 0; n < b.N; n++ {
						if _, _, known, err := family.parse(ins.Op, ins, "amd64"); !known || err != nil {
							b.Fatal("allocation benchmark rejected its unchanged input", err)
						}
					}
				})
			}
		}
	}
}

const x86PackedNarrowPhysicalNames = "PACKSSLW PACKSSWB PACKUSDW PACKUSWB VPACKSSDW VPACKSSWB VPACKUSDW VPACKUSWB"

func TestX86PackedNarrowPhysicalRejectionContract(t *testing.T) {
	for _, row := range []struct {
		instruction string
		context     bool
		width       int
	}{
		{"VPACKSSDW (R8),X1,X8", true, 16},
		{"VPACKSSDW (AX),X1,X8", true, 16},
		{"VPACKSSDW (R8),X1,X2", false, 16},
		{"PACKSSWB X0,M1", false, 0},
	} {
		t.Run(row.instruction, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row.instruction+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			ins.x86Encoded = true
			before := append([]Operand(nil), ins.Args...)
			form, known, err := x86PackedNarrowProperties(ins, "386")
			if !known || err == nil || errors.Is(err, ErrProbeNeedsContext) != row.context ||
				form.byteWidth != row.width || !reflect.DeepEqual(form.source, Operand{}) {
				t.Fatal("rejected physical form changed its classification or retained a source", form, known, err)
			}
			if row.width == 0 && !reflect.DeepEqual(form, x86PackedNarrowForm{}) {
				t.Fatal("early MMX failure retained a partial form")
			}
			if !reflect.DeepEqual(ins.Args, before) {
				t.Fatal("rejected physical source was modified")
			}
		})
	}
}

func TestX86PackedNarrowPropertiesAvoidRedundantCopies(t *testing.T) {
	for _, name := range strings.Fields(x86PackedNarrowPhysicalNames) {
		t.Run(name, func(t *testing.T) {
			for _, memory := range []bool{false, true} {
				ins := x86PackedPhysicalTestInstruction(name, memory)
				_, known, err := x86PackedNarrowProperties(ins, "amd64")
				if !known || err != nil {
					t.Fatal("allocation fixture must be accepted", err)
				}
				allocations := testing.AllocsPerRun(100, func() {
					_, known, err = x86PackedNarrowProperties(ins, "amd64")
				})
				limit := 0.0
				if !strings.HasPrefix(name, "V") && name != "PACKUSDW" {
					limit = 1 // Existing MMX bank adapter owns its projection.
				}
				if !known || err != nil || allocations > limit {
					t.Errorf("memory=%v: %.0f allocations, want at most %.0f; known=%v err=%v", memory, allocations, limit, known, err)
				}
			}
		})
	}
}

func BenchmarkX86PackedNarrowProperties(b *testing.B) {
	for _, name := range strings.Fields(x86PackedNarrowPhysicalNames) {
		for _, memory := range []bool{false, true} {
			kind := "register"
			if memory {
				kind = "memory"
			}
			ins := x86PackedPhysicalTestInstruction(name, memory)
			b.Run(name+"/"+kind, func(b *testing.B) {
				b.ReportAllocs()
				for n := 0; n < b.N; n++ {
					if _, known, err := x86PackedNarrowProperties(ins, "amd64"); !known || err != nil {
						b.Fatal("allocation benchmark rejected its input", err)
					}
				}
			})
		}
	}
}
