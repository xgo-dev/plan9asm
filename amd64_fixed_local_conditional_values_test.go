package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalConditionalTypedValues(t *testing.T) {
	for _, condition := range x86CMOVOracleConditions {
		for _, width := range []struct {
			name  string
			bytes int64
		}{{"W", 2}, {"L", 4}, {"Q", 8}} {
			for _, source := range []string{"AX", "BX", "8(SP)"} {
				text := "CMOV" + width.name + condition.name + " " + source + ",BX"
				t.Run(text, func(t *testing.T) {
					state := fixedLocalExchangeState()
					state.known[AX], state.known[BX] = 255, 255
					state.booleans[AX], state.booleans[BX] = 0x55, 0xaa
					for i := int64(0); i < 8; i++ {
						state.bytes.set(8+i, true)
						state.booleanBytes.set(8+i, 0x55&(1<<uint(i)) != 0)
					}
					ins := x86ScalarLaneInstruction(t, text)
					if err := fixedLocalStep(&ins, &state, FuncSig{}, &x86FixedLocalProof{frame: 64}, 0); err != nil {
						t.Fatal("complete numerical alternatives rejected", err)
					}
					mask := uint8((1 << uint(width.bytes)) - 1)
					want := uint8(0xaa &^ mask)
					if source == "BX" {
						want |= 0xaa & mask
					}
					if width.bytes == 4 {
						want |= 240
					}
					if state.booleans[BX] != want || state.known[BX] != 255 || state.flags != x86ByteFlagsAll {
						t.Fatal("conditional selection lost byte intersection, upper writeback or FLAGS", state)
					}
					if _, constant := state.constants[BX]; constant {
						t.Fatal("a memory/partial numerical value acquired an invented constant")
					}
				})
			}
		}
	}
}

func TestGoAMD64FixedLocalConditionalPointerIdentity(t *testing.T) {
	for _, condition := range x86CMOVOracleConditions {
		for _, row := range []struct {
			name   string
			origin x86FixedLocalOrigin
		}{
			{"private", x86FixedLocalOrigin{}},
			{"input", x86FixedLocalOrigin{parameter: 8}},
			{"literal", x86FixedLocalOrigin{literal: x86StaticSBAddress{"table<>", 16}}},
			{"global", x86FixedLocalOrigin{global: "example.global"}},
		} {
			for _, source := range []string{"AX", "BX", "8(SP)"} {
				t.Run(condition.name+"/"+row.name+"/"+source, func(t *testing.T) {
					state := fixedLocalExchangeState()
					if row.name == "private" {
						state.pointers[AX], state.pointers[BX], state.addresses[8] = 24, 24, 24
					} else {
						origin := fixedLocalOrigin(row.origin)
						state.opaque[AX], state.opaque[BX], state.opaqueCells[8] = origin, origin, origin
					}
					before := cloneFixedLocalState(state)
					ins := x86ScalarLaneInstruction(t, "CMOVQ"+condition.name+" "+source+",BX")
					if err := fixedLocalStep(&ins, &state, FuncSig{}, &x86FixedLocalProof{frame: 64}, 0); err != nil {
						t.Fatal("same complete pointer identity was treated as numerical bytes", err)
					}
					if state.known[BX] != 0 || state.flags != before.flags ||
						!reflect.DeepEqual(state.pointers, before.pointers) || !reflect.DeepEqual(state.opaque, before.opaque) {
						t.Fatal("conditional pointer acquired NUM, lost identity or changed FLAGS", state, before)
					}
				})
			}
		}
	}
}

func TestGoAMD64FixedLocalConditionalRangeAndAuthority(t *testing.T) {
	t.Run("different inputs", func(t *testing.T) {
		state := fixedLocalExchangeState()
		state.opaque[SI] = fixedLocalOrigin(x86FixedLocalOrigin{parameter: 0})
		state.opaque[DI] = fixedLocalOrigin(x86FixedLocalOrigin{parameter: 8})
		ins := x86ScalarLaneInstruction(t, "CMOVQEQ SI,DI")
		proof := &x86FixedLocalProof{frame: 64}
		if err := fixedLocalStep(&ins, &state, FuncSig{}, proof, 0); err != nil {
			t.Fatal("two bounded native alternatives rejected", err)
		}
		if !state.opaque[DI].valid() || state.opaque[DI].readonly() || fixedLocalNumericRead(Operand{Kind: OpReg, Reg: DI}, 8, &state) {
			t.Fatal("conditional input address was lost or acquired an unrelated role")
		}
		read := x86ScalarLaneInstruction(t, "MOVQ (DI),AX")
		if err := fixedLocalStep(&read, &state, FuncSig{}, proof, 0); err != nil {
			t.Fatal("native alternatives lost their existing faulting read", err)
		}
	})
	for _, bounds := range []struct {
		name              string
		left, right, want x86UnsignedRange
		both              bool
	}{
		{"same constant", x86UnsignedRange{8, 8}, x86UnsignedRange{8, 8}, x86UnsignedRange{8, 8}, true},
		{"same", x86UnsignedRange{8, 16}, x86UnsignedRange{8, 16}, x86UnsignedRange{8, 16}, true},
		{"overlap", x86UnsignedRange{8, 16}, x86UnsignedRange{12, 24}, x86UnsignedRange{8, 24}, true},
		{"reverse overlap", x86UnsignedRange{12, 24}, x86UnsignedRange{8, 16}, x86UnsignedRange{8, 24}, true},
		{"disjoint", x86UnsignedRange{8, 8}, x86UnsignedRange{24, 24}, x86UnsignedRange{8, 24}, true},
		{"reverse disjoint", x86UnsignedRange{24, 24}, x86UnsignedRange{8, 8}, x86UnsignedRange{8, 24}, true},
		{"one unbounded", x86UnsignedRange{8, 16}, x86UnsignedRange{}, x86UnsignedRange{}, false},
	} {
		t.Run(bounds.name, func(t *testing.T) {
			state := fixedLocalExchangeState()
			state.known[AX], state.known[BX] = 255, 255
			state.setRange(AX, bounds.left)
			if bounds.both {
				state.setRange(BX, bounds.right)
			}
			if bounds.left.minimum == bounds.left.maximum {
				state.constants[AX] = int64(bounds.left.minimum)
			}
			if bounds.both && bounds.right.minimum == bounds.right.maximum {
				state.constants[BX] = int64(bounds.right.minimum)
			}
			state.comparison = x86FixedLocalComparison{register: BX, constant: 31}
			ins := x86ScalarLaneInstruction(t, "CMOVQEQ AX,BX")
			if err := fixedLocalStep(&ins, &state, FuncSig{}, &x86FixedLocalProof{frame: 64}, 0); err != nil {
				t.Fatal(err)
			}
			value, bounded := state.ranges[BX]
			if bounded != bounds.both || bounded && value != bounds.want || state.comparison.register != "" {
				t.Fatal("selection intersected ranges or retained its old comparison value", value, bounded, state.comparison)
			}
			constant, known := state.constants[BX]
			if known != (bounds.name == "same constant") || known && constant != 8 {
				t.Fatal("equal constants were lost or unequal alternatives invented a constant", constant, known)
			}
		})
	}
	for _, row := range []struct{ name, body string }{
		{"different private offsets", "LEAQ 8(SP),CX\nLEAQ 24(SP),DX\nCMOVQEQ CX,DX"},
		{"input and NUM", "CMOVQEQ SI,AX"},
		{"NUM and input", "CMOVQEQ AX,SI"},
		{"private and input", "LEAQ 8(SP),CX\nCMOVQEQ CX,SI"},
		{"partial input", "MOVQ SI,CX\nCMOVLEQ SI,CX"},
		{"logical pointer slot", "MOVQ SI,CX\nCMOVQEQ p+0(FP),CX"},
		{"uninitialized potential memory", "CMOVQEQ 8(SP),AX"},
		{"memory extent", "CMOVQEQ 60(SP),AX"},
	} {
		t.Run(row.name, func(t *testing.T) {
			fn, sig, _ := fixedLocalInputFixture(t, "CMPQ AX,AX\n"+row.body)
			if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("conditional selection invented a pointer or access authority", err)
			}
		})
	}
	for _, operands := range []string{"AX,BX", "BX,AX"} {
		t.Run("literal-input/"+operands, func(t *testing.T) {
			state := fixedLocalExchangeState()
			state.opaque[AX] = fixedLocalOrigin(x86FixedLocalOrigin{parameter: 0})
			state.opaque[BX] = fixedLocalOrigin(x86FixedLocalOrigin{literal: x86StaticSBAddress{"table<>", 16}})
			before := cloneFixedLocalState(state)
			ins := x86ScalarLaneInstruction(t, "CMOVQEQ "+operands)
			if err := fixedLocalStep(&ins, &state, FuncSig{}, &x86FixedLocalProof{frame: 64}, 0); !errors.Is(err, ErrProbeNeedsContext) ||
				!reflect.DeepEqual(state, before) {
				t.Fatal("readonly/native selection widened authority or changed rejected state", err)
			}
		})
		t.Run("bound-literal-input/"+operands, func(t *testing.T) {
			state := fixedLocalExchangeState()
			state.opaque[AX] = fixedLocalOrigin(x86FixedLocalOrigin{parameter: 0})
			state.opaque[BX] = fixedLocalOrigin(x86FixedLocalOrigin{literal: x86StaticSBAddress{"table<>", 16}})
			proof := &x86FixedLocalProof{frame: 64, binding: &x86FixedLocalBinding{
				literalData: map[string]x86FixedLocalData{"table<>": {size: 32, alignment: 16}},
			}}
			ins := x86ScalarLaneInstruction(t, "CMOVQEQ "+operands)
			if err := fixedLocalStep(&ins, &state, FuncSig{}, proof, 0); err != nil {
				t.Fatal("bounded readonly/native alternatives rejected", err)
			}
			destination := ins.Args[1].Reg
			read := x86ScalarLaneInstruction(t, fmt.Sprintf("MOVQ (%s),CX", destination))
			if err := fixedLocalStep(&read, &state, FuncSig{}, proof, 0); err != nil {
				t.Fatal("complete readonly/native read rejected", err)
			}
			write := x86ScalarLaneInstruction(t, fmt.Sprintf("MOVQ $1,(%s)", destination))
			if err := fixedLocalStep(&write, &state, FuncSig{}, proof, 0); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("readonly alternative acquired write permission", err)
			}
		})
	}
}

func fixedLocalConditionalBodies() []string {
	var bodies []string
	for _, condition := range x86CMOVOracleConditions {
		for _, body := range []string{
			"MOVQ $8,CX\nMOVQ $8,DX\nCMPQ AX,AX\nCMOVQ%s CX,DX\nMOVQ AX,(SP)(DX*1)\nMOVQ 8(SP),AX",
			"LEAQ 0(SP),CX\nMOVQ CX,DX\nCMPQ AX,AX\nCMOVQ%s CX,DX\nMOVQ (DX),AX",
			"MOVQ SI,CX\nCMPQ AX,AX\nCMOVQ%s SI,CX\nMOVQ (CX),AX",
		} {
			bodies = append(bodies, fmt.Sprintf(body, condition.name))
		}
	}
	return bodies
}

func TestGoAMD64FixedLocalConditionalCompleteSources(t *testing.T) {
	var source strings.Builder
	bodies := fixedLocalConditionalBodies()
	for index, body := range bodies {
		fn, sig, assembly := fixedLocalInputFixture(t, body)
		fmt.Fprint(&source, strings.Replace(assembly, "·Value", fmt.Sprintf("·Value%d", index), 1))
		t.Run(fmt.Sprint(index+1), func(t *testing.T) {
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("whole conditional value transport source rejected", err)
			}
		})
	}
	if len(bodies) != 48 {
		t.Fatal("complete condition/value inventory changed", len(bodies))
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
}

func TestGoAMD64FixedLocalConditionalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	bodies := fixedLocalConditionalBodies()
	for index, body := range bodies {
		_, _, source := fixedLocalInputFixture(t, body)
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(source, "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(p,q *uint64,a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(bodies))
}
