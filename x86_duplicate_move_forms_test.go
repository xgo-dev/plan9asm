package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86DuplicateMoveEverySelectedByteAndIndependentState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86DuplicateMoveOracle {
			for _, bank := range []string{"X", "Y", "Z"} {
				if !row.vector && bank != "X" {
					continue
				}
				for _, masking := range []string{"plain", "merge", "zero"} {
					if !row.vector && masking != "plain" {
						continue
					}
					t.Run(arch+"/"+row.name+"/"+bank+"/"+masking, func(t *testing.T) {
						op, mask := row.name, ""
						if masking != "plain" {
							mask = "K3,"
						}
						if masking == "zero" {
							op += ".Z"
						}
						ins := x86YMMReadSource(t, fmt.Sprintf("%s %s0,%s%s2", op, bank, mask, bank))
						width := map[string]int{"X": 16, "Y": 32, "Z": 64}[bank]
						var required uint64
						for offset := 0; offset < width; offset++ {
							lane := offset / row.bytes
							if lane%2 == 0 != row.odd {
								required |= uint64(1) << uint(offset)
							}
						}
						state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward,
							fp: []bool{true, false}, auto: []bool{false, true}}
						state.xmm[0], state.vectorUpper[0] = uint16(required), required&^0xffff
						state.xmm[2], state.vectorUpper[2] = 0xffff, 0xa55aa55aa55a0000
						if masking == "merge" {
							state.vectorUpper[2] = ^uint64(0xffff)
						}
						state.masks[3], state.pointerGP[6], state.callerAddressGP[6] = true, true, true
						state.gp[4], state.canonicalGP[4] = 0x81, 0xa5
						before, expected := state.clone(), state.clone()
						expected.xmm[2] = 0xffff
						if row.vector {
							expected.vectorUpper[2] = ^uint64(0xffff)
						}
						if !x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, expected) {
							t.Fatal("selected bytes did not close, or GP/status/DF/storage/aliases changed")
						}
						for missing := 0; missing < width; missing++ {
							if required>>uint(missing)&1 == 0 {
								continue // These source bytes were deliberately unknown in the positive.
							}
							current := before.clone()
							if missing < 16 {
								current.xmm[0] &^= 1 << uint(missing)
							} else {
								current.vectorUpper[0] &^= uint64(1) << uint(missing)
							}
							initial := current.clone()
							if accepted, known := x86ResultDuplicateMoveStep(ins, &current, nil, arch, false); !known || accepted || !reflect.DeepEqual(current, initial) {
								t.Fatal("unknown selected byte acquired NUM or partially changed a failed state", missing)
							}
						}
						if got := x86ResultCallerAddressesAfter(ins, before.callerAddressGP, nil, arch); got != before.callerAddressGP {
							t.Fatal("vector-only output lost or invented a GP address")
						}
						if got := x86RegisterCanonicalBytesAfter(ins, before.canonicalGP, arch); got != before.canonicalGP {
							t.Fatal("vector-only output changed independent bool canonicality")
						}
					})
				}
			}
		}
	}
}

func TestX86DuplicateMoveGrammarRejectsBeforeAnyIR(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86DuplicateMoveOracle {
			original := x86YMMReadSource(t, row.name+" X0,X2")
			for _, control := range []struct {
				name string
				edit func(*Instr)
			}{
				{"dispatch", func(ins *Instr) { ins.Op = "MOVL" }},
				{"suffix", func(ins *Instr) { ins.Op += ".BCST" }},
				{"missing", func(ins *Instr) { ins.Args = nil }},
				{"immediate", func(ins *Instr) { ins.Args[0] = Operand{Kind: OpImm, Imm: 0} }},
				{"gp-source", func(ins *Instr) { ins.Args[0] = Operand{Kind: OpReg, Reg: AX} }},
				{"gp-output", func(ins *Instr) { ins.Args[1] = Operand{Kind: OpReg, Reg: AX} }},
				{"memory-output", func(ins *Instr) { ins.Args[1] = Operand{Kind: OpMem, Mem: MemRef{Base: AX}} }},
				{"width", func(ins *Instr) { ins.Args[0] = Operand{Kind: OpReg, Reg: "Y0"} }},
				{"mask-zero", func(ins *Instr) { ins.Args = []Operand{ins.Args[0], {Kind: OpReg, Reg: "K0"}, ins.Args[1]} }},
				{"scale", func(ins *Instr) { ins.Args[0] = Operand{Kind: OpMem, Mem: MemRef{Base: AX, Index: CX, Scale: 3}} }},
			} {
				t.Run(arch+"/"+row.name+"/"+control.name, func(t *testing.T) {
					ins := original
					ins.Args = append([]Operand(nil), original.Args...)
					control.edit(&ins)
					var output strings.Builder
					ctx := &amd64Ctx{b: &output, goarch: arch}
					if known, terminated, err := ctx.lowerDuplicateMove(Op(row.name), ins); !known || terminated || err == nil || output.Len() != 0 || ctx.tmp != 0 {
						t.Fatal("malformed grammar emitted or read a source before rejection", err, output.String())
					}
				})
			}
		}
	}
}
