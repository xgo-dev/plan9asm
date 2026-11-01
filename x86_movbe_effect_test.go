package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86MOVBEOrderedInputBytesAndPreservedFlags(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"MOVBEW", "MOVBEWW", "MOVBEL", "MOVBELL", "MOVBEQ", "MOVBEQQ"} {
			width := int64(x86MOVBEWidths[Op(op)] / 8)
			if arch == "386" && width == 8 {
				continue // Both Q spellings have independent Go rejection controls.
			}
			for _, store := range []bool{false, true} {
				line := op + " input+0(FP),BX"
				if store {
					line = op + " BX,result+8(FP)"
				}
				ins := x86YMMReadSource(t, line)
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || len(effect.operands) != 2 || !effect.requiresResultProof ||
					effect.flagsRead != 0 || effect.flagsDefined != 0 || effect.flagsKilled != 0 {
					t.Fatal("complete MOVBE directions lack their status-preserving effect", arch, op, known, err)
				}
				for index, operand := range effect.operands {
					if operand.index != index || operand.width != width || operand.read != (index == 0) ||
						operand.write != (index == 1) || !reflect.DeepEqual(operand.operand, ins.Args[index]) {
						t.Fatal("MOVBE ordered width or read/write effect differs", operand)
					}
				}
				for missing := -1; missing < int(width); missing++ {
					t.Run(fmt.Sprintf("%s/%s/store=%t/missing=%d", arch, op, store, missing), func(t *testing.T) {
						owned := make([]bool, 16)
						state := x86ResultState{fp: make([]bool, 16), flags: x86ByteFlagsAll}
						for index := range owned {
							owned[index] = true
							state.fp[index] = index < 8
						}
						state.gp[3] = 0xa0 // W preserves unknown old bytes; L zero-extends them.
						if store {
							state.gp[3] = 0xff
						}
						if missing >= 0 {
							if store {
								state.gp[3] &^= 1 << uint(missing)
							} else {
								state.fp[missing] = false
							}
						}
						before := state.clone()
						accepted := x86ResultTransfer(ins, &state, owned, 8, arch)
						if accepted != (missing < 0) {
							t.Fatal("MOVBE overwrite hid an unknown input byte", accepted)
						}
						if accepted {
							if store {
								for index := int64(8); index < 8+width; index++ {
									before.fp[index] = true
								}
							} else if width == 2 {
								before.gp[3] |= 3
							} else {
								before.gp[3] = 0xff
							}
						}
						if !reflect.DeepEqual(before, state) {
							t.Fatal("MOVBE changed FLAGS, unrelated storage or rejected state")
						}
					})
				}
			}
		}
	}
}

func TestX86MOVBERawIdentityCannotSupplyPointerOrNumericalBytes(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"MOVBEW", "MOVBEL", "MOVBEQ"} {
			if arch == "386" && op == "MOVBEQ" {
				continue
			}
			for _, operands := range []string{"(AX),BX", "BX,(AX)"} {
				file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+
					x86RawNumericalInstruction(t, arch, op+" "+operands)+"RET\n")
				if err != nil {
					t.Fatal(err)
				}
				file, err = normalizeX86RawFile(file, arch)
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				if !x86RawMOVBESource(ins, arch) {
					t.Fatal("complete original raw MOVBE source not recognized", arch, op, operands)
				}
				for _, control := range []struct {
					name   string
					change func(*Instr)
				}{
					{"origin", func(i *Instr) { i.x86SourceRaw = nil }},
					{"opcode", func(i *Instr) { i.Op = "MOVL" }},
					{"operand", func(i *Instr) { i.Args[0] = Operand{Kind: OpImm, Imm: 1} }},
					{"source-opcode", func(i *Instr) { i.x86SourceRaw.op = "MOVL" }},
					{"source-operand", func(i *Instr) { i.x86SourceRaw.args[0].Reg = DX }},
					{"vector", func(i *Instr) { i.x86VectorBytes = 16 }},
					{"address", func(i *Instr) { i.x86AddressBits = 16 }},
					{"override", func(i *Instr) { i.x86UnboundAddressOverride = true }},
					{"segment", func(i *Instr) { i.x86SegmentPrefix = 0x64 }},
					{"literal", func(i *Instr) { i.x86RIPLiteral = true }},
				} {
					t.Run(arch+"/"+op+"/"+operands+"/"+control.name, func(t *testing.T) {
						changed := ins
						changed.Args = append([]Operand(nil), ins.Args...)
						origin := *ins.x86SourceRaw
						origin.args = append([]Operand(nil), origin.args...)
						changed.x86SourceRaw = &origin
						control.change(&changed)
						state := x86ResultState{flags: x86ByteFlagsAll}
						state.pointerGP[0], state.gp[3] = true, 0xff
						if control.name == "origin" {
							// With every physical marker absent this is ordinary
							// named source, not a malformed encoded instruction.
							// Numerical AX still cannot invent a native pointer.
							state.pointerGP[0], state.gp[0] = false, 0xff
						}
						before := state.clone()
						accepted, _ := x86LoweredMOVBEResultStep(changed, &state, nil, 0, arch)
						if accepted || x86RawMOVBESource(changed, arch) || !reflect.DeepEqual(before, state) {
							t.Fatal("changed raw source borrowed a MOVBE continuation", accepted)
						}
					})
				}
				for _, pointer := range []bool{false, true} {
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.gp[0], state.pointerGP[0] = 0xff, pointer
					// A store must consume BX numerically, not just an opaque pointer.
					if strings.HasPrefix(operands, "BX") {
						state.pointerGP[3] = true
					}
					before := state.clone()
					accepted, known := x86LoweredMOVBEResultStep(ins, &state, nil, 0, arch)
					want := pointer && !strings.HasPrefix(operands, "BX")
					if accepted != want || !known || !accepted && !reflect.DeepEqual(before, state) {
						t.Fatal("numerical address or opaque store input gained memory/data authority", pointer, operands, accepted)
					}
				}
			}
		}
	}
}
