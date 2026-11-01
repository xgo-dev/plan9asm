package plan9asm

import (
	"reflect"
	"testing"
)

func TestX86TernaryGPRawOriginCannotSupplyInputsOrMemory(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"ANDNL", "ANDNQ", "PDEPL", "PDEPQ", "PEXTL", "PEXTQ"} {
			for _, first := range []string{"AX", "(AX)"} {
				file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+x86RawNumericalInstruction(t, arch, op+" "+first+",BX,CX")+"RET\n")
				if err != nil {
					t.Fatal(err)
				}
				file, err = normalizeX86RawFile(file, arch)
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				if !x86RawTernaryGPSource(ins, arch) {
					t.Fatal("complete original ternary source not recognized", arch, op, first)
				}
				for _, control := range []struct {
					name   string
					change func(*Instr)
				}{
					{"origin", func(i *Instr) { i.x86SourceRaw = nil }},
					{"opcode", func(i *Instr) { i.Op = "MOVL" }},
					{"operand", func(i *Instr) { i.Args[1].Reg = DX }},
					{"source-operand", func(i *Instr) { i.x86SourceRaw.args[1].Reg = DX }},
					{"vector", func(i *Instr) { i.x86VectorBytes = 16 }},
					{"address", func(i *Instr) { i.x86AddressBits = 16 }},
					{"override", func(i *Instr) { i.x86UnboundAddressOverride = true }},
					{"segment", func(i *Instr) { i.x86SegmentPrefix = 0x64 }},
					{"literal", func(i *Instr) { i.x86RIPLiteral = true }},
				} {
					t.Run(arch+"/"+op+"/"+first+"/"+control.name, func(t *testing.T) {
						changed := ins
						changed.Args = append([]Operand(nil), ins.Args...)
						origin := *ins.x86SourceRaw
						origin.args = append([]Operand(nil), origin.args...)
						changed.x86SourceRaw = &origin
						control.change(&changed)
						state := x86ResultState{flags: x86ByteFlagsAll}
						state.gp[0], state.gp[3] = 0xff, 0xff
						before := state.clone()
						accepted, _ := x86LoweredTernaryGPResultStep(changed, &state, nil, 0, arch)
						if accepted || x86RawTernaryGPSource(changed, arch) || !reflect.DeepEqual(before, state) {
							t.Fatal("changed raw source borrowed a numerical continuation", accepted)
						}
					})
				}
				if first == "(AX)" {
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.gp[0], state.gp[3] = 0xff, 0xff
					before := state.clone()
					if accepted, known := x86LoweredTernaryGPResultStep(ins, &state, nil, 0, arch); accepted || !known || !reflect.DeepEqual(before, state) {
						t.Fatal("numerical AX invented an incoming pointer", arch, op)
					}
				}
			}
		}
	}
}
