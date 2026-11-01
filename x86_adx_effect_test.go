package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86ADXSelectedCarryAndEveryInputByte(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"ADCXL", "ADCXQ", "ADOXL", "ADOXQ"} {
			if arch == "386" && strings.HasSuffix(op, "Q") {
				continue
			}
			width, flag := 4, uint8(x86ByteFlagCF)
			if strings.HasSuffix(op, "Q") {
				width = 8
			}
			if strings.HasPrefix(op, "ADOX") {
				flag = x86ByteFlagOF
			}
			ins := x86YMMReadSource(t, op+" AX,BX")
			effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
			if !known || err != nil || !effect.requiresResultProof || effect.flagsRead != flag || effect.flagsDefined != flag || effect.flagsKilled != flag {
				t.Fatal("complete typed carry obligation differs", op, known, err)
			}
			for _, flags := range []uint8{0, x86ByteFlagCF, x86ByteFlagOF, x86ByteFlagCF | x86ByteFlagOF} {
				for missing := -1; missing < width*2; missing++ {
					t.Run(fmt.Sprintf("%s/%s/flags=%d/missing=%d", arch, op, flags, missing), func(t *testing.T) {
						state := x86ResultState{flags: flags}
						state.gp[0], state.gp[3] = uint8((1<<uint(width))-1), uint8((1<<uint(width))-1)
						if missing >= 0 {
							index := 0
							if missing >= width {
								index = 3
							}
							state.gp[index] &^= 1 << uint(missing%width)
						}
						before := state.clone()
						accepted := x86ResultTransfer(ins, &state, nil, 0, arch)
						want := missing < 0 && flags&flag != 0
						if accepted != want || !accepted && !reflect.DeepEqual(before, state) {
							t.Fatal("ADX borrowed wrong carry/missing byte or changed rejected state", accepted, want)
						}
						if accepted {
							before.gp[3] = 0xff
							if !reflect.DeepEqual(before, state) {
								t.Fatal("ADX changed unrelated state or failed dword zero extension")
							}
						}
					})
				}
			}
		}
	}
}

func TestX86ADXVoidAndUnusedBoolRequireSelectedCarry(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range []string{"ADCXL", "ADCXQ", "ADOXL", "ADOXQ"} {
			if target.arch == "386" && strings.HasSuffix(op, "Q") {
				continue
			}
			for _, unusedBool := range []bool{false, true} {
				for _, seed := range []string{"CF", "OF"} {
					t.Run(fmt.Sprintf("%s/%s/bool=%t/seed=%s", target.triple, op, unusedBool, seed), func(t *testing.T) {
						extent, declaration := 0, "func Value()"
						if unusedBool {
							extent, declaration = 1, "func Value(unused bool)"
						}
						flags := "CLC\n"
						if seed == "OF" {
							flags = "MOVL $0x7fffffff,DX\nINCL DX\n"
						}
						source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\nMOVL $7,AX\nMOVL $3,BX\n%s%s AX,BX\nRET\n", extent, flags, op)
						valid := (seed == "OF") == strings.HasPrefix(op, "ADOX")
						for _, api := range []string{"text", "module", "Go"} {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
							if valid {
								if err != nil || ir == "" {
									t.Fatal("initialized selected carry rejected", api, err)
								}
							} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("unused result/bool borrowed the other carry chain", api, err)
							}
						}
					})
				}
			}
		}
	}
}

func TestX86ADXRawDefaultModeAndOriginCannotBeRebound(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"ADCXL", "ADCXQ", "ADOXL", "ADOXQ"} {
			if arch == "386" && strings.HasSuffix(op, "Q") {
				continue
			}
			file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+x86RawNumericalInstruction(t, arch, op+" AX,BX")+"RET\n")
			if err != nil {
				t.Fatal(err)
			}
			file, err = normalizeX86RawFile(file, arch)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			if !x86RawADXSource(ins, arch) || ins.x86SourceRaw.addressBits != goWordSize(arch)*8 {
				t.Fatal("raw ADX lost its exact original default address mode", arch, op)
			}
			for _, control := range []struct {
				name   string
				change func(*Instr)
			}{
				{"origin", func(ins *Instr) { ins.x86SourceRaw = nil }},
				{"opcode", func(ins *Instr) {
					ins.Op = "ADCXL"
					if ins.x86SourceRaw.op == "ADCXL" {
						ins.Op = "ADOXL"
					}
				}},
				{"operand", func(ins *Instr) { ins.Args[0].Reg = DX }},
				{"source-operand", func(ins *Instr) { ins.x86SourceRaw.args[0].Reg = DX }},
				{"address", func(ins *Instr) { ins.x86AddressBits /= 2 }},
				{"source-address", func(ins *Instr) { ins.x86SourceRaw.addressBits /= 2 }},
				{"missing-address", func(ins *Instr) { ins.x86AddressBits = 0 }},
				{"override", func(ins *Instr) { ins.x86UnboundAddressOverride = true }},
				{"segment", func(ins *Instr) { ins.x86SegmentPrefix = 0x64 }},
				{"literal", func(ins *Instr) { ins.x86RIPLiteral = true }},
			} {
				t.Run(arch+"/"+op+"/"+control.name, func(t *testing.T) {
					changed := ins
					changed.Args = append([]Operand(nil), ins.Args...)
					origin := *ins.x86SourceRaw
					origin.args = append([]Operand(nil), origin.args...)
					changed.x86SourceRaw = &origin
					control.change(&changed)
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.gp[0], state.gp[3] = 0xff, 0xff
					before := state.clone()
					accepted, known := x86LoweredADXResultStep(changed, &state, nil, 0, arch)
					if accepted || !known || x86RawADXSource(changed, arch) || !reflect.DeepEqual(before, state) {
						t.Fatal("changed ADX origin/mode borrowed a numerical continuation", accepted, known)
					}
				})
			}
		}
	}
}
