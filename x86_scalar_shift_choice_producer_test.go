package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86ScalarShiftArchitecturalChoiceProducerFacts(t *testing.T) {
	cf, pf, af, zf, sf, of := x86ByteFlagCF, x86ByteFlagPF, x86ByteFlagAF, x86ByteFlagZF, x86ByteFlagSF, x86ByteFlagOF
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			text                 string
			old, finite, choices uint8
			value                bool
		}{
			{"SHLW CL,BX,AX", x86ByteFlagsAll, 0, x86ByteFlagsAll, true},
			{"SHRW $17,BX,AX", 0, x86ByteFlagsAll, x86ByteFlagsAll, true},
			{"SHLW $16,BX,AX", 0, x86ByteFlagsAll, af | of, false},
			{"SHLW $0,BX,AX", x86ByteFlagsAll, 0, 0, false},
			{"SHLB CL,AH", x86ByteFlagsAll, 0, cf | af | of, false},
			{"SARB CL,AH", x86ByteFlagsAll, 0, af | of, false},
			{"SHLB $8,AH", 0, x86ByteFlagsAll, cf | af | of, false},
			{"SHLL $1,AX", 0, x86ByteFlagsAll, af, false},
			{"SHRL CL,AX", x86ByteFlagsAll, 0, af | of, false},
			{"ROLW CL,AX", x86ByteFlagsAll, 0, of, false},
			{"RORB $8,AX", pf | af | zf | sf, cf | of, of, false},
			{"ROLW $1,AX", pf | af | zf | sf, cf | of, 0, false},
			{"RCLB $9,AX", x86ByteFlagsAll, 0, 0, false},
			{"RCRW $17,AX", x86ByteFlagsAll, 0, 0, false},
			{"RCLB $10,AX", pf | af | zf | sf, cf | of, of, false},
			{"RCRL CL,AX", x86ByteFlagsAll, 0, of, false},
		} {
			t.Run(arch+"/"+row.text, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.text)
				form, known, err := x86ScalarShiftProperties(ins.Op, ins, arch)
				if !known || err != nil {
					t.Fatal("independent valid producer grammar", known, err)
				}
				outcome := form.outcome()
				if outcome.flagsFromOld != row.old || outcome.flagsFinite != row.finite ||
					outcome.flagsChoice != row.choices || outcome.valueChoice != row.value {
					t.Fatal("opcode/count-specific outcome differs from independent ISA directory", outcome, row)
				}
				for initial := uint8(0); initial <= x86ByteFlagsAll; initial++ {
					state := x86ResultState{flags: initial}
					for register := range state.gp {
						state.gp[register] = 0xff
					}
					before := state.clone()
					accepted, recognized := x86LoweredScalarShiftChoiceStep(ins, &state, nil, 0, arch)
					required := uint8(0)
					if strings.HasPrefix(row.text, "RCLB $10") || strings.HasPrefix(row.text, "RCRL CL") {
						required = cf
					}
					if !recognized || !accepted {
						t.Fatal("closed register transfer must preserve its existing unknown-result fallback", initial)
					}
					if initial&required == required {
						if state.flags != initial&row.old|row.finite {
							t.Fatal("conditional/unchanged FLAGS became invented facts", initial, state.flags)
						}
					} else if state.gp[0] == before.gp[0] {
						t.Fatal("missing carry input became a finite initialized numerical result")
					}
				}
			})
		}
	}
}

func TestX86ScalarShiftArchitecturalChoiceRawOriginBoundaries(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		rows := x86ShiftChoiceCases(arch)
		code := x86ShiftChoiceOriginalBytes(t, arch, rows)
		for index, row := range rows {
			if !row.flagsChoice {
				continue // BMI2 has its independent complete source-binding owner.
			}
			t.Run(arch+"/"+row.text, func(t *testing.T) {
				decoded, err := decodeX86RawDirectives(rawX86Function(code[index]), arch)
				if err != nil || len(decoded.Instrs) != 1 {
					t.Fatal("complete original Go instruction could not be decoded", err)
				}
				ins := decoded.Instrs[0]
				if !x86RawLegacyScalarShiftSource(ins, arch) {
					t.Fatal("complete original raw scalar input lost exact source identity")
				}
				for _, mutation := range []string{"origin", "opcode", "operand", "source-operand", "vector", "address", "override", "segment", "literal", "return", "reader"} {
					t.Run(mutation, func(t *testing.T) {
						changed := x86ShiftChoiceMutatedOrigin(ins, mutation)
						if x86RawLegacyScalarShiftSource(changed, arch) {
							t.Fatal("changed source retained its exact raw identity")
						}
						state := x86ResultState{flags: x86ByteFlagsAll}
						for register := range state.gp {
							state.gp[register] = 0xff
						}
						before := state.clone()
						accepted, _ := x86LoweredScalarShiftChoiceStep(changed, &state, nil, 0, arch)
						if mutation == "origin" {
							// x86Encoded relaxes physical operand grammar; it is not
							// a universal raw-origin bit. These legacy instructions
							// have exactly named metadata after dropping origin. The
							// complete immutable Func replay, tested independently,
							// must detect that edit; a standalone step cannot.
							named := Instr{Op: changed.Op, Args: append([]Operand(nil), changed.Args...), Raw: changed.Raw}
							if ins.x86Encoded || !reflect.DeepEqual(changed, named) || !x86ResultNamedPredicateInstruction(changed) {
								t.Fatal("origin deletion unexpectedly retained another physical restriction")
							}
							want := before.clone()
							wantAccepted, _ := x86LoweredScalarShiftChoiceStep(named, &want, nil, 0, arch)
							if accepted != wantAccepted || !reflect.DeepEqual(state, want) {
								t.Fatal("indistinguishable named instructions acquired different numerical contracts")
							}
							return
						}
						if accepted || !reflect.DeepEqual(state, before) {
							t.Fatal("foreign source role acquired finite scalar outcomes")
						}
					})
				}
			})
		}
	}
}

func x86ShiftChoiceMutatedOrigin(ins Instr, mutation string) Instr {
	changed := cloneX86ReplayInstrs([]Instr{ins})[0]
	switch mutation {
	case "origin":
		changed.x86SourceRaw = nil
	case "opcode":
		changed.x86SourceRaw.op = "UNKNOWN"
	case "operand":
		changed.Args[0] = Operand{Kind: OpReg, Reg: DX}
	case "source-operand":
		changed.x86SourceRaw.args[0] = Operand{Kind: OpReg, Reg: DX}
	case "vector":
		changed.x86VectorBytes = 16
	case "address":
		changed.x86AddressBits = 32
	case "override":
		changed.x86UnboundAddressOverride = true
	case "segment":
		changed.x86SegmentPrefix = 0x64
	case "literal":
		changed.x86RIPLiteral = true
	case "return":
		changed.x86RawNearReturn = new(x86RawNearReturnForm)
	case "reader":
		changed.x86NumericalRead = &x86NumericalReadCertificate{}
	}
	return changed
}

func TestX86ScalarShiftArchitecturalChoiceProducerIRGuards(t *testing.T) {
	for _, row := range []struct {
		text        string
		flag, value int
	}{
		{"SHLB CL,AH", 3, 0}, {"SARW CL,AX", 2, 0}, {"SHRL CL,AX", 2, 0},
		{"RORQ CL,AX", 1, 0}, {"RCLW CL,AX", 1, 0},
		{"SHLW CL,BX,AX", 6, 1}, {"SHRW $17,BX,AX", 6, 1},
		{"SHLQ CL,BX,AX", 2, 0}, {"SHLXQ CX,BX,AX", 0, 0},
	} {
		t.Run(row.text, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, row.text)
			ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
			ctx.goarch = "amd64"
			ctx.blocks = []amd64Block{{instrs: []Instr{ins}}}
			if _, err := ctx.lowerInstr(0, 0, ins, nil, nil); err != nil {
				t.Fatal("actual scalar producer emitter failed", err)
			}
			ir := output.String()
			if strings.Count(ir, "freeze i1 poison") != row.flag || strings.Count(ir, "freeze i16 poison") != row.value ||
				strings.Count(ir, " = freeze ") != row.flag+row.value {
				t.Fatal("producer froze an input/old high byte, or lost a distinct output choice", fmt.Sprint(row), ir)
			}
			for _, line := range strings.Split(ir, "\n") {
				if strings.Contains(line, " = freeze ") && !strings.HasSuffix(line, " poison") {
					t.Fatal("an unavailable source value was frozen", line)
				}
			}
		})
	}
}

func TestX86ScalarShiftArchitecturalChoiceEveryInputByteBeforeAlias(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []struct {
			text       string
			inputs     [16]uint8
			result     int
			resultMask uint8
		}{
			{"SHLW CL,BX,AX", [16]uint8{0: 3, 1: 1, 3: 3}, 0, 3},
			{"SHRW CX,AX,AX", [16]uint8{0: 3, 1: 1}, 0, 3},
			{"SHLW CL,CX,CX", [16]uint8{1: 3}, 1, 3},
			{"SHLW $17,BX,AX", [16]uint8{0: 3, 3: 3}, 0, 3},
			{"SHLW $0,BX,AX", [16]uint8{0: 3}, 0, 3},
			{"SHLB CL,AH", [16]uint8{0: 2, 1: 1}, 0, 2},
			{"RCLW CL,AX", [16]uint8{0: 3, 1: 1}, 0, 3},
			{"SHRL CX,AX", [16]uint8{0: 15, 1: 1}, 0, 255},
		} {
			t.Run(arch+"/"+row.text, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.text)
				for register := 0; register < 16; register++ {
					for missing := uint(0); missing < 8; missing++ {
						state := x86ResultState{gp: row.inputs, flags: x86ByteFlagsAll}
						state.gp[register] &^= 1 << missing
						before := state.clone()
						accepted, known := x86LoweredScalarShiftChoiceStep(ins, &state, nil, 0, arch)
						valid := row.inputs[register]&(1<<missing) == 0
						if !known || valid && (!accepted || state.gp[row.result]&row.resultMask != row.resultMask) ||
							!valid && accepted && state.gp[row.result]&row.resultMask == row.resultMask ||
							!accepted && !reflect.DeepEqual(before, state) {
							t.Fatal("paired choice supplied a missing aliased byte or mutated a rejected state", register, missing, accepted)
						}
						if valid && row.resultMask != 255 && state.gp[row.result]&^row.resultMask != before.gp[row.result]&^row.resultMask {
							t.Fatal("partial output choice invented unwritten high bytes")
						}
					}
				}
			})
		}
	}
}
