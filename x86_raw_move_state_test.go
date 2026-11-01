package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86RawMoveObservedInstruction(t *testing.T, arch string, code []byte) Instr {
	t.Helper()
	var source strings.Builder
	source.WriteString("TEXT ·Move(SB),4,$0-0\n")
	for _, value := range code {
		fmt.Fprintf(&source, "BYTE $%d\n", value)
	}
	source.WriteString("RET\n")
	file, err := Parse(ArchAMD64, source.String())
	if err == nil {
		file, err = normalizeX86RawFile(file, arch)
	}
	if err != nil || len(file.Funcs[0].Instrs) != 3 {
		t.Fatal("actual raw move lost its single original instruction", err)
	}
	return file.Funcs[0].Instrs[1]
}

func x86RawMoveInitializedState() x86ResultState {
	state := x86ResultState{
		flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward,
		fp: []bool{true, false}, auto: []bool{false, true},
	}
	for index := range state.gp {
		state.gp[index], state.canonicalGP[index] = 0xff, 0xa5
	}
	state.pointerGP[3], state.pointerGP[7] = true, true
	state.callerAddressGP[3], state.callerAddressGP[7] = true, true
	for index := range state.masks {
		state.masks[index] = true
	}
	for index := 0; index < 3; index++ {
		state.xmm[index], state.vectorUpper[index] = 0xffff, ^uint64(0xffff)
	}
	return state
}

func TestX86RawMoveEveryByteAndIndependentState(t *testing.T) {
	rows := x86RawMoveOriginCases()
	for _, arch := range []string{"amd64", "386"} {
		code := x86RawMoveOriginGoBytes(t, arch, rows)
		for index, row := range rows {
			t.Run(arch+"/"+row.row, func(t *testing.T) {
				ins := x86RawMoveObservedInstruction(t, arch, code[index])
				width := map[string]int{"X": 16, "Y": 32, "Z": 64}[row.bank]
				if row.scalar {
					width = 4
					if strings.HasPrefix(row.row, "VMOVSD") {
						width = 8
					}
				}
				for source := 0; source < 3; source++ {
					for missing := -1; missing < 64; missing++ {
						state := x86RawMoveInitializedState()
						if missing >= 0 {
							if missing < 16 {
								state.xmm[source] &^= uint16(1) << uint(missing)
							} else {
								state.vectorUpper[source] &^= uint64(1) << uint(missing)
							}
						}
						before, expected := state.clone(), state.clone()
						accepted := true
						known := ^uint64(0)
						if row.role == "store" {
							accepted = source != 2 || missing < 0 || missing >= width
						} else if row.scalar {
							if row.role == "register" && source == 0 && missing >= 0 && missing < width ||
								row.masking == "merge" && source == 2 && missing >= 0 && missing < width {
								accepted = false
							}
							if row.role == "register" && source == 1 && missing >= width && missing < 16 {
								known &^= uint64(1) << uint(missing)
							}
						} else if missing >= 0 && missing < width &&
							(row.role == "register" && source == 0 || row.masking == "merge" && source == 2) {
							known &^= uint64(1) << uint(missing)
						}
						if accepted && row.role != "store" {
							expected.xmm[2], expected.vectorUpper[2] = uint16(known), known&^0xffff
						}
						got, recognized := x86LoweredRawVectorMoveStep(ins, &state, nil, 0, arch)
						if !recognized || got != accepted ||
							accepted && !reflect.DeepEqual(state, expected) || !accepted && !reflect.DeepEqual(state, before) {
							t.Fatal("raw move invented a byte, changed independent state or partially committed a rejection", source, missing, got, accepted)
						}
					}
				}
				for _, control := range []string{"mask", "address"} {
					if control == "mask" && row.masking == "plain" || control == "address" && row.role == "register" {
						continue
					}
					state := x86RawMoveInitializedState()
					if control == "mask" {
						state.masks[1] = false
					} else if row.role == "load" {
						state.pointerGP[3] = false
					} else {
						state.pointerGP[7] = false
					}
					before := state.clone()
					if accepted, recognized := x86LoweredRawVectorMoveStep(ins, &state, nil, 0, arch); !recognized || accepted || !reflect.DeepEqual(state, before) {
						t.Fatal("raw move borrowed an unknown mask/numerical address or partially changed state", control)
					}
				}
			})
		}
	}
}

func TestX86RawMoveEditedOriginRejectsAtomically(t *testing.T) {
	rows := x86RawMoveOriginCases()
	for _, arch := range []string{"amd64", "386"} {
		code := x86RawMoveOriginGoBytes(t, arch, rows)
		for index, row := range rows {
			t.Run(arch+"/"+row.row, func(t *testing.T) {
				original := x86RawMoveObservedInstruction(t, arch, code[index])
				for _, control := range []struct {
					name string
					edit func(*Instr)
				}{
					{"origin", func(ins *Instr) { ins.x86SourceRaw = nil }},
					{"opcode", func(ins *Instr) {
						name, suffix, dotted := strings.Cut(string(ins.Op), ".")
						if row.scalar {
							name = map[string]string{"VMOVSS": "VMOVSD", "VMOVSD": "VMOVSS"}[name]
						} else if name == "VMOVDQA" || name == "VMOVDQU" {
							name = map[string]string{"VMOVDQA": "VMOVDQU", "VMOVDQU": "VMOVDQA"}[name]
						} else if name == "VMOVUPS" {
							name = "VMOVUPD"
						} else {
							name = "VMOVUPS"
						}
						if dotted {
							name += "." + suffix
						}
						ins.Op = Op(name)
					}},
					{"operand", func(ins *Instr) {
						last := &ins.Args[len(ins.Args)-1]
						if last.Kind == OpMem {
							last.Mem.Off++
						} else {
							last.Reg = Reg(row.bank + "3")
						}
					}},
					{"source opcode", func(ins *Instr) { ins.x86SourceRaw.op = "MOVL" }},
					{"source operand", func(ins *Instr) { ins.x86SourceRaw.args[0] = Operand{Kind: OpReg, Reg: "X4"} }},
					{"vector width", func(ins *Instr) { ins.x86VectorBytes += 16 }},
					{"source width", func(ins *Instr) { ins.x86SourceRaw.vectorBytes += 16 }},
					{"address width", func(ins *Instr) { ins.x86AddressBits = 16 }},
					{"address override", func(ins *Instr) { ins.x86UnboundAddressOverride = true }},
					{"segment", func(ins *Instr) { ins.x86SegmentPrefix = 0x64 }},
					{"literal", func(ins *Instr) { ins.x86RIPLiteral = true }},
					{"raw return", func(ins *Instr) { ins.x86RawNearReturn = new(x86RawNearReturnForm) }},
				} {
					changed := cloneX86ReplayInstrs([]Instr{original})[0]
					control.edit(&changed)
					state := x86RawMoveInitializedState()
					before := state.clone()
					if accepted, _ := x86LoweredRawVectorMoveStep(changed, &state, nil, 0, arch); accepted || x86RawVectorMoveSource(changed, arch) || !reflect.DeepEqual(state, before) {
						t.Fatal("edited original move borrowed a paired continuation or changed state", control.name)
					}
				}
			})
		}
	}
}
