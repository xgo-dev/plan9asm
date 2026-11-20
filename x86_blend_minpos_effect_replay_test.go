package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86BlendMinposCanonicalRows() []x86BlendMinposCase {
	var result []x86BlendMinposCase
	for _, row := range x86BlendMinposCases() {
		if row.minimum {
			if row.operand == "X0" {
				continue
			}
		} else if row.legacy && row.dst != 2 || !row.legacy && row.dst != 3 {
			continue
		}
		result = append(result, row)
	}
	return result
}

func TestX86BlendMinposTypedEveryByteMaskAndAliases(t *testing.T) {
	for _, row := range x86BlendMinposCanonicalRows() {
		if row.operand == "(BX)" {
			continue
		}
		width, destination := row.width, row.dst
		if row.legacy || row.minimum {
			width = 16
		}
		for role := 0; role < 4; role++ {
			t.Run(fmt.Sprintf("%s/%s/role%d", row.op, row.bank, role), func(t *testing.T) {
				for missing := -1; missing < 64; missing++ {
					state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward, masks: [8]bool{1: true}}
					for register := 0; register < 4; register++ {
						state.writeVector(register, 64, ^uint64(0), false)
					}
					if missing >= 0 {
						state.writeVector(role, 64, ^(uint64(1) << uint(missing)), false)
					}
					before := state.clone()
					instruction := x86ScalarLaneInstruction(t, row.instruction())
					if !x86ScalarFPResultTransfer(instruction, &state, nil, 0, "amd64") {
						t.Fatal("complete named typed blend/minimum effect is missing", instruction.Raw)
					}
					want := before.vectorBytes(destination)
					if !row.legacy {
						want = ^uint64(0)
					}
					active := x86CallerVectorByteMask(int64(width))
					want &^= active
					if row.minimum {
						want |= 0xfff8 // bits 127:19 are zero, including byte 3.
						if before.vectorBytes(1)&0xffff == 0xffff {
							want |= 7
						}
					} else {
						base := 2
						for at := 0; at < width; at++ {
							maskByte := (at/(row.bits/8)+1)*(row.bits/8) - 1
							known := before.vectorBytes(0)&(uint64(1)<<uint(maskByte)) != 0 &&
								before.vectorBytes(1)&(uint64(1)<<uint(at)) != 0 && before.vectorBytes(base)&(uint64(1)<<uint(at)) != 0
							if known {
								want |= uint64(1) << uint(at)
							}
						}
					}
					if got := state.vectorBytes(destination); got != want {
						t.Fatalf("%s role%d byte%d: known=%016x want=%016x", row.instruction(), role, missing, got, want)
					}
					for register := 0; register < 4; register++ {
						if register != destination && state.vectorBytes(register) != before.vectorBytes(register) {
							t.Fatal("typed blend/minimum wrote a nondestination alias")
						}
					}
					if state.flags != before.flags || state.direction != before.direction ||
						state.gp != before.gp || state.pointerGP != before.pointerGP || state.callerAddressGP != before.callerAddressGP || state.masks != before.masks {
						t.Fatal("typed blend/minimum altered unrelated FLAGS, DF, GP, pointer or K state")
					}
				}
			})
		}
	}
}

func x86BlendMinposReplayProgram(row x86BlendMinposCase, code []byte, arch string, raw, memory bool) (string, string) {
	word, move, suffix := goWordSize(arch), "MOVQ", "Q"
	if arch == "386" {
		move, suffix = "MOVL", "L"
	}
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·Value(SB),4,$0-%d\n%s out+0(FP),DI\n%s input+%d(FP),BX\n", 2*word, move, move, word)
	for register := 0; register < 4; register++ {
		fmt.Fprintf(&source, "VPXORQ Z%d,Z%d,Z%d\n", register, register, register)
	}
	if memory {
		// The opcode retains its original full native source read; this is
		// not a preloaded numerical replacement for its faulting access.
		row.operand = "(BX)"
	}
	source.WriteString("MOVL $3,CX\nCMPL CX,$3\nSTD\n")
	if raw {
		source.WriteString(x86RawDisplacementDirectives(code))
	} else {
		source.WriteString(row.instruction() + "\n")
	}
	fmt.Fprintf(&source, "VMOVUPS Z%d,(DI)\nPUSHF%s\nPOP%s CX\nANDL $0xcd5,CX\nMOVL CX,112(DI)\nCLD\nRET\n", row.dst, suffix, suffix)
	return source.String(), "func Value(out *[128]byte,input *[32]byte)\n"
}

func TestX86BlendMinposWholeProducerReplayKeepsOriginalIdentity(t *testing.T) {
	rows := x86BlendMinposCanonicalRows()
	codes := x86BlendMinposOriginalCodes(t, rows)
	for _, arch := range []string{"386", "amd64"} {
		var prior strings.Builder
		for index, row := range rows {
			for _, raw := range []bool{false, true} {
				if arch == "386" && !raw && !row.legacy && !row.minimum {
					continue
				}
				source, _ := x86BlendMinposReplayProgram(row, codes[index], arch, raw, row.operand == "(BX)")
				prior.WriteString(strings.Replace(source, "·Value(SB)", fmt.Sprintf("·Prior%d_%t(SB)", index, raw), 1))
			}
		}
		x86LEAActualTargetGoObject(t, arch, x86AddressMemoryTargets(arch)[0], prior.String())
		for index, row := range rows {
			source, declaration := x86BlendMinposReplayProgram(row, codes[index], arch, true, row.operand == "(BX)")
			check := x86LegacyFloatReplayCheck(t, arch, source, declaration)
			if arch == "amd64" || row.legacy || row.minimum {
				t.Run(arch+"/"+row.instruction()+"/named", func(t *testing.T) {
					named, _ := x86BlendMinposReplayProgram(row, codes[index], arch, false, row.operand == "(BX)")
					if err := check(mustParseX86RawReturn(t, named).Funcs[0]); err != nil {
						t.Fatal("the independently initialized legal named producer must succeed", err)
					}
				})
			}
			for _, mutation := range []string{"valid", "origin", "replay", "source-spelling", "producer", "snapshot", "operand", "header"} {
				t.Run(arch+"/"+row.instruction()+"/"+mutation, func(t *testing.T) {
					file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
					if err != nil || len(file.Funcs) != 1 {
						t.Fatal("actual original whole raw producer prerequisite", err)
					}
					original := file.Funcs[0]
					if original.x86RawReplay == nil || original.x86RawReplay.validate(original, arch) != nil {
						t.Fatal("the original raw source lost its independent complete replay")
					}
					candidate := original
					candidate.Instrs = cloneX86ReplayInstrs(original.Instrs)
					ordinal := -1
					for at, instruction := range candidate.Instrs {
						if instruction.x86SourceRaw != nil && string(instruction.Op) == row.op {
							if ordinal >= 0 {
								t.Fatal("ambiguous original blend/minimum row")
							}
							ordinal = at
						}
					}
					if ordinal < 0 {
						t.Fatal("original Go bytes lost their decoded target instruction")
					}
					switch mutation {
					case "origin":
						candidate.Instrs[ordinal].x86SourceRaw = nil
					case "replay":
						candidate.x86RawReplay = nil
					case "source-spelling":
						candidate.Instrs[ordinal].Raw += " changed"
					case "producer":
						candidate.Instrs[1].Raw += " changed"
					case "snapshot":
						replay := *original.x86RawReplay
						replay.normalized = cloneX86ReplayInstrs(replay.normalized)
						replay.normalized[ordinal].Op = "NOP"
						candidate.x86RawReplay = &replay
					case "operand":
						candidate.Instrs[ordinal].Args[len(candidate.Instrs[ordinal].Args)-1].Reg = "X7"
					case "header":
						candidate.ArgSize++
					}
					err = check(candidate)
					if mutation == "valid" {
						if err != nil {
							t.Fatal("complete initialized original raw producer must succeed", err)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("edited source/origin/whole producer acquired a numerical continuation", err)
					}
					if original.x86RawReplay.validate(original, arch) != nil {
						t.Fatal("mutating a candidate corrupted the original source seal")
					}
				})
			}
		}
	}
}

func TestX86BlendMinposStandaloneNativeMemoryRemainsUnproved(t *testing.T) {
	for _, row := range x86BlendMinposCanonicalRows() {
		if row.operand != "(BX)" {
			continue
		}
		for _, arch := range []string{"386", "amd64"} {
			state := x86ResultState{flags: x86ByteFlagsAll}
			for register := 0; register < 4; register++ {
				state.writeVector(register, 64, ^uint64(0), false)
			}
			state.pointerGP[3], state.callerAddressGP[3] = true, true
			before := state.clone()
			instruction := x86ScalarLaneInstruction(t, row.instruction())
			if x86ScalarFPResultTransfer(instruction, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
				t.Fatal("declaration-only native blend/minimum read acquired backing or mutated rejection", arch, row.instruction())
			}
		}
	}
}

func TestX86BlendMinposDeadMemoryRetainsOriginalObservableRead(t *testing.T) {
	rows := x86BlendMinposCanonicalRows()
	codes := x86BlendMinposOriginalCodes(t, rows)
	for index, row := range rows {
		if row.operand != "(BX)" {
			continue
		}
		for _, arch := range []string{"386", "amd64"} {
			word, move, triple := goWordSize(arch), "MOVQ", "x86_64-unknown-linux-gnu"
			if arch == "386" {
				move, triple = "MOVL", "i386-unknown-linux-gnu"
			}
			for _, raw := range []bool{false, true} {
				if arch == "386" && !raw && !row.legacy && !row.minimum {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/%s/raw=%t", arch, row.op, row.bank, raw), func(t *testing.T) {
					var source strings.Builder
					fmt.Fprintf(&source, "TEXT ·Value(SB),4,$0-%d\n%s input+0(FP),BX\n", word, move)
					zero := "PXOR"
					if !row.legacy {
						zero = "VXORPS"
					}
					for register := 0; register < 4; register++ {
						if row.legacy {
							fmt.Fprintf(&source, "%s X%d,X%d\n", zero, register, register)
						} else {
							fmt.Fprintf(&source, "%s %s%d,%s%d,%s%d\n", zero, row.bank, register, row.bank, register, row.bank, register)
						}
					}
					if raw {
						source.WriteString(x86RawDisplacementDirectives(codes[index]))
					} else {
						source.WriteString(row.instruction() + "\n")
					}
					source.WriteString("RET\n")
					x86LEAActualTargetGoObject(t, arch, triple, source.String())
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source.String(), "func Value(input *[32]byte)", arch, triple, api)
						if err != nil {
							t.Fatal("dead output/zero mask did not erase the actual source-read obligation", api, err)
						}
						if row.legacy {
							if !strings.Contains(ir, "asm sideeffect") || !strings.Contains(ir, strings.ToLower(row.op)+" ") || !strings.Contains(ir, "~{memory}") {
								t.Fatal("legacy m128 must retain its actual opcode and alignment/fault behavior", api)
							}
						} else if !strings.Contains(ir, fmt.Sprintf("load volatile <%d x i8>", row.width)) &&
							!strings.Contains(ir, strings.ToLower(row.op)+" ") {
							t.Fatal("VEX full tuple read was removed for a dead zero-mask result", api)
						}
						if strings.Contains(ir, "+avx512") {
							t.Fatal("isolated SSE4.1/AVX/AVX2 family borrowed an unrelated AVX512 producer", api)
						}
					}
				})
			}
		}
	}
}
