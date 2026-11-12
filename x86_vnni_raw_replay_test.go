package plan9asm

import (
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func x86VNNIVEXCode(opcode byte, bank string, memory bool) []byte {
	prefix, modrm := byte(0x71), byte(0xc2) // VEX.128.66.0F38.W0, X2,X1,X0.
	if bank == "Y" {
		prefix |= 4
	}
	if memory {
		modrm = 0 // (AX),X1,X0; VEX has no compressed displacement.
	}
	return []byte{0xc4, 0xe2, prefix, opcode, modrm}
}

func TestX86VNNIIntegerVEXPhysicalPriorAndWholeProducerReplay(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc required for independent raw VNNI instruction prior")
	}
	for _, arch := range []string{"386", "amd64"} {
		triple := testTargetTriple("linux", arch)
		t.Run(arch, func(t *testing.T) {
			var input strings.Builder
			for _, member := range x86VNNIIntegerMembers {
				for _, bank := range []string{"X", "Y"} {
					for _, memory := range []bool{false, true} {
						for _, value := range x86VNNIVEXCode(member.opcode, bank, memory) {
							fmt.Fprintf(&input, "0x%02x ", value)
						}
						input.WriteByte('\n')
					}
				}
			}
			stage, cancel := runtimeOracleStageContext(t)
			command := exec.CommandContext(stage, mc, "--disassemble", "--triple="+triple, "--mattr=+avxvnni")
			command.Stdin = strings.NewReader(input.String())
			output, err := runtimeOracleCombinedOutput(stage, command)
			cancel()
			if err != nil || strings.Contains(string(output), "warning") || strings.Contains(string(output), "invalid") {
				t.Fatalf("independent LLVM22 rejected original VEX VNNI bytes: %v\n%s", err, output)
			}
			for _, member := range x86VNNIIntegerMembers {
				if got := len(regexp.MustCompile(`(?m)\b`+strings.ToLower(member.op)+`[ \t]+`).FindAll(output, -1)); got != 4 {
					t.Fatal("independent VEX instruction denominator changed", member.op, got, string(output))
				}
				for _, bank := range []string{"X", "Y"} {
					for _, memory := range []bool{false, true} {
						input := "register"
						if memory {
							input = "full"
						}
						row := x86VNNIOracleRow{member.op, bank, input, "plain"}
						named, declaration := row.program(arch, "Value")
						source := strings.Replace(named, row.instruction()+"\n", x86RawDisplacementDirectives(x86VNNIVEXCode(member.opcode, bank, memory)), 1)
						t.Run(fmt.Sprintf("%s/%s/memory=%t", member.op, bank, memory), func(t *testing.T) {
							x86LEAActualTargetGoObject(t, arch, triple, source)
							file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
							if err != nil {
								t.Fatal("complete physically validated VEX source could not normalize", err)
							}
							original, ordinal := file.Funcs[0], -1
							for i, ins := range original.Instrs {
								if ins.Op == Op(member.op) && ins.x86SourceRaw != nil {
									ordinal = i
								}
							}
							if ordinal < 0 || original.x86RawReplay == nil || original.x86RawReplay.validate(original, arch) != nil {
								t.Fatal("original VEX source lost its complete immutable producer replay")
							}
							state := x86FMA3ResultInputState()
							state.pointerGP[0] = true
							before := state.clone()
							if x86ScalarFPResultTransfer(original.Instrs[ordinal], &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
								t.Fatal("standalone raw source borrowed the named numerical or native memory contract")
							}
							check := x86LegacyFloatReplayCheck(t, arch, named, declaration)
							for _, mutation := range []string{"original", "origin-only", "missing-replay", "producer", "operand", "encoded", "vector-width", "original-bytes"} {
								t.Run(mutation, func(t *testing.T) {
									candidate := original
									candidate.Instrs = cloneX86ReplayInstrs(original.Instrs)
									ins := &candidate.Instrs[ordinal]
									switch mutation {
									case "origin-only":
										ins.x86SourceRaw = nil
										// VEX was decoded with the legacy grammar flag false:
										// do not add another mutation to conceal its erasure.
									case "missing-replay":
										candidate.x86RawReplay = nil
									case "producer":
										candidate.Instrs[1].Raw += " changed"
									case "operand":
										ins.Args[1].Reg = Reg(bank + "7")
									case "encoded":
										ins.x86Encoded = !ins.x86Encoded
									case "vector-width":
										ins.x86VectorBytes = 7
									case "original-bytes":
										replay := *original.x86RawReplay
										replay.source = strings.Replace(replay.source, "BYTE $", "BYTE $1+", 1)
										candidate.x86RawReplay = &replay
									}
									failure := check(candidate)
									if mutation == "original" {
										if failure != nil {
											t.Fatal("initialized raw VEX producer lost its paired lowering owner", failure)
										}
									} else if !errors.Is(failure, ErrProbeNeedsContext) {
										t.Fatal("edited VEX generation or producer borrowed a named instruction contract", failure)
									}
									if original.x86RawReplay.validate(original, arch) != nil {
										t.Fatal("cloned source mutation damaged its independently sealed original")
									}
								})
							}
						})
					}
				}
			}
		})
	}
}
