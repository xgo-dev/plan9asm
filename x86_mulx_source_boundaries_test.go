package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86MULXPhysicalFrameOutputsNeedTheirOwnSourceRole(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range x86MULXTestOps(arch) {
			rows := []string{op + " AX,BX,DX"}
			registers := []string{"SP"}
			if arch == "amd64" {
				registers = append(registers, "BP")
			}
			for _, register := range registers {
				rows = append(rows, op+" AX,"+register+",DX", op+" AX,BX,"+register)
			}
			code, pcs := x86NumericalBoundaryGoBytes(t, arch, strings.Join(rows, "\n")+"\nRET\n")
			if len(pcs) != len(rows)+1 {
				t.Fatal("actual Go omitted a write-only MULX output row", pcs)
			}
			mode := 64
			if arch == "386" {
				mode = 32
			}
			x86NumericalVEXGPRequireMC(t, code, mode, len(pcs))
			var prior strings.Builder
			var sources []string
			for index, row := range rows {
				for _, raw := range []bool{false, true} {
					instruction := row + "\n"
					if raw {
						instruction = x86RawDisplacementDirectives(code[pcs[index]:pcs[index+1]])
					}
					body := "TEXT Value(SB),4,$0-0\nMOVL $7,AX\nMOVL $3,DX\n" + instruction + "RET\n"
					prior.WriteString(strings.Replace(body, "TEXT Value(SB)", fmt.Sprintf("TEXT Output%d(SB)", len(sources)), 1))
					sources = append(sources, body)
				}
			}
			// The Go object independently establishes source-format validity;
			// neither that nor Yrl grants a physical SP/BP return contract.
			x86LEAActualTargetGoObject(t, arch, x86AddressMemoryTargets(arch)[0], prior.String())
			for index, source := range sources {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/row%d/raw=%t/%s", arch, op, index/2, index%2 == 1, api), func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, "func Value()", arch, x86AddressMemoryTargets(arch)[0], api)
						if index < 2 {
							if err != nil || ir == "" {
								t.Fatal("ordinary initialized BX/DX product lost its source role", err)
							}
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("write-only Yrl output borrowed a physical stack/frame role", err)
						}
					})
				}
			}
		}
	}
}

func TestX86MULXRawContinuationRequiresCompleteOriginalProducer(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range x86MULXTestOps(arch) {
			physical := x86MULXTestPhysical(t, arch, op)
			prefix := "TEXT Value(SB),4,$0-4\nMOVL $7,AX\nMOVL $3,DX\n"
			suffix := "MOVL CX,ret+0(FP)\nRET\n"
			named := prefix + op + " AX,CX,DX\n" + suffix
			source := prefix + physical[op+" AX,CX,DX"] + suffix
			x86LEAActualTargetGoObject(t, arch, x86AddressMemoryTargets(arch)[0],
				strings.Replace(named, "TEXT Value(SB)", "TEXT Named(SB)", 1)+source)
			strict, check := x86RegisterReplayConsumers(t, arch, named)
			namedFunction := mustParseX86RawReturn(t, named).Funcs[0]
			if strict(namedFunction) != nil || check(namedFunction) != nil {
				t.Fatal("initialized named MULX was not an independent strict positive")
			}
			file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
			if err != nil {
				t.Fatal("original MULX decoding prerequisite", err)
			}
			original, ordinal := file.Funcs[0], -1
			for index, ins := range original.Instrs {
				if x86RawMULXSource(ins, arch) {
					ordinal = index
				}
			}
			if ordinal < 0 || original.x86RawReplay == nil || original.x86RawReplay.validate(original, arch) != nil {
				t.Fatal("actual initialized MULX lost its complete original replay")
			}
			for _, mutation := range []string{
				"none", "origin", "opcode", "operand", "source-operand", "vector", "address", "override", "segment",
				"missing replay", "source spelling", "original bytes", "decoded snapshot", "producer",
			} {
				t.Run(arch+"/"+op+"/"+mutation, func(t *testing.T) {
					candidate := original
					candidate.Instrs = cloneX86ReplayInstrs(original.Instrs)
					switch mutation {
					case "missing replay":
						candidate.x86RawReplay = nil
					case "source spelling":
						candidate.Instrs[ordinal].Raw += " changed"
					case "original bytes":
						replay := *original.x86RawReplay
						replay.source = strings.Replace(replay.source, "BYTE $", "BYTE $1+", 1)
						candidate.x86RawReplay = &replay
					case "decoded snapshot":
						replay := *original.x86RawReplay
						replay.decoded = cloneX86ReplayInstrs(replay.decoded)
						replay.decoded[ordinal].x86SourceRaw = nil
						candidate.x86RawReplay = &replay
					case "producer":
						candidate.Instrs[1].Args[0].Imm = 9
					default:
						candidate.Instrs[ordinal] = x86ShiftChoiceMutatedOrigin(candidate.Instrs[ordinal], mutation)
					}
					if mutation == "origin" {
						// Removing origin makes the direct instruction look named;
						// the whole-Func consumer must retain the sealed restriction.
						if x86RawMULXSource(candidate.Instrs[ordinal], arch) || strict(candidate) != nil {
							t.Fatal("origin-only control did not reach genuine strict numerical success")
						}
					}
					err := check(candidate)
					if mutation == "none" && err != nil || mutation != "none" && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("MULX continuation lost whole original producer identity", mutation, err)
					}
					if original.x86RawReplay.validate(original, arch) != nil {
						t.Fatal("candidate mutation changed the independent original replay")
					}
				})
			}
		}
	}
}
