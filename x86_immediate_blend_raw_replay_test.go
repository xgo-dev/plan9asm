package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86ImmediateBlendRawWholeProducerReplayBoundaries(t *testing.T) {
	rows, codes := x86ImmediateBlendCases(), x86ImmediateBlendOriginalCodes(t)
	for _, arch := range []string{"amd64", "386"} {
		var prior strings.Builder
		for index, row := range rows {
			source, _ := x86ImmediateBlendInitializedProgram(row, codes[index], arch, fmt.Sprint("Prior", index))
			prior.WriteString(source)
		}
		x86LEAActualTargetGoObject(t, arch, x86AddressMemoryTargets(arch)[0], prior.String())
		for index, row := range rows {
			source, declaration := x86ImmediateBlendInitializedProgram(row, codes[index], arch, "Value")
			check := x86LegacyFloatReplayCheck(t, arch, source, declaration)
			for _, mutation := range []string{
				"valid", "origin", "missing-replay", "producer", "opcode", "spelling", "original-bytes", "snapshot",
			} {
				t.Run(fmt.Sprintf("%s/%s/%d/memory=%t/%s", arch, row.op, row.width, row.memory, mutation), func(t *testing.T) {
					file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
					if err != nil || len(file.Funcs) != 1 {
						t.Fatal("actual Go/LLVM-accepted original whole producer could not decode its physical blend", err)
					}
					original, ordinal := file.Funcs[0], -1
					for position, ins := range original.Instrs {
						if ins.Op == Op(row.op) && ins.x86SourceRaw != nil {
							if ordinal >= 0 {
								t.Fatal("ambiguous original blend instruction")
							}
							ordinal = position
						}
					}
					if ordinal < 0 || original.x86RawReplay == nil || original.x86RawReplay.validate(original, arch) != nil {
						t.Fatal("complete original producer lost its sealed raw identity")
					}
					candidate := original
					candidate.Instrs = cloneX86ReplayInstrs(original.Instrs)
					instruction := &candidate.Instrs[ordinal]
					switch mutation {
					case "origin":
						instruction.x86SourceRaw = nil
					case "missing-replay":
						candidate.x86RawReplay = nil
					case "producer":
						candidate.Instrs[1].Raw += " changed"
					case "opcode":
						instruction.Op = "BLENDPS"
						if row.op == "BLENDPS" {
							instruction.Op = "BLENDPD"
						}
					case "spelling":
						instruction.Raw += " changed"
					case "original-bytes", "snapshot":
						replay := *original.x86RawReplay
						if mutation == "original-bytes" {
							replay.source = strings.Replace(replay.source, "BYTE $", "BYTE $1+", 1)
						} else {
							replay.normalized = cloneX86ReplayInstrs(replay.normalized)
							replay.normalized[ordinal].Raw += " changed"
						}
						candidate.x86RawReplay = &replay
					}
					err = check(candidate)
					if mutation == "valid" {
						if err != nil {
							t.Fatal("whole initialized original raw blend producer rejected", err)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("real whole-Func consumer accepted edited original blend/source identity", err)
					}
					if original.x86RawReplay.validate(original, arch) != nil {
						t.Fatal("mutating a clone corrupted its independently sealed original producer")
					}
				})
			}
		}
	}
}

func TestX86ImmediateBlendVEXWIGAndReservedWPhysicalForms(t *testing.T) {
	rows, codes := x86ImmediateBlendCases(), x86ImmediateBlendOriginalCodes(t)
	for index, row := range rows {
		if row.legacy {
			continue
		}
		code := append([]byte(nil), codes[index]...)
		if len(code) < 6 || code[0] != 0xc4 || code[2]&0x80 != 0 {
			t.Fatal("independent Go instruction lost its W0 VEX envelope", row, code)
		}
		code[2] |= 0x80
		for _, mode := range []int{32, 64} {
			t.Run(fmt.Sprintf("%s/%d/memory=%t/mode=%d", row.op, row.width, row.memory, mode), func(t *testing.T) {
				// Intel: three members are WIG; VPBLENDD alone is W0 (#UD at W1).
				if row.op != "VPBLENDD" {
					x86NumericalNativeRequireMC(t, code, mode, 1, "+sse4.1,+avx2")
				}
				ins, length, known, err := decodedX86ImmediatePackedBlendInstruction(code, mode)
				if row.op == "VPBLENDD" {
					if !known || err == nil {
						t.Fatal("reserved VEX.W1 VPBLENDD acquired valid numerical form", ins, err)
					}
				} else if !known || err != nil || length != len(code) || ins.Op != Op(row.op) {
					t.Fatal("official WIG physical form rejected as frontend named grammar or W0-only", ins, length, err)
				}
			})
		}
	}
}

func TestX86ImmediateBlendIntegerExpressionsAndInvalidGrammar(t *testing.T) {
	for _, row := range x86ImmediateBlendCases() {
		if row.memory || row.width != 16 {
			continue
		}
		for _, immediate := range []string{"(1<<7)|37", "255-90", "(0xa0|5)", "0xa5+0"} {
			t.Run(row.op+"/"+immediate, func(t *testing.T) {
				// Go's full integer grammar is the prior, not our ImmRaw parser.
				operation := row.instruction(immediate)
				source := "TEXT ·Value(SB),4,$0-4\nPXOR X0,X0\nPXOR X1,X1\nPXOR X2,X2\n" + operation + "\nMOVL X2,ret+0(FP)\nRET\n"
				x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32", "amd64", "x86_64-unknown-linux-gnu", api); err != nil || ir == "" {
						t.Fatal("actual Go integer expression lost its existing initialized named role", api, err)
					}
				}
			})
		}
		for _, suffix := range []string{".", ".Z", ".BCST", ".SAE", ".RN_SAE", ".Z.Z"} {
			t.Run(row.op+suffix, func(t *testing.T) {
				operation := strings.Replace(row.instruction("0xa5"), row.op, row.op+suffix, 1)
				if suffix == "." {
					_, err := Parse(ArchAMD64, "TEXT invalid(SB),4,$0-0\n"+operation+"\nRET\n")
					if err == nil || !strings.Contains(err.Error(), "instruction suffix expected identifier") {
						t.Fatal("actual parser lost its independent trailing-dot rejection", err)
					}
					t.Log("original malformed source remains rejected by the parser:", err)
				}
				// Exercise the lowerer's independent grammar too, without asking
				// a helper to parse the very syntax that must already be rejected.
				ins := x86ScalarLaneInstruction(t, row.instruction("0xa5"))
				ins.Op, ins.Raw = Op(row.op+suffix), operation
				ctx, output := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Ret: Void}, nil)
				before := output.String()
				known, _, err := ctx.lowerImmediatePackedBlend(ins.Op, ins)
				if !known || err == nil || output.String() != before {
					t.Fatal("invalid suffix absent from the complete Go optab emitted a blend", operation, known, err)
				}
			})
		}
	}
}
