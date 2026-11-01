package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86COMIOriginalProducerObjects(t *testing.T, source, declarations, arch, triple string) {
	t.Helper()
	x86LEAActualTargetGoObject(t, arch, triple, source)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("original COMI producer objects require LLVM22")
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
			if err != nil || ir == "" {
				t.Fatal("complete initialized original COMI producer rejected", err)
			}
			optimized := x86DwordProductIROptimize(t, ir)
			for _, pipeline := range []struct{ body, level string }{
				{ir, "-O0"}, {ir, "-O2"}, {optimized, "-O2"},
			} {
				x86PackedStringCompileObject(t, llc, triple, pipeline.body, pipeline.level)
			}
		})
	}
}

func TestX86COMIOriginalRawNativeProducerObjectsThreeAMD64Targets(t *testing.T) {
	source, _, mainC, count := x86COMIRawNativeFixture(t)
	if count != 24 || strings.Count(source, "TEXT ") != 24 ||
		strings.Count(source, "VMOVUPS (AX),Z") != 24 || strings.Count(source, "VMOVUPS (BX),Z") != 24 ||
		fmt.Sprintf("%x", sha256.Sum256([]byte(mainC))) != "220d60304277ec428c85b577d20628b7f171bbfda06f92212b16ed3c25a68d48" {
		t.Fatal("original complete 24-kernel ASM/C inventory changed")
	}
	// Retain the actual complete generated source, including original Go bytes,
	// rather than claiming that a different low-bank or reduced-width program
	// executed this native oracle. This test compiles objects; it never runs it.
	t.Logf("original COMI ASM sha256=%x\n%s", sha256.Sum256([]byte(source)), source)
	t.Logf("original COMI C sha256=%x\n%s", sha256.Sum256([]byte(mainC)), mainC)
	var declarations strings.Builder
	for index := 0; index < count; index++ {
		fmt.Fprintf(&declarations, "func flagcompare%d(a,b,out *byte)\n", index)
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86COMIOriginalProducerObjects(t, source, declarations.String(), "amd64", triple)
		})
	}
}

type x86COMIRawProducerRow struct {
	op       string
	encoding string
	form     string
	code     []byte
}

func x86COMIRawProducerRows(t *testing.T) []x86COMIRawProducerRow {
	t.Helper()
	var rows []x86COMIRawProducerRow
	for _, op := range []string{"VCOMISS", "VCOMISD", "VUCOMISS", "VUCOMISD"} {
		for _, encoding := range []string{"VEX", "EVEX"} {
			for _, form := range []string{"register", "memory", "sae"} {
				if encoding == "VEX" && form == "sae" {
					continue
				}
				operation := op + " X1,X0"
				if form == "memory" {
					operation = op + " (BX),X0"
				}
				if encoding == "EVEX" {
					// The actual low-bank SAE encoding is an independent Go
					// prior. Clear only b for plain EVEX and use the exact BX
					// ModRM for memory; LLVM MC below separately proves both
					// physical modes, not our decoder or Go's BYTE acceptance.
					operation = op + ".SAE X1,X0"
				}
				code := assembleX87ControlBytes(t, "amd64", "TEXT probe(SB),4,$0-0\n"+operation+"\nRET\n")
				if len(code) < 2 || code[len(code)-1] != 0xc3 {
					t.Fatal("actual Go COMI byte capture lost its terminal RET", operation, code)
				}
				code = append([]byte(nil), code[:len(code)-1]...)
				if encoding == "EVEX" {
					if len(code) != 6 || code[0] != 0x62 || code[3]&0x10 == 0 || code[5] != 0xc1 {
						t.Fatal("actual Go low-bank SAE physical envelope changed", operation, code)
					}
					if form != "sae" {
						code[3] &^= 0x10
					}
					if form == "memory" {
						code[5] = 0x03 // r/m=BX, no displacement; destination X0.
					}
				}
				for _, mode := range []int{32, 64} {
					x86NumericalNativeRequireMC(t, code, mode, 1, "+avx,+avx512f,+avx512vl")
				}
				rows = append(rows, x86COMIRawProducerRow{op, encoding, form, code})
			}
		}
	}
	if len(rows) != 20 {
		t.Fatal("complete four-member VEX/EVEX register/memory/SAE directory changed", len(rows))
	}
	return rows
}

func x86COMIRawProducerProgram(row x86COMIRawProducerRow, arch, name string, raw bool) (string, string) {
	word, move := goWordSize(arch), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s a+0(FP),AX\n%s b+%d(FP),BX\n%s out+%d(FP),DI\n",
		name, word*3, move, move, word, move, word*2)
	for _, register := range []int{0, 1, 2} {
		fmt.Fprintf(&source, "VMOVUPS (AX),Z%d\n", register)
	}
	source.WriteString("VMOVUPS (BX),Z1\nMOVL $2147483647,CX\nADDL $1,CX\n")
	if raw {
		source.WriteString(x86RawDisplacementDirectives(row.code))
	} else {
		op, input := row.op, "X1"
		if row.form == "memory" {
			input = "(BX)"
		}
		if row.form == "sae" {
			op += ".SAE"
		}
		fmt.Fprintf(&source, "%s %s,X0\n", op, input)
	}
	source.WriteString("SETEQ (DI)\nSETCS 1(DI)\nSETPS 2(DI)\nSETMI 3(DI)\nSETOS 4(DI)\nVMOVUPS Z0,8(DI)\nVMOVUPS Z1,72(DI)\nRET\n")
	return source.String(), fmt.Sprintf("func %s(a,b *[64]byte,out *[136]byte)\n", name)
}

func TestX86COMIRawAndNamedNativeProducerFiveTargetObjects(t *testing.T) {
	rows := x86COMIRawProducerRows(t)
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			for index, row := range rows {
				for _, raw := range []bool{false, true} {
					body, declaration := x86COMIRawProducerProgram(row, target.arch, fmt.Sprintf("Compare%dRaw%t", index, raw), raw)
					source.WriteString(body)
					declarations.WriteString(declaration)
				}
			}
			x86COMIOriginalProducerObjects(t, source.String(), declarations.String(), target.arch, target.triple)
		})
	}
}

func TestX86COMIRawNativeProducerWholeSourceIdentity(t *testing.T) {
	rows := x86COMIRawProducerRows(t)
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range rows {
			source, declaration := x86COMIRawProducerProgram(row, arch, "Value", true)
			x86LEAActualTargetGoObject(t, arch, x86AddressMemoryTargets(arch)[0], source)
			check := x86LegacyFloatReplayCheck(t, arch, source, declaration)
			for _, mutation := range []string{"valid", "origin", "encoded", "generation", "opcode", "operand",
				"origin-operand", "origin-mode", "missing-replay", "replay-mode", "producer", "spelling",
				"original-bytes", "decoded-snapshot", "normalized-snapshot", "all-generation-snapshots"} {
				t.Run(arch+"/"+row.op+"/"+row.encoding+"/"+row.form+"/"+mutation, func(t *testing.T) {
					file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
					if err != nil || len(file.Funcs) != 1 {
						t.Fatal("actual Go/LLVM-accepted whole COMI producer failed to normalize", err)
					}
					original, ordinal := file.Funcs[0], -1
					for index, instruction := range original.Instrs {
						if _, known, _ := x86COMIProperties(instruction, arch); known {
							if ordinal >= 0 {
								t.Fatal("ambiguous original COMI producer")
							}
							ordinal = index
						}
					}
					if ordinal < 0 || original.x86RawReplay == nil || original.x86RawReplay.validate(original, arch) != nil {
						t.Fatal("original COMI lacks its complete immutable replay")
					}
					candidate := original
					candidate.Instrs = cloneX86ReplayInstrs(original.Instrs)
					instruction := &candidate.Instrs[ordinal]
					switch mutation {
					case "origin":
						instruction.x86SourceRaw = nil
					case "encoded":
						instruction.x86Encoded = !instruction.x86Encoded
					case "generation":
						instruction.x86ScalarFlagCompareEVEX = !instruction.x86ScalarFlagCompareEVEX
					case "opcode":
						instruction.Op = "VCOMISS"
						if row.op == "VCOMISS" {
							instruction.Op = "VUCOMISS"
						}
					case "operand":
						instruction.Args[0] = Operand{Kind: OpReg, Reg: "X2"}
					case "origin-operand":
						instruction.x86SourceRaw.args[1].Reg = "X2"
					case "origin-mode":
						instruction.x86SourceRaw.addressBits = 16
					case "missing-replay":
						candidate.x86RawReplay = nil
					case "producer":
						candidate.Instrs[1].Raw += " changed"
					case "spelling":
						instruction.Raw += " changed"
					default:
						if mutation != "valid" {
							replay := *original.x86RawReplay
							replay.decoded = cloneX86ReplayInstrs(replay.decoded)
							replay.normalized = cloneX86ReplayInstrs(replay.normalized)
							switch mutation {
							case "replay-mode":
								replay.goarch = "386"
								if arch == "386" {
									replay.goarch = "amd64"
								}
							case "original-bytes":
								replay.source = strings.Replace(replay.source, "BYTE $", "BYTE $1+", 1)
							case "decoded-snapshot", "all-generation-snapshots":
								replay.decoded[ordinal].x86ScalarFlagCompareEVEX = !replay.decoded[ordinal].x86ScalarFlagCompareEVEX
							case "normalized-snapshot":
								replay.normalized[ordinal].Raw += " changed"
							}
							if mutation == "all-generation-snapshots" {
								instruction.x86ScalarFlagCompareEVEX = !instruction.x86ScalarFlagCompareEVEX
								replay.normalized[ordinal].x86ScalarFlagCompareEVEX = instruction.x86ScalarFlagCompareEVEX
							}
							candidate.x86RawReplay = &replay
						}
					}
					err = check(candidate)
					if mutation == "valid" {
						if err != nil {
							t.Fatal("complete original COMI native continuation rejected", err)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("edited original COMI source borrowed raw/physical identity", mutation, err)
					}
					if original.x86RawReplay.validate(original, arch) != nil {
						t.Fatal("mutating a clone changed the independent original replay")
					}
				})
			}
		}
	}
}

func TestX86COMIRawNativeProducerCannotInventMissingInputs(t *testing.T) {
	rows := x86COMIRawProducerRows(t)
	for _, arch := range []string{"amd64", "386"} {
		word, move := goWordSize(arch), "MOVQ"
		if arch == "386" {
			move = "MOVL"
		}
		var prior strings.Builder
		var cases []struct{ name, source, declaration string }
		for _, row := range rows {
			for _, raw := range []bool{false, true} {
				for _, missing := range []string{"first-pointer", "second-pointer", "output-pointer", "whole-upper-bytes", "future-pointer"} {
					source, declaration := x86COMIRawProducerProgram(row, arch, fmt.Sprint("Missing", len(cases)), raw)
					from, to := move+" a+0(FP),AX\n", ""
					switch missing {
					case "second-pointer":
						from = fmt.Sprintf("%s b+%d(FP),BX\n", move, word)
					case "output-pointer":
						from = fmt.Sprintf("%s out+%d(FP),DI\n", move, word*2)
					case "whole-upper-bytes":
						from, to = "VMOVUPS (AX),Z0\n", "MOVSS (AX),X0\n"
					}
					changed := strings.Replace(source, from, to, 1)
					if missing == "future-pointer" {
						changed = strings.Replace(changed, "VMOVUPS Z0,8(DI)\n", from+"VMOVUPS Z0,8(DI)\n", 1)
					}
					if changed == source {
						t.Fatal("independent missing-input mutation did not apply")
					}
					prior.WriteString(changed)
					name := fmt.Sprintf("%s/%s/%s/%s/raw=%t/%s", arch, row.op, row.encoding, row.form, raw, missing)
					cases = append(cases, struct{ name, source, declaration string }{name, changed, declaration})
				}
			}
		}
		// One complete real object retains all 200 exact named functions,
		// rather than rebuilding the same selected SDK prior for each API.
		if len(cases) != 200 {
			t.Fatal("complete missing-input counterexample inventory changed", len(cases))
		}
		x86LEAActualTargetGoObject(t, arch, x86AddressMemoryTargets(arch)[0], prior.String())
		for _, row := range cases {
			t.Run(row.name, func(t *testing.T) {
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, row.source, row.declaration, arch, x86AddressMemoryTargets(arch)[0], api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("COMI continuation supplied an absent reaching input", api, err)
					}
				}
			})
		}
	}
}

func TestX86COMIRawProducerPreservesIndependentSourceDomains(t *testing.T) {
	rows := x86COMIRawProducerRows(t)
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range rows {
			t.Run(arch+"/"+row.op+"/"+row.encoding+"/"+row.form, func(t *testing.T) {
				source, _ := x86COMIRawProducerProgram(row, arch, "Value", true)
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
				if err != nil || len(file.Funcs) != 1 || file.Funcs[0].x86RawReplay == nil ||
					file.Funcs[0].x86RawReplay.validate(file.Funcs[0], arch) != nil {
					t.Fatal("original source-domain fixture lacks its complete raw replay", err)
				}
				count := 0
				for _, instruction := range file.Funcs[0].Instrs {
					if _, known, _ := x86COMIProperties(instruction, arch); !known {
						continue
					}
					count++
					if got := x86ResultDirectionAfterSource(instruction, x86ResultDirectionBackward, arch); got != x86ResultDirectionBackward {
						t.Error("scalar status comparison lost independent DF")
					}
					if !x86ResultPreservesPrivateStorage(instruction, arch) {
						t.Error("scalar status comparison lost existing private stack or ID")
					}
					var before [16]bool
					before[0], before[2], before[3], before[7] = true, true, true, true
					if got := x86ResultCallerAddressesAfter(instruction, before, nil, arch); got != before {
						t.Error("scalar status comparison revoked unrelated existing GP identities")
					}
				}
				if count != 1 {
					t.Fatal("ambiguous source-domain comparison inventory", count)
				}
			})
		}
	}
}
