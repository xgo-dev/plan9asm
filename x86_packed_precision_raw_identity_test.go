package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86PackedPrecisionRawGenerationAndWholeProducerIdentity(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for index, row := range x86RawPackedPrecisionForms {
			t.Run(fmt.Sprintf("%s/%s/LL%d/EVEX=%t", arch, row.op, row.length, row.evex), func(t *testing.T) {
				name := fmt.Sprint("RawPackedPrecision", index)
				code := rawPackedPrecisionBytes(row.pp, row.length, row.evex, false)
				header := "TEXT ·" + name + "(SB),4,$0-0\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n"
				source := header + x86RawDisplacementDirectives(code) + "RET\n"
				goAssemblerOracleOutput(t, arch, source, "", true)
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), arch)
				if err != nil || len(file.Funcs) != 1 {
					t.Fatal("original complete raw precision producer cannot be decoded", err)
				}
				original := file.Funcs[0]
				ordinal := len(original.Instrs) - 2
				var addresses [16]bool
				addresses[3], addresses[7] = true, true
				t.Run("independent-source-domains", func(t *testing.T) {
					instruction := original.Instrs[ordinal]
					if x86ResultDirectionAfterSource(instruction, x86ResultDirectionBackward, arch) != x86ResultDirectionBackward ||
						!x86ResultPreservesPrivateStorage(instruction, arch) ||
						x86ResultCallerAddressesAfter(instruction, addresses, nil, arch) != addresses {
						t.Fatal("bound precision opcode revoked independent DF/ID/private-stack/GP-address facts")
					}
				})
				check := func(fn Func, targetArch string) error {
					triple := "x86_64-unknown-linux-gnu"
					if targetArch == "386" {
						triple = "i386-unknown-linux-gnu"
					}
					ctx := newX86Ctx(new(strings.Builder), fn, FuncSig{Name: name, Ret: Void}, nil, nil, targetArch, triple, false)
					return ctx.checkLoweredScalarFPResultInitialization()
				}
				if original.x86RawReplay == nil || original.x86RawReplay.validate(original, arch) != nil {
					t.Fatal("raw precision decoding did not preserve the whole original producer")
				}
				if err := check(original, arch); err != nil {
					t.Fatal("complete initialized raw precision producer lost its paired numerical continuation", err)
				}
				features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{original.Instrs[ordinal]}})
				if strings.Contains(features, "+avx512f") != row.evex || row.evex && row.length < 2 && !strings.Contains(features, "+avx512vl") {
					t.Fatal("low-bank physical precision generation lost its independent native ISA profile", features, row.evex)
				}
				for _, mutation := range []string{"origin", "encoded", "whole-producer", "operand", "vector-width", "missing-replay", "snapshot", "header"} {
					candidate := original
					candidate.Instrs = cloneX86ReplayInstrs(original.Instrs)
					instruction := &candidate.Instrs[ordinal]
					switch mutation {
					case "origin":
						instruction.x86SourceRaw = nil
					case "encoded":
						instruction.x86Encoded = !instruction.x86Encoded
					case "whole-producer":
						candidate.Instrs[1].Raw += " changed"
					case "operand":
						instruction.Args[0].Reg = Reg(string(instruction.Args[0].Reg[:1]) + "3")
					case "vector-width":
						instruction.x86VectorBytes = 7
					case "missing-replay":
						candidate.x86RawReplay = nil
					case "snapshot":
						replay := *original.x86RawReplay
						replay.normalized = cloneX86ReplayInstrs(replay.normalized)
						replay.normalized[ordinal].x86SourceRaw = nil
						candidate.x86RawReplay = &replay
					case "header":
						candidate.ArgSize++
					}
					if err := check(candidate, arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("edited raw source or producer borrowed the original precision continuation", mutation, err)
					}
				}
				foreign := "amd64"
				if arch == "amd64" {
					foreign = "386"
				}
				if err := check(original, foreign); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("raw precision source borrowed another architecture", err)
				}
				if original.x86RawReplay.validate(original, arch) != nil {
					t.Fatal("negative clone corrupted the original independent producer")
				}
			})
		}
	}
}

func TestX86PackedPrecisionInvalidFormsMatchActualGo(t *testing.T) {
	for _, instruction := range []string{
		"CVTPS2PD Y0,X1", "CVTPD2PS X0,Y1", "CVTPS2PD.SAE X0,X1",
		"VCVTPS2PD X0,Z1", "VCVTPS2PD.Z X0,X1", "VCVTPS2PD.SAE X0,Y1",
		"VCVTPS2PD.RN_SAE Y0,Z1", "VCVTPS2PD.BCST X0,Y1", "VCVTPS2PD X0,K0,X1",
		"VCVTPD2PSY X0,X1", "VCVTPD2PSX Y0,X1", "VCVTPD2PSX X0,Y1",
		"VCVTPD2PS.RN_SAE (BX),Y1", "VCVTPD2PS.SAE Z0,Y1", "VCVTPD2PSX.RN_SAE X0,X1",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT rejected(SB),4,$0-0\n" + instruction + "\nRET\n"
			masklessZero := instruction == "VCVTPS2PD.Z X0,X1"
			historicalReserved := masklessZero && !goToolchainAtLeast(runtime.Version(), 1, 21)
			goAssemblerOracleOutput(t, "amd64", source, "", historicalReserved)
			if masklessZero {
				// Go 1.20's issue-57952 bug emitted EVEX.z=1/aaa=0.
				// Those actual bytes are reserved, not an additional legal
				// format. New Go must retain its ordinary source diagnostic.
				code := []byte{0x62, 0xf1, 0x7c, 0x88, 0x5a, 0xc8}
				if historicalReserved {
					listing := x86InsertExtractGoListing(t, "amd64", source)
					var observed []byte
					for _, line := range strings.Split(string(listing), "\n") {
						observed = append(observed, x86InsertExtractListedBytes(line)...)
					}
					if !bytes.Equal(observed, append(append([]byte(nil), code...), 0xc3)) {
						t.Fatalf("historical reserved precision bytes changed: %x", observed)
					}
					t.Logf("%s actual Go object emitted reserved z=1/aaa=0 bytes %x, not a legal form", runtime.Version(), code)
				}
				if _, _, known, err := decodedX86PackedPrecisionConvertInstruction(code, 64); !known || err == nil {
					t.Fatal("reserved precision zeroing acquired raw semantics", known, err)
				}
				raw := x86RawINSERTPSSource("rejected", code)
				goAssemblerOracleOutput(t, "amd64", raw, "", true)
				for _, program := range []string{source, raw} {
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, program, "func rejected()\n", "amd64", "x86_64-unknown-linux-gnu", api)
						if ir != "" || err == nil || errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("reserved named/raw zeroing lost syntax rejection or produced IR", api, err)
						}
					}
				}
			}
			ins := x86ScalarLaneInstruction(t, instruction)
			if _, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64"); !known || err == nil {
				t.Fatal("known precision family lacks a closed independent Go grammar", known, err)
			}
		})
	}
}
