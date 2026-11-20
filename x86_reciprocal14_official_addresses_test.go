package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Keep the actual SDK source operands, including SP, repeated base/index,
// negative displacements and non-K1 masks. Canonical row witnesses do not
// establish initialized entry or memory authority for these original operands.
func x86Reciprocal14OfficialOriginalInstructions(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(runtime.GOROOT(), "src", "cmd", "asm", "internal", "asm", "testdata", "avx512enc", "avx512f.s")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	members := make(map[string]bool)
	for _, member := range x86Reciprocal14TestMembers {
		members[member.op] = true
	}
	var instructions []string
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "//")
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) != 0 && members[fields[0]] {
			instructions = append(instructions, line)
		}
	}
	if len(instructions) != 68 {
		t.Fatal("complete original reciprocal14 SDK source denominator changed", len(instructions))
	}
	return instructions
}

func TestX86Reciprocal14OriginalEncodingWholeBoundaries(t *testing.T) {
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86Reciprocal14Rows(legacy, avx)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, row := range rows {
		for _, witness := range row.Witnesses {
			count++
			t.Run(fmt.Sprint(count), func(t *testing.T) {
				if length, err := x86NumericalVectorBoundary(witness.Encoding, 64); err != nil || length != len(witness.Encoding) {
					t.Fatalf("original %s boundary %x: length=%d err=%v", witness.Instruction, witness.Encoding, length, err)
				}
				for _, mutation := range []string{"truncated", "fixed bit", "zero without mask", "reserved source"} {
					changed := append([]byte(nil), witness.Encoding...)
					switch mutation {
					case "truncated":
						changed = changed[:len(changed)-1]
					case "fixed bit":
						changed[2] &^= 4
					case "zero without mask":
						changed[3] = changed[3]&^7 | 0x80
					case "reserved source":
						if strings.HasSuffix(row.Opcode, "SS") || strings.HasSuffix(row.Opcode, "SD") {
							changed[3] |= 0x10 // Scalar encodings have no broadcast/rounding field.
						} else {
							changed[2] &^= 8 // Unary packed encodings reserve vvvv and V'.
						}
					}
					if _, err := x86NumericalVectorBoundary(changed, 64); err == nil {
						t.Fatal("changed bytes borrowed complete original boundary", mutation, witness.Instruction)
					}
				}
			})
		}
	}
	if len(rows) != 32 || count != 132 {
		t.Fatal("complete reciprocal14 row/boundary denominator changed", len(rows), count)
	}
}

func x86Reciprocal14OriginalRegisterInputs(t *testing.T, instruction string, privateFrame bool) (Instr, string) {
	t.Helper()
	ins := x86ScalarLaneInstruction(t, instruction)
	vectors, masks := make(map[int]bool), make(map[string]bool)
	for _, arg := range ins.Args {
		if arg.Kind != OpReg {
			continue
		}
		if amd64IsKOperand(arg) {
			masks[string(arg.Reg)] = true
			continue
		}
		if index, valid := amd64VectorRegisterIndex(arg.Reg, amd64VectorByteWidth(arg.Reg)); valid {
			vectors[index] = true
		}
	}
	var indices []int
	for index := range vectors {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	var source strings.Builder
	for _, index := range indices {
		if privateFrame {
			fmt.Fprintf(&source, "VMOVUPS 0(SP),Z%d\n", index)
		} else {
			fmt.Fprintf(&source, "VPXORD Z%d,Z%d,Z%d\n", index, index, index)
		}
	}
	var maskNames []string
	for mask := range masks {
		maskNames = append(maskNames, mask)
	}
	sort.Strings(maskNames)
	for _, mask := range maskNames {
		fmt.Fprintf(&source, "MOVQ $65535,AX\nKMOVQ AX,%s\n", mask)
	}
	return ins, source.String()
}

func x86Reciprocal14OriginalCallerSource(t *testing.T, instruction string) (string, string) {
	t.Helper()
	ins, setup := x86Reciprocal14OriginalRegisterInputs(t, instruction, false)
	var body strings.Builder
	body.WriteString(setup)
	if first := ins.Args[0]; first.Kind == OpMem {
		fmt.Fprintf(&body, "MOVQ input+8(FP),%s\nLEAQ 128(%s),%s\n", first.Mem.Base, first.Mem.Base, first.Mem.Base)
		if first.Mem.Index != "" && first.Mem.Index != first.Mem.Base {
			fmt.Fprintf(&body, "MOVQ $0,%s\n", first.Mem.Index)
		}
	}
	body.WriteString(instruction + "\n")
	destination := ins.Args[len(ins.Args)-1].Reg
	fmt.Fprintf(&body, "MOVQ out+0(FP),DI\nVMOVUPS %s,(DI)\nRET\n", destination)
	return "TEXT ·Original(SB),4,$0-16\n" + body.String(), "func Original(out,input *[512]byte)\n"
}

func TestX86Reciprocal14OriginalGPAndRegisterOperandsThreeAPIObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	count := 0
	for index, instruction := range x86Reciprocal14OfficialOriginalInstructions(t) {
		ins := x86ScalarLaneInstruction(t, instruction)
		if ins.Args[0].Kind == OpMem && (ins.Args[0].Mem.Base == SP || ins.Args[0].Mem.Base == BP) {
			continue // The captured private-frame owner below owns SP and BP.
		}
		if first := ins.Args[0]; first.Kind == OpMem && first.Mem.Index == first.Mem.Base {
			continue // The independent pending-address boundary below owns both originals.
		}
		count++
		t.Run(fmt.Sprintf("source%02d", index), func(t *testing.T) {
			source, declaration := x86Reciprocal14OriginalCallerSource(t, instruction)
			t.Logf("original=%q initializedSource=%q declaration=%q", instruction, source, declaration)
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if err != nil {
						t.Fatalf("initialized original operand source %q: %v", instruction, err)
					}
					x86ResultInitializationObject(t, llc, "x86_64-unknown-linux-gnu", ir, api)
				})
			}
		})
	}
	if count != 60 {
		t.Fatal("original GP/register source denominator changed", count)
	}
}

func TestX86Reciprocal14OriginalRepeatedPointerIndexRemainsContext(t *testing.T) {
	count := 0
	for _, instruction := range x86Reciprocal14OfficialOriginalInstructions(t) {
		ins := x86ScalarLaneInstruction(t, instruction)
		first := ins.Args[0]
		if first.Kind != OpMem || first.Mem.Index == "" || first.Mem.Index != first.Mem.Base {
			continue
		}
		count++
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			source, declaration := x86Reciprocal14OriginalCallerSource(t, instruction)
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
			// An initialized opaque pointer is not a NUM index or a proof that
			// 3*pointer+99 belongs to its input array. Keep both exact originals
			// pending a separate paired-native machine-address contract.
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "result initialization") {
					t.Fatal("repeated opaque pointer index acquired an unproved native address", instruction, api, err)
				}
			}
			t.Logf("PENDING_NATIVE_ADDRESS original=%q source=%q; no positive LLVM object or runtime claim", instruction, source)
		})
	}
	if count != 2 {
		t.Fatal("exact repeated-pointer address boundary denominator changed", count)
	}
}

func TestX86Reciprocal14OriginalSPAndBPHaveCapturedInitializedFrame(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	count := 0
	for _, instruction := range x86Reciprocal14OfficialOriginalInstructions(t) {
		ins, setup := x86Reciprocal14OriginalRegisterInputs(t, instruction, true)
		if ins.Args[0].Kind != OpMem || ins.Args[0].Mem.Base != SP && ins.Args[0].Mem.Base != BP {
			continue
		}
		count++
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var stores strings.Builder
			for offset := 0; offset < 80; offset += 8 {
				fmt.Fprintf(&stores, "MOVQ $0,%d(SP)\n", offset)
			}
			if ins.Args[0].Mem.Base == BP {
				stores.WriteString("MOVQ SP,BP\nADDQ $48,BP\nMOVQ $0,SI\n")
			}
			pkg, request, _, options := fixedLocalFrameFixture(t, stores.String()+setup+instruction)
			original, err := os.ReadFile(filepath.Join(request.Directory, request.AssemblyFile))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("original=%q initializedCapturedSource=%q", instruction, original)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
				if err != nil {
					t.Fatalf("original SP operand %q lost captured initialized frame: %v", instruction, err)
				}
				x86ResultInitializationObject(t, llc, options.TargetTriple, ir, "frame")
			})
		})
	}
	if count != 6 {
		t.Fatal("original physical-SP source denominator changed", count)
	}
}

func TestX86Reciprocal14FixedLocalTypedRolesRetainAllInputsAndStorage(t *testing.T) {
	const frameBytes, vectorSeed = 320, 128
	var original strings.Builder
	for index, member := range x86Reciprocal14TestMembers {
		bank := "Z"
		if member.scalar {
			bank = "X"
		}
		instruction := x86Reciprocal14TestInstruction(member.op, "16(SP)", bank, "merge", member.scalar)
		_, setup := x86Reciprocal14OriginalRegisterInputs(t, instruction, true)
		var stores strings.Builder
		for offset := 0; offset < 80; offset += 8 {
			fmt.Fprintf(&stores, "MOVQ $0,%d(SP)\n", offset)
		}
		// Keep vector seeds independent of the numerical source tuple. Removing
		// a source byte must fail at RCP14, not at an earlier initializer load.
		for offset := vectorSeed; offset < vectorSeed+64; offset += 8 {
			fmt.Fprintf(&stores, "MOVQ $0,%d(SP)\n", offset)
		}
		setup = strings.ReplaceAll(setup, "VMOVUPS 0(SP),", fmt.Sprintf("VMOVUPS %d(SP),", vectorSeed))
		source, signature, _ := x86PrivateAlignedFrameAuditFixture(t, stores.String()+setup+instruction)
		source = strings.Replace(source, "$160-40", fmt.Sprintf("$%d-40", frameBytes), 1)
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		for _, mutation := range []string{"complete", "mask", "old destination", "upper source", "memory byte", "outside frame", "raw"} {
			if mutation == "upper source" && !member.scalar {
				continue
			}
			t.Run(member.op+"/"+mutation, func(t *testing.T) {
				candidate := source
				switch mutation {
				case "mask":
					candidate = strings.Replace(candidate, "KMOVQ AX,K1\n", "", 1)
				case "old destination":
					candidate = strings.Replace(candidate, fmt.Sprintf("VMOVUPS %d(SP),Z18\n", vectorSeed), "", 1)
				case "upper source":
					candidate = strings.Replace(candidate, fmt.Sprintf("VMOVUPS %d(SP),Z17\n", vectorSeed), "", 1)
				case "memory byte":
					candidate = strings.Replace(candidate, "MOVQ AX,16(SP)\n", "", 1)
					candidate = strings.Replace(candidate, "MOVQ $0,16(SP)\n", "", 1)
				case "outside frame":
					outside := strings.Replace(instruction, "16(SP)", fmt.Sprintf("%d(SP)", frameBytes+16), 1)
					candidate = strings.Replace(candidate, instruction, outside, 1)
				}
				if mutation != "complete" && mutation != "raw" && candidate == source {
					t.Fatal("negative source did not change", mutation)
				}
				file, err := Parse(ArchAMD64, candidate)
				if err != nil {
					t.Fatal(err)
				}
				if mutation == "raw" {
					for index := range file.Funcs[0].Instrs {
						if string(file.Funcs[0].Instrs[index].Op) == member.op {
							file.Funcs[0].Instrs[index].x86Encoded = true
						}
					}
				}
				_, err = proveX86FixedLocal(file.Funcs[0], signature)
				if mutation == "complete" {
					if err != nil {
						t.Fatal("complete typed reciprocal14 frame rejected", err)
					}
				} else if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("missing input or foreign memory role obtained a private certificate", mutation, err)
				}
				if mutation == "memory byte" && !strings.Contains(err.Error(), "undefined or relocated private bytes") {
					t.Fatal("isolated source byte did not reach the numerical memory read guard", err)
				}
				if mutation == "outside frame" && !strings.Contains(err.Error(), "access crosses storage") {
					t.Fatal("outside-frame source did not reach the actual storage bound", err)
				}
			})
		}
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
	for _, member := range x86FloatingHelperOracleMembers() {
		ins := x86ScalarLaneInstruction(t, x86FloatingHelperOracleInstruction(member, false))
		effect, known, err := x86TypedFloatingHelperByteEffect(ins.Op, ins, "amd64")
		if !known || err != nil || effect.vector.memoryAlignment != 0 {
			t.Fatal("reciprocal14 metadata widened another native helper's private storage role", member.name, err)
		}
	}
}
