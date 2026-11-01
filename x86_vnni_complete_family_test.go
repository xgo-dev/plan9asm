package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Independent Go/Intel integer directory. BF16 has different arithmetic,
// native requirements and exceptions and must not inherit these rules.
var x86VNNIIntegerMembers = []struct {
	op     string
	opcode byte
}{{"VPDPBUSD", 0x50}, {"VPDPBUSDS", 0x51}, {"VPDPWSSD", 0x52}, {"VPDPWSSDS", 0x53}}

type x86VNNIOracleRow struct {
	op, bank, input, mode string
}

func x86VNNIOracleRows(arch string) []x86VNNIOracleRow {
	var rows []x86VNNIOracleRow
	for _, member := range x86VNNIIntegerMembers {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, input := range []string{"register", "full", "broadcast"} {
				for _, mode := range []string{"plain", "merge", "zero"} {
					if arch != "386" || mode == "plain" {
						rows = append(rows, x86VNNIOracleRow{member.op, bank, input, mode})
					}
				}
			}
		}
	}
	return rows
}

func (row x86VNNIOracleRow) instruction() string {
	op, first, mask := row.op, row.bank+"2", ""
	if row.input != "register" {
		first = "(AX)"
	}
	if row.input == "broadcast" {
		op += ".BCST"
	}
	if row.mode != "plain" {
		mask = "K1,"
	}
	if row.mode == "zero" {
		op += ".Z"
	}
	return op + " " + first + "," + row.bank + "1," + mask + row.bank + "0"
}

func TestX86VNNIIntegerEveryInputByteAccumulatorAndState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86VNNIOracleRows(arch) {
			if row.input != "register" {
				continue // Native memory has its separately paired source owner.
			}
			t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction())
				width := amd64VectorByteWidth(Reg(row.bank + "0"))
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || !effect.requiresResultProof || effect.flagsRead != 0 || effect.flagsDefined != 0 || effect.flagsKilled != 0 {
					t.Fatal("integer dot product lost its complete typed input/FLAGS owner", known, err)
				}
				destination := len(ins.Args) - 1
				seen := make(map[int]bool)
				for _, operand := range effect.operands {
					wantWidth := int64(width)
					if operand.index == 2 && destination == 3 {
						wantWidth = 8
					}
					if seen[operand.index] || operand.index < 0 || operand.index > destination ||
						!reflect.DeepEqual(operand.operand, ins.Args[operand.index]) ||
						!operand.read || operand.write != (operand.index == destination) || operand.width != wantWidth {
						t.Fatal("typed byte roles lost an input, old accumulator or exact physical width", operand)
					}
					seen[operand.index] = true
				}
				if len(seen) != len(ins.Args) {
					t.Fatal("typed byte roles omitted an arithmetic or mask input")
				}
				for _, result := range []LLVMType{Void, I32} {
					if !x86TypedFPResultNeedsProof(Func{Instrs: []Instr{ins}}, FuncSig{Ret: result}, arch) {
						t.Fatal("Void or absent result layout waived the integer-dot inputs", result)
					}
				}
				for input := 0; input < 3; input++ {
					for missing := -1; missing < 64; missing++ {
						state := x86FMA3ResultInputState()
						if missing >= 0 {
							state.writeVector(input, 64, state.vectorBytes(input)&^(uint64(1)<<uint(missing)), false)
						}
						before := state.clone()
						// Every corresponding four source bytes (or two words)
						// and every old dword are needed, even with EVEX.z.
						// Use the same complete active-input boundary for direct
						// and whole-source observers, including Void programs.
						want := missing < 0 || missing >= width
						if want {
							before.writeVector(0, width, x86CallerVectorByteMask(int64(width)), false)
						}
						if accepted := x86ScalarFPResultTransfer(ins, &state, nil, 0, arch); accepted != want || !reflect.DeepEqual(state, before) {
							t.Fatal("integer dot product borrowed an active input or changed aliases/FLAGS/DF/pointer state", input, missing, accepted, want)
						}
					}
				}
				if row.mode != "plain" {
					state := x86FMA3ResultInputState()
					state.masks[1] = false
					before := state.clone()
					if x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
						t.Fatal("an absent mask changed the numerical state")
					}
				}
			})
		}
	}
}

func x86VNNIOriginalConformance(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/conformance/amd64/conformance_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(data), "TEXT ·packedDotProductSemantics(SB)")
	if start < 0 {
		t.Fatal("original complete integer-dot conformance entry disappeared")
	}
	end := strings.Index(string(data[start:]), "\n// packedIntegerMinMaxSemantics")
	if end < 0 {
		t.Fatal("original integer-dot source boundary disappeared")
	}
	body := string(data[start : start+end])
	if fmt.Sprintf("%x", sha256.Sum256([]byte(body))) != "4096e21a32435046699e0e1a02379246b7ba6e1be681f8868515e838e511b410" {
		t.Fatal("original complete six-pointer ASM program changed")
	}
	data, err = os.ReadFile("amd64_conformance_test.go")
	if err != nil {
		t.Fatal(err)
	}
	function, err := x86SegmentMOVSourceFunction(data, "amd64ConformanceRuntimeC")
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(function)) != "41b0fc284d1aea9a9d24d613f84a6f4ad416d25a84dfa9664f81c7f1a9eef1b4" {
		t.Fatal("original whole C reference/observations changed", err)
	}
	return "#include \"textflag.h\"\n" + body
}

func TestX86VNNIIntegerOriginalInitializedConformanceObjects(t *testing.T) {
	source := x86VNNIOriginalConformance(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue // Preserve the real original MOVQ ABI0 program, not a rewritten mode32 source.
		}
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source,
						"func packedDotProductSemantics(out,signedBytes,unsignedBytes,wordsA,wordsB,accumulator *byte)",
						target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("original complete initialized integer-dot program lost its public owner", err)
					}
					for _, pipeline := range []struct{ ir, level string }{
						{ir, "-O0"}, {ir, "-O2"}, {x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						x86PackedStringCompileObject(t, llc, target.triple, pipeline.ir, pipeline.level)
					}
				})
			}
		})
	}
}

func (row x86VNNIOracleRow) program(arch, name string) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s a+%d(FP),AX\n%s b+%d(FP),BX\n%s old+%d(FP),CX\n"+
		"VMOVUPS (AX),Z2\nVMOVUPS (BX),Z1\nVMOVUPS (CX),Z0\nKMOVQ mask+%d(FP),K1\n%s\nVMOVUPS Z0,(DI)\nRET\n",
		name, 4*word+8, move, move, word, move, 2*word, move, 3*word, 4*word, row.instruction())
	return source, "func " + name + "(out,a,b,old *byte,mask uint64)\n"
}

func TestX86VNNIIntegerVoidAndMissingNativeInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := testTargetTriple("linux", arch)
		for _, member := range x86VNNIIntegerMembers {
			for _, unused := range []bool{false, true} {
				size, declaration := 0, "func Missing()"
				if unused {
					size, declaration = 1, "func Missing(unused bool)"
				}
				source := fmt.Sprintf("TEXT ·Missing(SB),4,$0-%d\n%s X2,X1,X0\nRET\n", size, member.op)
				x86LEAActualTargetGoObject(t, arch, triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/unused=%t/%s", arch, member.op, unused, api), func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("Void or unused bool supplied missing dot-product sources/accumulator", ir != "", err)
						}
					})
				}
			}
		}
	}
}
