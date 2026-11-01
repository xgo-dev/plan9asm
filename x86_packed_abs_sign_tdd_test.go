package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"
)

type x86PackedAbsSignOracleRow struct {
	op, bank, mode, source string
	bits, width            int
	sign, legacy, memory   bool
}

// Independent of the emitter: legacy six X-only names, three VEX sign
// names, and four ABS names with their full EVEX width/mask/broadcast axes.
// Intel's NP MMX encodings are not Go's yxm_q4 named grammar.
func x86PackedAbsSignOracleRows() []x86PackedAbsSignOracleRow {
	var rows []x86PackedAbsSignOracleRow
	for _, sign := range []bool{false, true} {
		stem := "PABS"
		if sign {
			stem = "PSIGN"
		}
		for index, suffix := range []string{"B", "W", "D"} {
			for _, memory := range []bool{false, true} {
				rows = append(rows, x86PackedAbsSignOracleRow{op: stem + suffix, bank: "X", bits: 8 << index,
					width: 16, legacy: true, sign: sign, memory: memory})
			}
		}
	}
	for index, suffix := range []string{"B", "W", "D", "Q"} {
		for at, bank := range []string{"X", "Y", "Z"} {
			for _, mode := range []string{"plain", "merge", "zero"} {
				for _, source := range []string{"register", "memory", "broadcast"} {
					if source == "broadcast" && index < 2 {
						continue
					}
					rows = append(rows, x86PackedAbsSignOracleRow{op: "VPABS" + suffix, bank: bank, bits: 8 << index,
						width: 16 << at, mode: mode, source: source, memory: source != "register"})
				}
			}
		}
	}
	for index, suffix := range []string{"B", "W", "D"} {
		for at, bank := range []string{"X", "Y"} {
			for _, memory := range []bool{false, true} {
				rows = append(rows, x86PackedAbsSignOracleRow{op: "VPSIGN" + suffix, bank: bank, bits: 8 << index,
					width: 16 << at, sign: true, memory: memory})
			}
		}
	}
	return rows
}

func (row x86PackedAbsSignOracleRow) instruction() string {
	op, source, mask := row.op, row.bank+"0", ""
	if row.sign {
		source = row.bank + "1"
	}
	if row.memory {
		source = "(AX)"
		if row.sign {
			source = "(BX)"
		}
	}
	if row.source == "broadcast" {
		op += ".BCST"
	}
	if row.mode == "merge" || row.mode == "zero" {
		mask = ",K1"
	}
	if row.mode == "zero" {
		op += ".Z"
	}
	if row.sign && !row.legacy {
		return fmt.Sprintf("%s %s,%s0,%s2", op, source, row.bank, row.bank)
	}
	return fmt.Sprintf("%s %s%s,%s2", op, source, mask, row.bank)
}

func x86PackedAbsSignOriginalProgramUnchanged(t *testing.T) {
	t.Helper()
	file := "amd64_lower_abs_sign_test.go"
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	set := token.NewFileSet()
	syntax, err := parser.ParseFile(set, file, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range syntax.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "TestAMD64PackedAbsSignRuntimeSemantics" {
			start, end := set.Position(function.Pos()).Offset, set.Position(function.End()).Offset
			// Exclude only the independently audited execution preflight. The
			// original ASM, C, inputs and every other driver statement retain
			// their unchanged fingerprint and separate literal-level pins.
			original := strings.Replace(string(data[start:end]),
				"\tx86OriginalFloatingRuntimeRequireCPU(t, \"packed-abs-sign\", clang, triple, runPrefix)\n", "", 1)
			if fmt.Sprintf("%x", sha256.Sum256([]byte(original))) != "2f3f1858c33eaac4ffc0d298859629e18716b06fbec597aa2a84587d27cf9ed3" {
				t.Fatal("original initialized ABS/sign source, C oracle or observations changed")
			}
			return
		}
	}
	t.Fatal("original packed ABS/sign runtime root disappeared")
}

func TestX86PackedAbsSignCompleteTypedOperandRoles(t *testing.T) {
	x86PackedAbsSignOriginalProgramUnchanged(t)
	rows := x86PackedAbsSignOracleRows()
	if len(rows) != 114 {
		t.Fatal("complete independent ABS/sign physical source directory changed", len(rows))
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range rows {
			t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction())
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || !effect.requiresResultProof || effect.dynamicMemory ||
					effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 {
					t.Fatal("complete ABS/sign family lacks typed data/mask/write effects", effect, known, err)
				}
				reads, writes := make(map[int]bool), make(map[int]bool)
				for _, operand := range effect.operands {
					width := row.width
					if operand.index == 0 && row.source == "broadcast" {
						width = row.bits / 8
					}
					if operand.operand.Kind == OpReg && operand.operand.Reg == "K1" {
						width = 8
					}
					if operand.index < 0 || operand.index >= len(ins.Args) || operand.width != int64(width) ||
						!reflect.DeepEqual(operand.operand, ins.Args[operand.index]) {
						t.Fatal("typed family confused scalar tuple, vector or K width", operand)
					}
					reads[operand.index] = reads[operand.index] || operand.read
					writes[operand.index] = writes[operand.index] || operand.write
				}
				last := len(ins.Args) - 1
				for index := range ins.Args {
					wantRead := index == 0 || row.sign && index == 1 ||
						row.mode == "merge" || row.mode == "zero" && index == 1
					if reads[index] != wantRead || writes[index] != (index == last) {
						t.Fatal("write-only ABS, PSIGN data, merging old destination or mask dependency changed", index, reads, writes)
					}
				}
			})
		}
	}
}

func TestX86PackedAbsSignUnknownBytesAliasesAndUnchangedState(t *testing.T) {
	for _, row := range x86PackedAbsSignOracleRows() {
		if row.memory {
			continue
		}
		for _, arch := range []string{"amd64", "386"} {
			t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
				original := x86ScalarLaneInstruction(t, row.instruction())
				for _, alias := range []bool{false, true} {
					ins := original
					ins.Args = append([]Operand(nil), original.Args...)
					if alias {
						ins.Args[0] = ins.Args[len(ins.Args)-1]
					}
					for register := 0; register < 3; register++ {
						for missing := -1; missing < 64; missing++ {
							state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward, masks: [8]bool{1: true}}
							for index := 0; index < 3; index++ {
								state.writeVector(index, 64, ^uint64(0), true)
							}
							state.pointerGP[5], state.callerAddressGP[6] = true, true
							if missing >= 0 {
								state.writeVector(register, 64, ^(uint64(1) << uint(missing)), true)
							}
							before := state.clone()
							if !x86ResultTransfer(ins, &state, nil, 0, arch) {
								t.Fatal("nontrapping unknown dead packed data was rejected instead of remaining unknown", alias, register, missing)
							}
							input := register == 0 && !row.sign || row.sign && register == 1 ||
								row.sign && register == 0 && !row.legacy || row.sign && register == 2 && row.legacy ||
								row.mode == "merge" && register == 2
							if alias {
								input = register == 2 || row.sign && !row.legacy && register == 0
							}
							if missing < 0 && state.vectorBytes(2) != ^uint64(0) ||
								input && missing >= 0 && missing < row.width && state.vectorBytes(2)&(uint64(1)<<uint(missing)) != 0 {
								t.Fatal("computed output invented an unknown input byte", alias, register, missing)
							}
							if row.legacy && state.vectorBytes(2)&^uint64(0xffff) != before.vectorBytes(2)&^uint64(0xffff) ||
								!row.legacy && state.vectorBytes(2)&^x86CallerVectorByteMask(int64(row.width)) != ^x86CallerVectorByteMask(int64(row.width)) ||
								state.flags != before.flags || state.direction != before.direction || state.pointerGP != before.pointerGP ||
								state.callerAddressGP != before.callerAddressGP || state.masks != before.masks {
								t.Fatal("ABS/sign altered unrelated FLAGS/DF/pointers/masks or upper aliases")
							}
							for index := 0; index < 2; index++ {
								if state.vectorBytes(index) != before.vectorBytes(index) {
									t.Fatal("ABS/sign wrote a nondestination register")
								}
							}
						}
					}
				}
			})
		}
	}
}

func x86PackedAbsSignInitializedSource(index int, row x86PackedAbsSignOracleRow, arch string) (string, string) {
	return x86PackedAbsSignInitializedInstruction(index, row.instruction(), arch, [3]int{0, 1, 2})
}

func x86PackedAbsSignInitializedInstruction(index int, instruction, arch string, registers [3]int) (string, string) {
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	name := fmt.Sprint("AbsSign", index)
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s input+%d(FP),AX\n%s control+%d(FP),BX\n%s old+%d(FP),CX\n"+
		"VMOVDQU64 (AX),Z%d\nVMOVDQU64 (BX),Z%d\nVMOVDQU64 (CX),Z%d\nKMOVQ mask+%d(FP),K1\nSTC\n%s\nVMOVDQU64 Z%d,(DI)\nSETCS 64(DI)\nRET\n",
		name, 4*word+8, move, move, word, move, 2*word, move, 3*word,
		registers[0], registers[1], registers[2], 4*word, instruction, registers[2])
	return source, fmt.Sprintf("func %s(out *[80]byte,input,control,old *[64]byte,mask uint64)\n", name)
}

func TestX86PackedAbsSignInitializedObjectsThreeAPIsFiveTargets(t *testing.T) {
	x86PackedAbsSignOriginalProgramUnchanged(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete ABS/sign original objects require LLVM22")
	}
	rows := x86PackedAbsSignOracleRows()
	for _, target := range x86RawReturnTargets {
		for start := 0; start < len(rows); start += 48 {
			end := start + 48
			if end > len(rows) {
				end = len(rows)
			}
			t.Run(fmt.Sprintf("%s/%d-%d", target.triple, start, end), func(t *testing.T) {
				var source, declarations strings.Builder
				for index := start; index < end; index++ {
					body, declaration := x86PackedAbsSignInitializedSource(index, rows[index], target.arch)
					source.WriteString(body)
					declarations.WriteString(declaration)
				}
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
						if err != nil {
							t.Fatal("complete initialized ABS/sign family rejected", err)
						}
						for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							compileLLVMToObject(t, llc, target.triple, "abs-sign-complete.ll", "abs-sign-complete.o", body)
						}
					})
				}
			})
		}
	}
}

func TestX86PackedAbsSignMaskNativeAndMMXBoundaries(t *testing.T) {
	for _, row := range x86PackedAbsSignOracleRows() {
		if !row.memory && row.mode != "merge" && row.mode != "zero" {
			continue
		}
		for _, unusedBool := range []bool{false, true} {
			extent, declaration := 0, "func Missing()"
			if unusedBool {
				extent, declaration = 1, "func Missing(unused bool)"
			}
			source := fmt.Sprintf("TEXT ·Missing(SB),4,$0-%d\n%s\nRET\n", extent, row.instruction())
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("dead/Void source invented its missing native address or K input", row.instruction(), unusedBool, api)
				}
			}
		}
	}
	for _, op := range []string{"PABSB", "PABSW", "PABSD", "PSIGNB", "PSIGNW", "PSIGND"} {
		// Intel's NP form is MMX, but Go's only named legacy row is XMM.
		goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+op+" M0,M1\nRET\n", "", false)
		ins := x86ScalarLaneInstruction(t, op+" M0,M1")
		state := x86ResultState{nativeMMX: [8]uint8{0: 0xff, 1: 0xff}, flags: x86ByteFlagsAll}
		before := state.clone()
		if x86ResultTransfer(ins, &state, nil, 0, "amd64") || !reflect.DeepEqual(state, before) {
			t.Fatal("named XMM family borrowed independent physical MMX/x87 state", op)
		}
	}
}
