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
	"strconv"
	"strings"
	"testing"
)

// Independent ISA/Go directory: every member takes exactly m128, four
// effective register sources and the old accumulator. SS reads only each
// source's low dword but preserves the old accumulator's other X bytes.
var x86FourSourceOracle = []struct {
	op                  string
	scalar, dot, negate bool
}{
	{"V4FMADDPS", false, false, false}, {"V4FMADDSS", true, false, false},
	{"V4FNMADDPS", false, false, true}, {"V4FNMADDSS", true, false, true},
	{"VP4DPWSSD", false, true, false}, {"VP4DPWSSDS", false, true, false},
}

type x86FourSourceOracleRow struct {
	op, mode        string
	first, dest     int
	scalar, dot     bool
	missing, unused string
}

func x86FourSourceOracleRows(arch string) []x86FourSourceOracleRow {
	var rows []x86FourSourceOracleRow
	for _, member := range x86FourSourceOracle {
		for _, first := range []int{0, 2} {
			for _, destination := range []int{0, 6} {
				for _, mode := range []string{"plain", "merge", "zero"} {
					if arch == "386" && mode != "plain" {
						continue // Go's named 386 frontend has a three-operand cap.
					}
					rows = append(rows, x86FourSourceOracleRow{
						op: member.op, scalar: member.scalar, dot: member.dot,
						first: first, dest: destination, mode: mode,
					})
				}
			}
		}
	}
	return rows
}

func (row x86FourSourceOracleRow) instruction() string {
	bank, op, mask := "Z", row.op, ""
	if row.scalar {
		bank = "X"
	}
	if row.mode != "plain" {
		mask = "K1,"
	}
	if row.mode == "zero" {
		op += ".Z"
	}
	return fmt.Sprintf("%s (BX),[%s%d-%s%d],%s%s%d", op, bank, row.first, bank, row.first+3, mask, bank, row.dest)
}

func x86FourSourceOriginalRuntimeUnchanged(t *testing.T) {
	t.Helper()
	x86FourSourceOriginalProgram(t)
}

// Historical whole-driver anchor was
// 8c732301b5e7ad3d1d5154236322b9f3939a347d1f05f0a01bed3ecf9b21d53d.
// Only the driver may migrate to explicit private mathematical instrumentation;
// these two unchanged original literals remain the active program contract.
func x86FourSourceOriginalProgram(t *testing.T) (string, string) {
	t.Helper()
	const name = "amd64_lower_four_source_test.go"
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	positions := token.NewFileSet()
	syntax, err := parser.ParseFile(positions, name, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestAMD64FourSourceRuntimeSemantics" {
			continue
		}
		program := make(map[string]string)
		for _, statement := range function.Body.List {
			declaration, ok := statement.(*ast.DeclStmt)
			if !ok {
				continue
			}
			constants, ok := declaration.Decl.(*ast.GenDecl)
			if !ok || constants.Tok != token.CONST {
				continue
			}
			for _, specification := range constants.Specs {
				value, ok := specification.(*ast.ValueSpec)
				if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
					continue
				}
				key := value.Names[0].Name
				if key != "source" && key != "mainC" {
					continue
				}
				literal, ok := value.Values[0].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING || program[key] != "" {
					t.Fatal("original four-source program lost its single actual source/C literal", key)
				}
				program[key], err = strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		for key, want := range map[string]string{
			"source": "c68bfc687ce73e04389fd0e3f57146554f85d3967d9c44c80ac6e1dbefbd5070",
			"mainC":  "44e5e74ea2f0f24009632362a848a5bc0e9f6c8002e04d8e4310a2f4270bc3a4",
		} {
			if fmt.Sprintf("%x", sha256.Sum256([]byte(program[key]))) != want {
				t.Fatal("the original complete ASM or independent C oracle changed", key)
			}
		}
		return program["source"], program["mainC"]
	}
	t.Fatal("the original complete four-source runtime program disappeared")
	return "", ""
}

func x86FourSourceInitializedSource(row x86FourSourceOracleRow, arch, name string, dead bool) (string, string) {
	word, move := goWordSize(arch), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	extent, extra := 4*word+8, ""
	if row.unused != "" {
		extent++
		extra = ",unused bool"
	}
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s input+%d(FP),SI\n%s old+%d(FP),CX\n",
		name, extent, move, move, word, move, 2*word)
	if row.missing == "numeric address" {
		source.WriteString("MOVL $42,BX\n")
	} else if row.missing != "address" {
		fmt.Fprintf(&source, "%s memory+%d(FP),BX\n", move, 3*word)
	}
	base := row.first &^ 3
	for register := 0; register < 4; register++ {
		if row.missing != fmt.Sprint("source", register) {
			fmt.Fprintf(&source, "VMOVUPS %d(SI),Z%d\n", 64*register, base+register)
		}
	}
	if (row.dest < base || row.dest >= base+4) && row.missing != "old" {
		fmt.Fprintf(&source, "VMOVUPS (CX),Z%d\n", row.dest)
	}
	if row.missing != "mask" {
		fmt.Fprintf(&source, "KMOVQ mask+%d(FP),K1\n", 4*word)
	}
	source.WriteString("STC\n" + row.instruction() + "\n")
	if !dead {
		// Full Z observation checks scalar upper-X preservation and EVEX
		// zeroing above X, not only the computed low scalar lane.
		fmt.Fprintf(&source, "VMOVUPS Z%d,(DI)\n", row.dest)
	}
	source.WriteString("SETCS 64(DI)\nRET\n")
	return source.String(), fmt.Sprintf("func %s(out *[80]byte,input *[256]byte,old *[64]byte,memory *[16]byte,mask uint64%s)\n", name, extra)
}

func TestX86FourSourceIndependentNamedDirectoryAndGoBytes(t *testing.T) {
	x86FourSourceOriginalRuntimeUnchanged(t)
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			rows := x86FourSourceOracleRows(arch)
			want := 72
			if arch == "386" {
				want = 24
			}
			if len(rows) != want {
				t.Fatal("independent complete mode/mask/alias directory changed", len(rows))
			}
			var body strings.Builder
			for _, row := range rows {
				body.WriteString(row.instruction() + "\n")
			}
			code, pcs := x86NumericalBoundaryGoBytes(t, arch, body.String()+"RET")
			if len(pcs) != len(rows)+1 || len(code) == 0 || code[len(code)-1] != 0xc3 {
				t.Fatal("the independent original Go opcode/PC directory is incomplete")
			}
			for index, row := range rows {
				instruction := code[pcs[index]:pcs[index+1]]
				opcode := map[string]byte{"V4FMADDPS": 0x9a, "V4FMADDSS": 0x9b, "V4FNMADDPS": 0xaa,
					"V4FNMADDSS": 0xab, "VP4DPWSSD": 0x52, "VP4DPWSSDS": 0x53}[row.op]
				if len(instruction) != 6 || instruction[0] != 0x62 || instruction[1] != 0xf2 || instruction[4] != opcode ||
					instruction[5] != byte(row.dest<<3)|3 {
					t.Fatal("Go bytes disagree with the independent EVEX memory/ModRM row", row.instruction(), instruction)
				}
			}
		})
	}
}

func TestX86FourSourceCompleteTypedImplicitReadAndWriteRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86FourSourceOracleRows(arch) {
			t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction())
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || !effect.requiresResultProof || effect.dynamicMemory ||
					effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 {
					t.Fatal("the complete typed family is missing actual input and accumulator obligations", effect, known, err)
				}
				memory, old, mask := 0, 0, 0
				sources := make(map[Reg]int64)
				for _, operand := range effect.operands {
					switch operand.index {
					case 0:
						if !operand.read || operand.write || operand.width != 16 || !reflect.DeepEqual(operand.operand, ins.Args[0]) {
							t.Fatal("four-source memory is one complete m128, not a selected dword or vector envelope", operand)
						}
						memory++
					case 1:
						if operand.operand.Kind != OpReg || !operand.read || operand.write {
							t.Fatal("effective aligned source block must expose each actual implicit register", operand)
						}
						sources[operand.operand.Reg] = operand.width
					default:
						if operand.index == len(ins.Args)-1 {
							width := int64(64)
							if row.scalar {
								width = 16
							}
							if !operand.read || !operand.write || operand.width != width {
								t.Fatal("the old accumulator is read even for .Z, with scalar upper-X preservation", operand)
							}
							old++
						} else if len(ins.Args) == 4 && operand.index == 2 {
							if !operand.read || operand.write || operand.width != 8 || operand.operand.Reg != "K1" {
								t.Fatal("masked four-source lost its actual K input", operand)
							}
							mask++
						} else {
							t.Fatal("unobserved operand role", operand)
						}
					}
				}
				bank, width := "Z", int64(64)
				if row.scalar {
					bank, width = "X", 4
				}
				wantSources := make(map[Reg]int64)
				for register := 0; register < 4; register++ {
					wantSources[Reg(fmt.Sprintf("%s%d", bank, register))] = width
				}
				wantMask := 0
				if row.mode != "plain" {
					wantMask = 1
				}
				if memory != 1 || old != 1 || mask != wantMask || !reflect.DeepEqual(sources, wantSources) {
					t.Fatal("encoded [2-5] must read the aligned [0-3] block without manufacturing bytes", memory, old, mask, sources)
				}
			})
		}
	}
}

func TestX86FourSourceInitializedWholeObjectsFiveTargets(t *testing.T) {
	x86FourSourceOriginalRuntimeUnchanged(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete four-source objects require exact LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			rows := x86FourSourceOracleRows(target.arch)
			for start := 0; start < len(rows); start += 24 {
				end := start + 24
				if end > len(rows) {
					end = len(rows)
				}
				t.Run(fmt.Sprintf("batch_%02d_%02d", start, end), func(t *testing.T) {
					var source, declarations strings.Builder
					for index := start; index < end; index++ {
						body, declaration := x86FourSourceInitializedSource(rows[index], target.arch, fmt.Sprint("Four", index), false)
						source.WriteString(body)
						declarations.WriteString(declaration)
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("a fully initialized complete four-source program lost its native input/result handoff", err)
							}
							for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
								compileLLVMToObject(t, llc, target.triple, "four-source-complete.ll", "four-source-complete.o", body)
							}
						})
					}
				})
			}
		})
	}
}

func TestX86FourSourceVoidStillOwnsItsTypedInputObligation(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, member := range x86FourSourceOracle {
			for _, unused := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/unused=%t", arch, member.op, unused), func(t *testing.T) {
					declaration := "func Value()"
					if unused {
						declaration = "func Value(unused bool)"
					}
					row := x86FourSourceOracleRow{op: member.op, scalar: member.scalar, dot: member.dot, first: 2, dest: 6, mode: "plain"}
					_, file, signature, source := x86ResultInitializationFixture(t, arch, declaration, row.instruction()+"\nRET\n")
					goAssemblerOracleOutput(t, arch, source, "", true)
					if !x86TypedFPResultNeedsProof(file.Funcs[0], signature, arch) {
						t.Fatal("Void or an unused canonical bool bypassed the complete instruction's input obligations")
					}
				})
			}
		}
	}
}

func TestX86FourSourceInitializedDeadVoidAndUnusedBool(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			for index, member := range x86FourSourceOracle {
				for _, unused := range []string{"", "bool"} {
					mode := "plain"
					if target.arch == "amd64" {
						mode = "zero"
					}
					row := x86FourSourceOracleRow{op: member.op, scalar: member.scalar, dot: member.dot,
						first: 2, dest: 6, mode: mode, unused: unused}
					body, declaration := x86FourSourceInitializedSource(row, target.arch, fmt.Sprintf("Dead%d%s", index, unused), true)
					source.WriteString(body)
					declarations.WriteString(declaration)
				}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized dead four-source instructions lost their actual inputs or cache/fault/MXCSR obligation", err)
					}
				})
			}
		})
	}
}

func TestX86FourSourceMissingActualInputsRemainContext(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, member := range x86FourSourceOracle {
			for _, missing := range []string{"source0", "source1", "source2", "source3", "old", "address", "numeric address", "mask"} {
				if arch == "386" && missing == "mask" {
					continue
				}
				t.Run(arch+"/"+member.op+"/"+missing, func(t *testing.T) {
					mode := "plain"
					if arch == "amd64" {
						mode = "zero"
					}
					row := x86FourSourceOracleRow{op: member.op, scalar: member.scalar, dot: member.dot,
						mode: mode, first: 2, dest: 6, missing: missing, unused: "bool"}
					source, declaration := x86FourSourceInitializedSource(row, arch, "Missing", false)
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("actual aligned-block/old/mask/native-address input was manufactured", api, err)
						}
					}
				})
			}
		}
	}
}
