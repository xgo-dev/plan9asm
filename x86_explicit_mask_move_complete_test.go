package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type x86ExplicitMaskMoveCase struct {
	name, instruction, bank string
	width, memory           int
}

func x86ExplicitMaskMoveIndependentCases() []x86ExplicitMaskMoveCase {
	var rows []x86ExplicitMaskMoveCase
	for _, op := range []string{"VMASKMOVPS", "VMASKMOVPD", "VPMASKMOVD", "VPMASKMOVQ"} {
		for _, width := range []int{16, 32} {
			bank := map[int]string{16: "X", 32: "Y"}[width]
			rows = append(rows,
				x86ExplicitMaskMoveCase{op + bank + "Load", op + " (AX)," + bank + "1," + bank + "2", bank, width, 0},
				x86ExplicitMaskMoveCase{op + bank + "Store", op + " " + bank + "0," + bank + "1,(AX)", bank, width, 2})
		}
	}
	return rows
}

func x86ExplicitMaskMoveOriginalRuntime(t *testing.T) string {
	t.Helper()
	const filename = "amd64_lower_explicit_mask_move_test.go"
	file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"source": "5aa75bf5b240d6245928cc4293d73076be1a04d00ff8da5beed3a8a1dc63d1f7",
		"mainC":  "381c4b7d0024fc557edd21dcb0a5758516898dd25b001583bf322fd11544db63",
	}
	source, owners := "", 0
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestAMD64ExplicitMaskMoveRuntimeSemantics" {
			continue
		}
		owners++
		ast.Inspect(function.Body, func(node ast.Node) bool {
			value, ok := node.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
				return true
			}
			name := value.Names[0].Name
			expected, found := want[name]
			if !found {
				return true
			}
			literal, ok := value.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatal("original explicit mask move reference lost its exact literal", name)
			}
			text, err := strconv.Unquote(literal.Value)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256([]byte(text))) != expected {
				t.Fatal("original complete explicit mask move ASM/C changed", name, err)
			}
			if name == "source" {
				source = text
			}
			delete(want, name)
			return true
		})
	}
	if owners != 1 || len(want) != 0 || source == "" {
		t.Fatal("missing or duplicate original complete explicit mask move runtime")
	}
	return source
}

func TestX86ExplicitMaskMoveOriginalInitializedSourceThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("original explicit mask move objects require LLVM22 llc")
	}
	source := x86ExplicitMaskMoveOriginalRuntime(t)
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source,
						"func explicitmaskmovesemantics(out,loadmem,data,mask,storemem *byte)", "amd64", triple, api)
					if err != nil || ir == "" {
						t.Fatal("actual initialized original mask/data/pointer inputs lost the complete family consumer", err)
					}
					for _, pipeline := range []struct{ ir, level string }{
						{ir, "-O0"}, {ir, "-O2"}, {x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						x86PackedStringCompileObject(t, llc, triple, pipeline.ir, pipeline.level)
					}
				})
			}
		})
	}
}

func TestX86ExplicitMaskMoveCompleteTypedEffectsAndSDKWidths(t *testing.T) {
	rows := x86ExplicitMaskMoveIndependentCases()
	if len(rows) != 16 {
		t.Fatal("incomplete four-member X/Y load/store family", len(rows))
	}
	for _, arch := range []string{"386", "amd64"} {
		var source strings.Builder
		source.WriteString("TEXT Forms(SB),4,$0-0\n")
		for _, row := range rows {
			source.WriteString(row.instruction + "\n")
		}
		source.WriteString("RET\n")
		requireX86GoAssemblerResult(t, arch, source.String(), true)
		for _, row := range rows {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction)
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				want := []x86TypedByteOperand{
					{index: 0, operand: ins.Args[0], width: int64(row.width), read: true},
					{index: 1, operand: ins.Args[1], width: int64(row.width), read: true},
					{index: 2, operand: ins.Args[2], width: int64(row.width), write: true},
				}
				if !known || err != nil || !effect.requiresResultProof || !reflect.DeepEqual(effect.operands, want) ||
					effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 || effect.dynamicMemory {
					t.Fatal("complete explicit mask family lacks its typed numerical/memory/FLAGS roles", known, err)
				}
				if !x86CallerVectorMoveKnown(ins) {
					t.Fatal("caller shape diverged from the complete explicit mask grammar")
				}
				ins.Args = append([]Operand(nil), ins.Args...)
				ins.Args[row.memory] = Operand{Kind: OpFP}
				width, write, valid := X86FPAccessBytes(ins, row.memory, arch)
				if !valid || width != int64(row.width) || write != (row.memory == 2) {
					t.Fatal("SDK width observer lost the complete possible native tuple", width, write, valid)
				}
			})
		}
	}
}

func TestX86ExplicitMaskMoveDeadEntriesCannotBorrowImplementationZeros(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := map[string]string{"386": "i386-unknown-linux-gnu", "amd64": "x86_64-unknown-linux-gnu"}[arch]
		for _, row := range x86ExplicitMaskMoveIndependentCases() {
			for _, unusedBool := range []bool{false, true} {
				declaration, extent := "func Unbound()", 0
				if unusedBool {
					declaration, extent = "func Unbound(unused bool)", 1
				}
				source := fmt.Sprintf("TEXT ·Unbound(SB),4,$0-%d\n%s\nRET\n", extent, row.instruction)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/unusedBool%t/%s", arch, row.name, unusedBool, api), func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("Void/unused bool invented mask, address or stored data bytes", err)
						}
					})
				}
			}
		}
	}
}

func TestX86ExplicitMaskMoveInitializedCompleteFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete explicit mask move objects require LLVM22 llc")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move := 8, "MOVQ"
			if target.arch == "386" {
				word, move = 4, "MOVL"
			}
			var source, declarations strings.Builder
			for _, row := range x86ExplicitMaskMoveIndependentCases() {
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),AX\n%s data+%d(FP),BX\n"+
					"%s mask+%d(FP),CX\n%s out+%d(FP),DX\nVMOVDQU (BX),%s0\nVMOVDQU (CX),%s1\nSTC\n%s\n",
					row.name, 4*word, move, move, word, move, 2*word, move, 3*word, row.bank, row.bank, row.instruction)
				if row.memory == 0 {
					fmt.Fprintf(&source, "VMOVDQU %s2,(DX)\n", row.bank)
				}
				fmt.Fprintf(&source, "SETCS %d(DX)\nRET\n", row.width)
				fmt.Fprintf(&declarations, "func %s(p,data,mask,out *byte)\n", row.name)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete initialized explicit mask grammar lost its public NUM/native consumer", err)
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

func TestX86ExplicitMaskMoveKeepsWholeNativeMemoryOpcodeWhenDead(t *testing.T) {
	for _, row := range x86ExplicitMaskMoveIndependentCases() {
		t.Run(row.name, func(t *testing.T) {
			source := fmt.Sprintf("TEXT Dead(SB),4,$0-24\nMOVQ p+0(FP),AX\nMOVQ mask+8(FP),BX\n"+
				"MOVQ data+16(FP),CX\nVMOVDQU (BX),%s1\nVMOVDQU (CX),%s0\n%s\nRET\n", row.bank, row.bank, row.instruction)
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
			file := mustParseX86RawReturn(t, source)
			sig := FuncSig{Name: "Dead", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}}}
			// Independent emitter evidence, not a public-entry or executed
			// fault claim. The public original/initialized owners above are separate.
			ir := x86ScalarFormatObjectUnit(t, file, map[string]FuncSig{"Dead": sig}, "amd64", "x86_64-unknown-linux-gnu", 0)
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				at := strings.Index(text, "@InstructionFormat0(")
				if at < 0 {
					t.Fatal("missing independent original instruction body")
				}
				body := strings.SplitN(text[at:], "\n}", 2)[0]
				opcode := strings.ToLower(strings.Fields(row.instruction)[0]) + " "
				if !strings.Contains(body, "asm sideeffect") || !strings.Contains(body, opcode) || !strings.Contains(body, "~{memory}") {
					t.Fatal("dead mask move lost its exact original native access/fault effect", row.name)
				}
			}
		})
	}
}
