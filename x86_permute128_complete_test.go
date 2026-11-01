package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Go's _yvperm2f128 has one row per member. Intel SDM Vol.2C 5-494..497
// requires VEX.256.66.0F3A.W0: W1/L0, EVEX, X/Z and masks are not forms.
var x86Permute128Members = []struct {
	op     string
	opcode byte
}{{"VPERM2F128", 0x06}, {"VPERM2I128", 0x46}}

func TestX86Permute128IndependentGoRowsAndAllSelectorBytes(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var source strings.Builder
	var expected []byte
	for _, member := range x86Permute128Members {
		count := 0
		for _, rule := range rules {
			if rule.Opcode != member.op {
				continue
			}
			if rule.RowIndex != 0 || rule.Ytab != "_yvperm2f128" || rule.Prefix != "Pavx" ||
				rule.ZCase != "Zvex_i_rm_v_r" || rule.ZOffset != 2 || rule.EncodingOffset != 0 ||
				strings.Join(rule.Classes, ",") != "Yu8,Yym,Yyr,Yyr" ||
				!reflect.DeepEqual(rule.OpBytes, []string{"avxEscape | vex256 | vex66 | vex0F3A | vexW0", fmt.Sprintf("0x%02X", member.opcode)}) {
				t.Fatal("complete independent Go row/encoding changed", rule)
			}
			count++
		}
		if count != 1 {
			t.Fatal("official permute128 encoder-row denominator changed", member.op, count)
		}
		for immediate := 0; immediate < 256; immediate++ {
			for _, memory := range []bool{false, true} {
				operand, modrm := "Y0", byte(0xd0)
				if memory {
					operand, modrm = "(AX)", 0x10
				}
				fmt.Fprintf(&source, "%s $%d,%s,Y1,Y2\n", member.op, immediate, operand)
				expected = append(expected, 0xc4, 0xe3, 0x75, member.opcode, modrm, byte(immediate))
			}
		}
	}
	actual, pcs := x86NumericalBoundaryGoBytes(t, "amd64", source.String()+"RET")
	expected = append(expected, 0xc3)
	if len(pcs) != 1025 || !bytes.Equal(actual, expected) {
		t.Fatal("actual Go bytes lost a member, r/m form or original imm8 bit", len(pcs), len(actual))
	}
}

// Plan9 source one is Intel SRC2; source two is Intel SRC1. Each selected
// output half copies exactly sixteen bytes. Bits 2/6 are ignored, 3/7 zero.
func x86Permute128RequiredBytes(immediate int) [2]uint64 {
	var inputs [2]uint64
	for output := 0; output < 2; output++ {
		if immediate&(8<<uint(output*4)) != 0 {
			continue
		}
		selected := immediate >> uint(output*4) & 3
		source := 1
		if selected >= 2 {
			source = 0
		}
		inputs[source] |= uint64(0xffff) << uint(selected%2*16)
	}
	return inputs
}

func x86Permute128CheckTransfer(t *testing.T, op string, immediate, destination int, known [3]uint64) {
	t.Helper()
	ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s $%d,Y0,Y1,Y%d", op, immediate, destination))
	state := x86FMA3ResultInputState()
	if immediate&1 != 0 {
		state.flags = 0
	}
	for register, mask := range known {
		state.writeVector(register, 64, mask, false)
	}
	before := state.clone()
	inputs := x86Permute128RequiredBytes(immediate)
	want := known[0]&inputs[0] == inputs[0] && known[1]&inputs[1] == inputs[1]
	accepted := x86ScalarFPResultTransfer(ins, &state, nil, 0, "amd64")
	if want {
		before.writeVector(destination, 32, 0xffffffff, false)
	}
	if accepted != want || !reflect.DeepEqual(state, before) {
		t.Fatal("128-bit selection borrowed an unknown byte, old destination or changed aliases/FLAGS/DF", op, immediate, destination, known, accepted, want)
	}
}

func TestX86Permute128AllSelectorsAndTypedByteRoles(t *testing.T) {
	for _, member := range x86Permute128Members {
		for immediate := 0; immediate < 256; immediate++ {
			t.Run(fmt.Sprintf("%s/imm%d", member.op, immediate), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s $%d,Y0,Y1,Y2", member.op, immediate))
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
				if !known || err != nil || !effect.requiresResultProof || effect.flagsRead != 0 || effect.flagsDefined != 0 || effect.flagsKilled != 0 {
					t.Fatal("permute128 has no complete typed byte/FLAGS owner", known, err)
				}
				seen := make(map[int]bool)
				for _, operand := range effect.operands {
					if operand.index < 1 || operand.index > 3 || seen[operand.index] || operand.width != 32 ||
						!reflect.DeepEqual(operand.operand, ins.Args[operand.index]) ||
						operand.write != (operand.index == 3) || operand.index == 3 && operand.read {
						t.Fatal("permute128 lost its two sources/write-only destination", operand)
					}
					seen[operand.index] = true
				}
				if len(seen) != 3 || !x86TypedFPResultNeedsProof(Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, "amd64") {
					t.Fatal("Void waived the source-wide input contract")
				}
				for _, destination := range []int{0, 1, 2} {
					for _, inputs := range [][3]uint64{
						{^uint64(0), ^uint64(0), 0}, {0, 0, 0},
						{0xffff, ^uint64(0), 0}, {0xffff0000, ^uint64(0), 0},
						{^uint64(0), 0xffff, 0}, {^uint64(0), 0xffff0000, 0},
					} {
						x86Permute128CheckTransfer(t, member.op, immediate, destination, inputs)
					}
				}
			})
		}
	}
}

func TestX86Permute128EverySelectedByteAndDestinationAlias(t *testing.T) {
	for _, member := range x86Permute128Members {
		for _, immediate := range []int{0x21, 0x32, 0x88} {
			for _, destination := range []int{0, 1, 2} {
				t.Run(fmt.Sprintf("%s/imm%d/dst%d", member.op, immediate, destination), func(t *testing.T) {
					for source := 0; source < 3; source++ {
						for missing := -1; missing < 64; missing++ {
							known := [3]uint64{^uint64(0), ^uint64(0), ^uint64(0)}
							if missing >= 0 {
								known[source] &^= uint64(1) << uint(missing)
							}
							x86Permute128CheckTransfer(t, member.op, immediate, destination, known)
						}
					}
				})
			}
		}
	}
}

func x86Permute128OriginalRuntime(t *testing.T) (string, string) {
	t.Helper()
	_, _, function := x86PhysicalFixtureSyntax(t, "amd64_lower_permute128_test.go", "TestAMD64Permute128RuntimeSemantics")
	values := make(map[string]string)
	ast.Inspect(function.Body, func(node ast.Node) bool {
		value, ok := node.(*ast.ValueSpec)
		if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
			return true
		}
		name := value.Names[0].Name
		if name != "source" && name != "mainC" {
			return true
		}
		literal, ok := value.Values[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING || values[name] != "" {
			t.Fatal("original permute128 source/C lost its unique literal", name)
		}
		var err error
		values[name], err = strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		return true
	})
	for name, want := range map[string]string{
		"source": "767466b2cbe556c3903ad61f162f4fe7d2d237d66840443ef0fc8d11ac8b09d4",
		"mainC":  "598ae6f88cd21eb5ff5225b1526e01bf5fb865de4737ddbb48d88cca10b8c43e",
	} {
		if fmt.Sprintf("%x", sha256.Sum256([]byte(values[name]))) != want {
			t.Fatal("complete original permute128 ASM/C/observations changed", name)
		}
	}
	return "#include \"textflag.h\"\n" + values["source"], values["mainC"]
}

const x86Permute128OriginalDeclarations = "func permute128integer(out,first,second *byte)\nfunc permute128float(out,first,second *byte)"

func TestX86Permute128OriginalInitializedThreeTargetObjects(t *testing.T) {
	source, _ := x86Permute128OriginalRuntime(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, x86Permute128OriginalDeclarations, "amd64", triple, api)
					if err != nil || ir == "" {
						t.Fatal("original initialized three-pointer permute128 program lost its owner", err)
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

func TestX86Permute128VoidDoesNotInventSelectedInputs(t *testing.T) {
	for _, member := range x86Permute128Members {
		for _, unused := range []bool{false, true} {
			declaration, size := "func Value()", 0
			if unused {
				declaration, size = "func Value(unused bool)", 1
			}
			for _, immediate := range []int{0x21, 0x88} {
				for _, memory := range []bool{false, true} {
					operand := "Y0"
					if memory {
						operand = "(AX)"
					}
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s $%d,%s,Y1,Y2\nRET\n", size, member.op, immediate, operand)
					x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(fmt.Sprintf("%s/unused%t/imm%d/memory%t/%s", member.op, unused, immediate, memory, api), func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
							if immediate == 0x88 && !memory {
								if err != nil || ir == "" {
									t.Fatal("two immediate-zero register halves require no vector input", err)
								}
							} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("Void/unused bool fabricated vector bytes or a pointer for zero/dead memory", err)
							}
						})
					}
				}
			}
		}
	}
}
