package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// This directory is independent of the production compare map. Legacy SSE
// has one X-result shape, signed Yi8 syntax and four refining prefixes. Intel
// SDM Vol.2A CMPPS/PD/SS/SD and Intel XED xed-isa.txt distinguish packed m128
// alignment/SSE_TYPE_2 from scalar m32/m64/SSE_TYPE_3 and preserve MXCSR.
// Selectors 8..255 remain original bytes, not invented IEEE truth tables.
type x86RawLegacyFloatCompareOracle struct {
	op     string
	prefix byte
	input  int
}

var x86RawLegacyFloatCompareOracles = []x86RawLegacyFloatCompareOracle{
	{"CMPPS", 0, 16}, {"CMPPD", 0x66, 16},
	{"CMPSS", 0xf3, 4}, {"CMPSD", 0xf2, 8},
}

func (row x86RawLegacyFloatCompareOracle) code(memory bool, predicate byte) []byte {
	var code []byte
	if row.prefix != 0 {
		code = append(code, row.prefix)
	}
	modrm := byte(0xc1) // destination X0, source X1
	if memory {
		modrm = 0x03 // destination X0, source (BX)
	}
	return append(code, 0x0f, 0xc2, modrm, predicate)
}

func x86RawLegacyFloatCompareOriginalProgramsUnchanged(t *testing.T) {
	t.Helper()
	const path = "amd64_raw_compare_float_test.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, path, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{
		"TestCrossLinuxRuntimeMatrixX86RawLegacyFloatingCompareRuntime": "8790480bde539b865752ea02cb0759b7346b9ae77c9462aefe33a3c1bedbb687",
		"x86RawLegacyFloatingCompareOriginalKernel":                     "bdab858ff28514acd7c91f5ec34c41d49ad5e8543076c20406c734ccf9360211",
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		hash, owned := expected[function.Name.Name]
		if !owned {
			continue
		}
		start, end := set.Position(function.Pos()).Offset, set.Position(function.End()).Offset
		if fmt.Sprintf("%x", sha256.Sum256(data[start:end])) != hash {
			t.Fatal("original complete raw compare ASM/C, full imm8 or MXCSR observations changed", function.Name.Name)
		}
		delete(expected, function.Name.Name)
	}
	if len(expected) != 0 {
		t.Fatal("original raw compare runtime or exact-byte kernel disappeared", expected)
	}
}

func TestX86RawLegacyFloatingCompareCompleteGoEncoderRows(t *testing.T) {
	x86RawLegacyFloatCompareOriginalProgramsUnchanged(t)
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	const grammar = "var yxcmpi = []ytab{\n\t{Zm_r_i_xm, 2, argList{Yxm, Yxr, Yi8}},\n}"
	if !strings.Contains(string(data), grammar) {
		t.Fatal("complete legacy compare zcase, byte offset or operand classes changed")
	}
	for _, row := range []string{
		"{ACMPPS, yxcmpi, Pm, opBytes{0xc2, 0}},",
		"{ACMPPD, yxcmpi, Px, opBytes{Pe, 0xc2}},",
		"{ACMPSS, yxcmpi, Px, opBytes{Pf3, 0xc2}},",
		"{ACMPSD, yxcmpi, Px, opBytes{Pf2, 0xc2}},",
	} {
		if !strings.Contains(string(data), row) {
			t.Fatal("legacy compare lost an original opcode/refining-prefix row", row)
		}
	}
}

func TestX86RawLegacyFloatingCompareInitializedOriginalProducers(t *testing.T) {
	x86RawLegacyFloatCompareOriginalProgramsUnchanged(t)
	for _, row := range x86RawLegacyFloatCompareOracles {
		for _, memory := range []bool{false, true} {
			input := "X1"
			if memory {
				input = "(BX)"
			}
			prefix := "TEXT ·Value(SB),4,$0-24\nMOVQ out+0(FP),DI\n" +
				"MOVQ left+8(FP),AX\nMOVQ right+16(FP),BX\nMOVOU (AX),X0\nMOVOU (BX),X1\n"
			named := prefix + row.op + " " + input + ",X0,$0\nMOVOU X0,(DI)\nRET\n"
			raw := prefix + x86RawDisplacementDirectives(row.code(memory, 0)) + "MOVOU X0,(DI)\nRET\n"
			// Retain the discovering runtime's ordinary MOVOU producers and
			// output. Only the compare spelling changes, never its initialization.
			goAssemblerOracleOutput(t, "amd64", named+strings.Replace(raw, "·Value", "·RawValue", 1), "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/memory=%t/%s", row.op, memory, api), func(t *testing.T) {
					for _, program := range []struct{ name, source string }{{"named", named}, {"raw", raw}} {
						ir, err := x86ScalarFPBitViewAPI(t, program.source, "func Value(out,left,right *byte)", "amd64", "x86_64-unknown-linux-gnu", api)
						if err != nil || ir == "" {
							t.Fatal("same initialized source lost its paired native compare continuation", program.name, err)
						}
						if !strings.Contains(ir, "asm sideeffect \""+strings.ToLower(row.op)+" $$0,") ||
							!strings.Contains(ir, "~{memory},~{fpsr}") {
							t.Fatal("original whole comparison or its native exceptions/access effects disappeared", program.name)
						}
					}
				})
			}
		}
	}
}

func TestX86RawLegacyFloatingCompareEverySelectorRetainsTypedState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86RawLegacyFloatCompareOracles {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				for _, memory := range []bool{false, true} {
					for selector := 0; selector < 256; selector++ {
						decoded, err := decodeX86RawDirectives(rawX86Function(row.code(memory, byte(selector))), arch)
						if err != nil || len(decoded.Instrs) != 1 {
							t.Fatal("independent complete prefix/opcode/imm8 failed to decode", memory, selector, err)
						}
						ins := decoded.Instrs[0]
						if ins.Op != Op(row.op) || len(ins.Args) != 3 || ins.Args[2].Imm != int64(int8(selector)) || ins.x86SourceRaw == nil {
							t.Fatal("raw source lost its original signed spelling, full selector or decoder identity", ins)
						}
						active := x86CallerVectorByteMask(int64(row.input))
						state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
						bx, _, _ := x86ResultGP("BX", x86ResultPointerWord(arch), arch)
						state.pointerGP[bx], state.masks[7] = true, true
						state.writeVector(0, 64, 0xa5a5a5a5a5a5a5a5|active, false)
						state.writeVector(1, 64, 0x5a5a5a5a5a5a5a5a|active, false)
						before := state.clone()
						local := ins
						local.x86Encoded, local.x86SourceRaw = false, nil
						control := before.clone()
						if accepted, known := x86ResultFloatCompareStep(local, &control, nil, arch, true); !known || !accepted {
							t.Fatal("named full-selector positive control failed before raw continuation", memory, selector)
						}
						want := before.clone()
						want.writeVector(0, 16, before.vectorBytes(0)|active, true)
						if !reflect.DeepEqual(control, want) {
							t.Fatal("named comparison changed original scalar passthrough, wider aliases or FLAGS", memory, selector)
						}
						if accepted, known := x86ResultFloatCompareStep(ins, &state, nil, arch, true); !known || !accepted || !reflect.DeepEqual(state, want) {
							t.Fatal("exact legacy raw compare did not reuse complete typed inputs and architectural writeback", memory, selector)
						}
						standalone := before.clone()
						if accepted, _ := x86ResultFloatCompareStep(ins, &standalone, nil, arch, false); accepted || !reflect.DeepEqual(standalone, before) {
							t.Fatal("standalone observer borrowed raw or native continuation authority", memory, selector)
						}
					}
				}
			})
		}
	}
}
