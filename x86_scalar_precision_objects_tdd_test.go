package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Replay the actual complete discovering runtime source. Neither its MOVSD/
// MOVSS producers nor its rounding/mask operations, C oracle or inputs may
// change merely to make the initialized program pass.
func x86ScalarPrecisionOriginalProgram(t *testing.T) string {
	t.Helper()
	const path = "amd64_lower_vcvtss2sd_test.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, path, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestAMD64ScalarPrecisionConvertRuntimeSemantics" {
			continue
		}
		start, end := set.Position(function.Pos()).Offset, set.Position(function.End()).Offset
		// Only this independently audited, execution-only preflight may be
		// removed from the original driver fingerprint. The complete original
		// ASM/C, samples and all other statements retain their old exact hash.
		original := strings.Replace(string(data[start:end]),
			"\tx86OriginalFloatingRuntimeRequireCPU(t, \"scalar-precision\", clang, triple, runPrefix)\n", "", 1)
		if fmt.Sprintf("%x", sha256.Sum256([]byte(original))) != "9df4a3815affc1e690c09fb6db69dfbe20c2acedb32baa9e31210d4a00a977ee" {
			t.Fatal("original precision conversion ASM/C, independent values or source inputs changed")
		}
		constants := make(map[string]string)
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
			if !ok || literal.Kind != token.STRING || constants[name] != "" {
				t.Fatal("original complete runtime escaped its independent single literal", name)
			}
			constants[name], err = strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			return true
		})
		if len(constants) != 2 || constants["source"] == "" || constants["mainC"] == "" {
			t.Fatal("complete original precision runtime or independent C oracle disappeared")
		}
		return constants["source"]
	}
	t.Fatal("original precision runtime root disappeared")
	return ""
}

func x86ScalarPrecisionRequireNativeEffects(t *testing.T, ir string, functions map[string][]string) {
	t.Helper()
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := parseIRModuleInContext(context, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
		t.Fatal(err)
	}
	for name, operations := range functions {
		function := module.NamedFunction(name)
		if function.IsNil() || function.FirstBasicBlock().IsNil() {
			t.Fatal("complete scalar precision source omitted an actual function body", name)
		}
		body := function.String()
		for _, operation := range operations {
			found := false
			for _, line := range strings.Split(body, "\n") {
				found = found || x86ScalarPrecisionNativeEffectLine(line, operation)
			}
			if !found {
				t.Fatal("original conversion opcode/MXCSR/exception effect was replaced by unowned pure LLVM arithmetic", name, operation, body)
			}
		}
	}
}

func x86ScalarPrecisionNativeEffectLine(line, operation string) bool {
	if strings.ContainsAny(line, "\r\n") {
		return false
	}
	_, rest, present := strings.Cut(line, "asm sideeffect \"")
	if !present {
		return false
	}
	assembly, rest, present := strings.Cut(rest, "\"")
	if !present {
		return false
	}
	// A mask's kmovw and the forced EVEX encoding belong to the same actual
	// opcode call. Do not accept unrelated prefixes, comments or other calls.
	if strings.HasPrefix(assembly, "kmovw ") {
		_, assembly, present = strings.Cut(assembly, "; ")
		if !present {
			return false
		}
	}
	assembly = strings.TrimPrefix(assembly, "{evex} ")
	canonical := strings.HasPrefix(assembly, strings.ToLower(operation)+" ")
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, ", \"") {
		return false
	}
	constraints, arguments, present := strings.Cut(rest[len(", \""):], "\"")
	memory, status := false, false
	for _, constraint := range strings.Split(constraints, ",") {
		memory = memory || constraint == "~{memory}"
		status = status || constraint == "~{fpsr}"
	}
	if !present || !memory || !status {
		return false
	}
	if canonical {
		return true
	}
	return x86PackedPrecisionNativeMemoryAlias(assembly, constraints, arguments, operation)
}

func TestX86ScalarPrecisionOpcodeReceiptBindsOneActualCall(t *testing.T) {
	for _, prefix := range []string{"", "{evex} ", "kmovw ${4:k}, %k1; ", "kmovw ${4:k}, %k1; {evex} "} {
		line := "  %x = call <4 x float> asm sideeffect \"" + prefix +
			"vcvtss2sd $3, $2, $0\", \"=v,0,v,v,~{memory},~{fpsr}\"()"
		if !x86ScalarPrecisionNativeEffectLine(line, "VCVTSS2SD") {
			t.Fatal("receipt rejected actual same-call mask/EVEX prefixes", prefix)
		}
		for _, changed := range []string{
			strings.Replace(line, "sideeffect", "", 1),
			strings.Replace(line, "~{memory}", "~{cc}", 1),
			strings.Replace(line, "~{fpsr}", "~{cc}", 1),
			strings.Replace(line, "vcvtss2sd", "vcvtsd2ss", 1),
			strings.Replace(line, "vcvtss2sd", "# vcvtss2sd", 1),
			strings.Replace(line, "vcvtss2sd", "nop; vcvtss2sd", 1),
		} {
			if x86ScalarPrecisionNativeEffectLine(changed, "VCVTSS2SD") {
				t.Fatal("receipt borrowed another instruction, comment, unowned status or memory effect", changed)
			}
		}
	}
}

func TestX86ScalarPrecisionOriginalProgramThreeAPIObjectsAndNativeOpcode(t *testing.T) {
	source := x86ScalarPrecisionOriginalProgram(t)
	declaration := "func scalarPrecisionConvertSemantics(out *[112]byte,doubles *float64,floats *float32,upper,old *[16]byte,mask uint64)\n"
	if _, err := parser.ParseFile(token.NewFileSet(), "api.go", "package bitview\n"+declaration, parser.AllErrors); err != nil {
		t.Fatal("complete original declaration is not valid Go", err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("original initialized scalar precision objects require LLVM22")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			// Supply the actual Go SDK's macro header, without modifying any
			// original assembly body byte or substituting its instruction set.
			x86LEAActualTargetGoObject(t, "amd64", triple, "#include \"textflag.h\"\n"+source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api)
					if err != nil {
						t.Fatal("original complete initialized precision source remains unclosed", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						x86ScalarPrecisionRequireNativeEffects(t, text, map[string][]string{
							"scalarPrecisionConvertSemantics": {"VCVTSD2SS", "VCVTSS2SD"},
						})
						compileLLVMToObject(t, llc, triple, "original-scalar-precision.ll", "original-scalar-precision.o", text)
					}
				})
			}
		})
	}
}

func x86ScalarPrecisionInitializedProgram(index int, row x86ScalarPrecisionOracleRow) (string, string, string) {
	name := fmt.Sprint("Precision", index)
	scalar, _, destination := row.registers()
	upper := scalar + 1 // Legacy's copied bytes come from old, not this independent input.
	inputType, preparation := "uint64", ""
	if row.source == "native" {
		inputType, preparation = "*[8]byte", "MOVQ input+8(FP),AX\n"
	} else if row.source == "register" {
		move := "MOVSS"
		if row.input == 8 {
			move = "MOVSD"
		}
		if row.high {
			move = "V" + move // Legacy scalar transport cannot address X16-X31.
		}
		preparation = fmt.Sprintf("%s input+8(FP),X%d\n", move, scalar)
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-40\nMOVQ out+0(FP),DI\nMOVQ upper+16(FP),BX\nMOVQ old+24(FP),CX\n"+
		"VMOVDQU64 (BX),Z%d\nVMOVDQU64 (CX),Z%d\nKMOVQ mask+32(FP),K1\n%sSTC\n%s\n"+
		"VMOVDQU64 Z%d,(DI)\nSETCS 64(DI)\nSTMXCSR 68(DI)\nRET\n", name, upper, destination, preparation, row.instruction(), destination)
	declaration := fmt.Sprintf("func %s(out *[80]byte,input %s,upper,old *[64]byte,mask uint64)\n", name, inputType)
	return source, declaration, name
}

func TestX86ScalarPrecisionCompleteInitializedMatrixThreeAPIObjects(t *testing.T) {
	x86ScalarPrecisionOriginalProgram(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete initialized scalar precision objects require LLVM22")
	}
	rows := x86ScalarPrecisionOracleRows("amd64")
	if len(rows) != 45 {
		t.Fatal("complete precision input/control inventory changed", len(rows))
	}
	var source, declarations strings.Builder
	functions := make(map[string][]string)
	for index, row := range rows {
		body, declaration, name := x86ScalarPrecisionInitializedProgram(index, row)
		source.WriteString(body)
		declarations.WriteString(declaration)
		functions[name] = []string{row.op}
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "api.go", "package bitview\n"+declarations.String(), parser.AllErrors); err != nil {
		t.Fatal("complete precision declarations are not valid Go", err)
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
					if err != nil {
						t.Fatal("complete initialized scalar precision matrix remains unclosed", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						x86ScalarPrecisionRequireNativeEffects(t, text, functions)
						compileLLVMToObject(t, llc, triple, "complete-scalar-precision.ll", "complete-scalar-precision.o", text)
					}
				})
			}
		})
	}
}

func TestX86ScalarPrecisionInitializedInputRevocationsAndZeroing(t *testing.T) {
	type inputMutation struct {
		name, remove string
		valid        bool
	}
	for index, row := range x86ScalarPrecisionOracleRows("amd64") {
		if row.source == "FP" || row.control != "" || row.high {
			continue // Shared byte roles do not vary with an embedded control.
		}
		source, declaration, _ := x86ScalarPrecisionInitializedProgram(index, row)
		input := "MOVQ input+8(FP),AX\n"
		if row.source == "register" {
			input = "MOVSS input+8(FP),X0\n"
			if row.input == 8 {
				input = "MOVSD input+8(FP),X0\n"
			}
		}
		upper := "VMOVDQU64 (CX),Z2\n"
		if row.vector {
			upper = "VMOVDQU64 (BX),Z1\n"
		}
		mutations := []inputMutation{
			{"active-input", input, false},
			{"copied-upper", upper, false},
			{"output-address", "MOVQ out+0(FP),DI\n", false},
		}
		if row.mode == "merge" || row.mode == "zero" {
			mutations = append(mutations,
				inputMutation{"mask", "KMOVQ mask+32(FP),K1\n", false},
				inputMutation{"old-destination", "VMOVDQU64 (CX),Z2\n", row.mode == "zero"})
		}
		for _, mutation := range mutations {
			if strings.Count(source, mutation.remove) != 1 {
				t.Fatal("independent source mutation is not exact", row, mutation.name)
			}
			changed := strings.Replace(source, mutation.remove, "", 1)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(row.instruction()+"/"+mutation.name+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, changed, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
					if mutation.valid {
						if err != nil || ir == "" {
							t.Fatal("write-only zero-masked destination acquired a false old-value dependency", err)
						}
						return
					}
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("complete initialized conversion borrowed a revoked active/upper/mask/old/native input", mutation.name, err)
					}
				})
			}
		}
	}
}
