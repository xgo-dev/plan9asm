package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var wasmConditionTestRoutes = []string{"Translate", "TranslateModule", "TranslateModuleInContext"}

func TestWASMControlConditionsRequireI32(t *testing.T) {
	const bad = "I64Const $4294967296\n"
	tests := []struct {
		name, body string
	}{
		{"If", bad + "If\nEnd"},
		{"BrIf", "Block\n" + bad + "BrIf $0\nEnd"},
		{"Select", "I32Const $11\nI32Const $22\n" + bad + "Select\nDrop"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			file, err := Parse(ArchWASM, "TEXT f(SB),4,$0-0\n"+tc.body+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "f"); err == nil {
				t.Error("inference accepted an i64 condition")
			}
			sigs := map[string]FuncSig{"f": {Name: "f", Ret: Void}}
			for _, route := range wasmConditionTestRoutes {
				ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIDirect), route)
				if err == nil || ir != "" || !strings.Contains(err.Error(), "condition requires i32") {
					t.Errorf("%s: expected a typed condition diagnostic, got %v", route, err)
				}
			}
		})
	}
}

func TestWASMSelectRejectsInvalidSourceFormat(t *testing.T) {
	for _, spelling := range []string{"Select.INVALID", "Select R0,R1,R2"} {
		file, err := Parse(ArchWASM, "TEXT f(SB),4,$0-0\nRET\n"+spelling+"\n")
		if err != nil {
			continue
		}
		if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "f"); err == nil {
			t.Errorf("inference accepted %q after RET", spelling)
		}
		sigs := map[string]FuncSig{"f": {Name: "f", Ret: Void}}
		if _, err := Translate(file, wasmPackedOptions(sigs, WASMABIDirect)); err == nil {
			t.Errorf("translation accepted %q after RET", spelling)
		}
	}
}

func TestWASMStructuredBranchRejectsInvalidResult(t *testing.T) {
	tests := []struct {
		name, body string
	}{
		{"width", "Block $1\nI64Const $4294967297\nBr $0\nEnd"},
		{"conditional width", "Block $1\nBlock\nI64Const $4294967297\nI32Const $1\nBrIf $1\nDrop\nEnd\nI32Const $11\nEnd"},
		{"enclosing stack", "Block $1\nI32Const $11\nBlock\nBr $1\nEnd\nDrop\nI32Const $22\nEnd"},
		{"conditional enclosing stack", "Block $1\nI32Const $11\nBlock\nI32Const $1\nBrIf $1\nEnd\nDrop\nI32Const $22\nEnd"},
		{"condition below entry height", "I32Const $1\nBlock\nBrIf $0\nEnd\nDrop\nI32Const $11"},
		{"invalid branch depth", "Block $1\nI32Const $11\nBr $2\nEnd"},
		{"unknown branch label", "Block $1\nI32Const $11\nI32Const $1\nBrIf absent\nEnd"},
		{"fallthrough width", "Block $1\nI64Const $4294967297\nEnd"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			file, err := Parse(ArchWASM, "TEXT f(SB),4,$0-0\n"+tc.body+"\nReturn\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "f"); err == nil {
				t.Error("inference accepted an invalid structured result or target")
			}
			sigs := map[string]FuncSig{"f": {Name: "f", Ret: I32}}
			for _, route := range wasmConditionTestRoutes {
				ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIDirect), route)
				if err == nil || ir != "" {
					t.Errorf("%s accepted an invalid structured result or target: %v", route, err)
				}
			}
		})
	}
}

func TestWASMControlConditionsAndLoopResultsRuntime(t *testing.T) {
	const input = "Get R0\nI32WrapI64\n"
	const decrement = "Get R0\nI64Const $1\nI64Sub\nTee R0\nI64Eqz\nI32Eqz\n"
	const selectI64 = "I64Const $11\nI64Const $22\n" + input
	type check struct{ input, want uint64 }
	type controlCase struct {
		name, body string
		checks     []check
	}
	choices := []check{
		{0, 22}, {1, 11}, {1 << 31, 11}, {1 << 32, 22}, {1<<32 + 1, 11},
	}
	tests := []controlCase{
		{"chooseIf", input + "If $2\nI64Const $11\nElse\nI64Const $22\nEnd\n", choices},
		{"chooseDepth", "Block $2\nI64Const $11\n" + input + "BrIf $0\nDrop\nI64Const $22\nEnd\n", choices},
		{"chooseLabel", "target:\nBlock $2\nI64Const $11\n" + input + "BrIf target\nDrop\nI64Const $22\nEnd\n", choices},
		{"chooseSelect", selectI64 + "Select\n", choices},
		{"chooseSelectOne", selectI64 + "Select $7\n", choices},
		{"chooseSelectTwo", selectI64 + "Select R0,R1\n", choices},
		{"chooseI32", "I32Const $11\nI32Const $22\n" + input + "Select\nI64ExtendI32U\n", choices},
		{"chooseF32", "F32Const $11.0\nF32Const $22.0\n" + input + "Select\nI64TruncF32S\n", choices},
		{"chooseF64", "F64Const $11.0\nF64Const $22.0\n" + input + "Select\nI64TruncF64S\n", choices},
		{
			"loopConditional", "Loop $2\n" + decrement + "BrIf $0\nI64Const $71\nEnd\n",
			[]check{{1, 71}, {17, 71}},
		},
		{
			"loopUnconditional", "Loop $2\n" + decrement + "If\nBr $1\nEnd\nI64Const $72\nEnd\n",
			[]check{{1, 72}, {17, 72}},
		},
		{
			"outerResult", "Block $2\nBlock $1\nGet R0\nBr $1\nEnd\nDrop\nI64Const $99\nEnd\n",
			[]check{{10, 10}, {1<<63 + 1, 1<<63 + 1}},
		},
		{
			"outerConditionalResult", "Block $2\nBlock $1\nI64Const $61\n" + input +
				"BrIf $1\nDrop\nI32Const $7\nEnd\nDrop\nI64Const $62\nEnd\n",
			[]check{{0, 62}, {1, 61}, {1 << 32, 62}},
		},
		{
			"outerNamedResult", "outer:\nBlock $2\nBlock $1\nGet R0\nBr outer\nEnd\nDrop\nI64Const $99\nEnd\n",
			[]check{{7, 7}, {1<<63 + 1, 1<<63 + 1}},
		},
		{
			"loopEntryWithoutResult", "Loop $2\nGet R0\nI64Eqz\nIf $1\nI32Const $0\nElse\n" +
				"Get R0\nI64Const $1\nI64Sub\nSet R0\nI64Const $42\nBr $1\nEnd\nDrop\nI64Const $73\nEnd\n",
			[]check{{0, 73}, {17, 73}},
		},
	}
	type resultForm struct {
		name, literal, toI64 string
		blockType            int
	}
	results := []resultForm{
		{"I32", "I32Const $%d", "I64ExtendI32U\n", 1},
		{"I64", "I64Const $%d", "", 2},
		{"F32", "F32Const $%d.0", "I64TruncF32S\n", 3},
		{"F64", "F64Const $%d.0", "I64TruncF64S\n", 4},
	}
	namespace, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/wasm/anames.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(namespace), `"V128Const"`) {
		const extract = "I32x4ExtractLane $0,$0\nI64ExtendI32U\n"
		tests = append(tests, controlCase{
			"chooseV128", "V128Const $11,$0\nV128Const $22,$0\n" + input + "Select\n" + extract, choices,
		})
		results = append(results, resultForm{"V128", "V128Const $%d,$0", extract, 5})
	}
	for _, result := range results {
		start := fmt.Sprintf("Block $%d\nBlock $2\n%s\n", result.blockType, fmt.Sprintf(result.literal, 17))
		end := "End\nDrop\n" + fmt.Sprintf(result.literal, 23) + "\nEnd\n" + result.toI64
		tests = append(tests,
			controlCase{
				"branch" + result.name, "Get R0\nDrop\n" + start + "Br $1\n" + end, []check{{0, 17}},
			},
			controlCase{
				"branchIf" + result.name, start + input + "BrIf $1\nDrop\nI64Const $7\n" + end,
				[]check{{0, 23}, {1, 17}, {1 << 32, 23}},
			},
		)
	}
	var src, original, goSrc, js strings.Builder
	goSrc.WriteString("package main\n")
	js.WriteString("const bytes = require('fs').readFileSync(process.argv[1]);\n")
	js.WriteString("const f = new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;\n")
	sigs := make(map[string]FuncSig)
	for _, tc := range tests {
		fmt.Fprintf(&src, "TEXT %s(SB),4,$0-0\n%sReturn\n", tc.name, tc.body)
		fmt.Fprintf(&original, "TEXT ·%s(SB),4,$0-16\nMOVD input+0(FP),R0\nGet SP\n", tc.name)
		original.WriteString(tc.body)
		original.WriteString("I64Store ret+8(FP)\nRET\n")
		fmt.Fprintf(&goSrc, "func %s(input uint64) uint64\n", tc.name)
		sigs[tc.name] = FuncSig{Name: tc.name, Args: []LLVMType{I64}, ArgRegs: []Reg{"R0"}, Ret: I64}
	}
	goSrc.WriteString("func main() {\n")
	for _, tc := range tests {
		for _, check := range tc.checks {
			message := fmt.Sprintf("wrong %s(%d) result", tc.name, check.input)
			fmt.Fprintf(&goSrc, "if %s(%d) != %d { panic(%q) }\n", tc.name, check.input, check.want, message)
			fmt.Fprintf(&js, "if (BigInt.asUintN(64, f.%s(%dn)) !== %dn) throw Error(%q);\n", tc.name, check.input, check.want, message)
		}
	}
	goSrc.WriteString("println(\"wasm control PASS\")\n}\n")

	t.Run("OriginalGo", func(t *testing.T) {
		dir := t.TempDir()
		for name, code := range map[string]string{
			"go.mod":         "module control_oracle\ngo 1.20\n",
			"main.go":        goSrc.String(),
			"control_wasm.s": original.String(),
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(code), 0600); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		binary := filepath.Join(dir, "control.wasm")
		cmd := exec.CommandContext(ctx, "go", "build", "-o", binary, ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=js", "GOARCH=wasm")
		if output, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
			t.Fatalf("Go build: %v\n%s", err, output)
		}
		cmd, err := wasmPackedGoRuntimeCommand(ctx, runtime.GOROOT(), wasmPackedNode(t), binary)
		if err != nil {
			t.Fatal(err)
		}
		if output, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil || strings.TrimSpace(string(output)) != "wasm control PASS" {
			t.Fatalf("Go execution: %v\n%s", err, output)
		}
	})

	file, err := Parse(ArchWASM, src.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range file.Funcs {
		got, err := InferWASMAssemblyFuncSig(fn, fn.Sym)
		if err != nil || len(got.Args) != 1 || got.Args[0] != I64 || got.Ret != I64 {
			t.Errorf("%s: inference returned %+v: %v", fn.Sym, got, err)
		} else {
			sigs[fn.Sym] = got
		}
	}
	for _, route := range wasmConditionTestRoutes {
		t.Run(route, func(t *testing.T) {
			ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIDirect), route)
			if err != nil {
				t.Fatal(err)
			}
			runLLVMWASMObject(t, ir, "0", js.String())
			runLLVMWASMObject(t, ir, "2", js.String())
		})
	}
}
