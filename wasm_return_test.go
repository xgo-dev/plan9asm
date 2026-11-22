package plan9asm

import (
	"strings"
	"testing"
)

func TestWASMRawReturnReadsOperandStack(t *testing.T) {
	const source = `TEXT stackValue(SB),4,$0-4
	MOVW $11,ret+0(FP)
	I32Const $73
	Return

TEXT oneOperand(SB),4,$0-4
	MOVW $11,ret+0(FP)
	I32Const $73
	Return $7

TEXT twoOperands(SB),4,$0-4
	MOVW $11,ret+0(FP)
	I32Const $73
	Return R0,$8

TEXT frameValue(SB),4,$0-4
	MOVW $11,ret+0(FP)
	I32Const $73
	RET
`
	file, err := Parse(ArchWASM, source)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(map[string]FuncSig)
	for _, name := range []string{"stackValue", "oneOperand", "twoOperands", "frameValue"} {
		sigs[name] = FuncSig{
			Name: name, Ret: I32,
			Frame: FrameLayout{Results: []FrameSlot{{Name: "ret", Type: I32, Field: -1}}},
		}
	}
	const oracle = `
const bytes = require('node:fs').readFileSync(process.argv[1]);
const wasm = new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;
const observed = [wasm.stackValue(), wasm.oneOperand(), wasm.twoOperands(), wasm.frameValue()];
if (observed.join(',') !== '73,73,73,11') {
  throw Error('wrong Return/RET result ' + observed);
}
`
	for _, target := range []string{"wasm32-unknown-unknown", "wasm32-unknown-wasi"} {
		for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
			t.Run(target+"/"+route, func(t *testing.T) {
				options := Options{Goarch: "wasm", TargetTriple: target, Sigs: sigs}
				ir, err := wasmPackedTranslate(t, file, options, route)
				if err != nil {
					t.Fatal(err)
				}
				for _, level := range []string{"0", "2"} {
					t.Run("O"+level, func(t *testing.T) {
						runLLVMWASMObject(t, ir, level, oracle)
					})
				}
			})
		}
	}
}

func TestWASMRawReturnRejectsInvalidFormatAndType(t *testing.T) {
	for _, row := range []struct {
		name, body, diagnostic string
		formatError            bool
	}{
		{"three-operands", "I32Const $1\nReturn $7,$8,$9", "Return accepts at most two", true},
		{"three-dead-operands", "I32Const $1\nReturn\nReturn $7,$8,$9", "Return accepts at most two", true},
		{"wrong-width", "I64Const $1\nReturn", "Return expects a i32 stack value, got i64", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			file, err := Parse(ArchWASM, "TEXT invalid(SB),4,$0-0\n"+row.body+"\n")
			if err != nil {
				t.Fatal(err)
			}
			options := wasmPackedOptions(map[string]FuncSig{"invalid": {Name: "invalid", Ret: Void}}, WASMABIGo)
			if _, err := Translate(file, options); err == nil || !strings.Contains(err.Error(), row.diagnostic) {
				t.Fatalf("Translate returned %v, want %q", err, row.diagnostic)
			}
			if row.formatError {
				if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "invalid"); err == nil || !strings.Contains(err.Error(), row.diagnostic) {
					t.Fatalf("signature inference returned %v, want %q", err, row.diagnostic)
				}
			}
		})
	}
}
