package plan9asm

import (
	"testing"
)

// Keep the public inference counterexamples independent of its private dead
// flag: a source label alone does not create an incoming control-flow edge.
func TestWASMV128CorePublicInferenceMatchesDeadControl(t *testing.T) {
	type testCase struct {
		name, body string
		accept     bool
		result     LLVMType
	}
	cases := []testCase{
		{"ret", "RET\nV128Not\nRET\n", true, Void},
		{"undef", "UNDEF\nV128Not\nRET\n", true, Void},
		{"unreachable", "Unreachable\nV128Not\nRET\n", true, Void},
		{"unused-label", "RET\nunused:\nV128Not\nRET\n", true, Void},
		{"branch", "Block\nBr $0\nV128Not\nEnd\nRET\n", true, Void},
		{"branch-unused-label", "Block\nBr $0\nunused:\nV128Not\nEnd\nRET\n", true, Void},
		{"dead-label-constant-does-not-change-ABI", "RET\nunused:\nV128Const $1,$2\nRET\n", true, Void},
		{"malformed-dead", "UNDEF\nV128Not $1\nRET\n", false, Void},
		{"malformed-dead-label", "RET\nunused:\nV128Const $1\nRET\n", false, Void},
		{"live-underflow", "V128Not\nRET\n", false, Void},
		{"live-wrong-scalar", "I64Const $1\nV128Not\nRET\n", false, Void},
		{"live-i64-return-ignores-dead-i32", "I64Const $9\nReturn\nI32Const $1\nReturn\n", true, I64},
	}
	for _, prefix := range []struct{ name, body string }{
		{"ret", "RET\n"}, {"ret-unused-label", "RET\nunused:\n"},
		{"undef", "UNDEF\n"}, {"unreachable", "Unreachable\n"},
	} {
		for _, scalar := range []string{"I32Const $1", "I64Const $1", "F64Const $1.0"} {
			cases = append(cases, testCase{
				name: prefix.name + "-dead-" + scalar, body: prefix.body + scalar + "\nRET\n", accept: true, result: Void,
			})
		}
	}
	// Retain every existing typed count and floating binary operation, rather
	// than using a single mnemonic to represent the complete descriptor paths.
	for _, family := range [][]string{wasmIntegerCountGoNames(t), wasmFloatBinaryGoNames(t), wasmFloatArithmeticGoNames(t)} {
		for _, name := range family {
			cases = append(cases,
				testCase{name: "typed-dead/" + name, body: "RET\n" + name + "\nRET\n", accept: true, result: Void},
				testCase{name: "typed-malformed-dead/" + name, body: "RET\n" + name + " $1\nRET\n", result: Void})
		}
	}
	if len(cases) != 84 {
		t.Fatal("complete dead-control regression inventory changed", len(cases))
	}
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			file, err := Parse(ArchWASM, "TEXT core(SB),4,$0-0\n"+row.body)
			if err != nil {
				t.Fatal("counterexample source must parse independently of the core grammar", err)
			}
			sig, inferenceError := InferWASMAssemblyFuncSig(file.Funcs[0], "core")
			if row.accept {
				if inferenceError != nil || sig.Ret != row.result || len(sig.Args) != 0 {
					t.Errorf("dead instruction changed public inference, want %s: %+v, %v", row.result, sig, inferenceError)
				}
			} else if inferenceError == nil {
				t.Error("public inference accepted malformed/live-invalid core source", sig)
			}
			for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
				ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(map[string]FuncSig{"core": {Name: "core", Ret: row.result}}, WASMABIDirect), route)
				if row.accept && (err != nil || ir == "") {
					t.Errorf("%s lost independent %s lowering control: %v", route, row.result, err)
				}
				if !row.accept && (err == nil || ir != "") {
					t.Errorf("%s accepted malformed/live-invalid core source: %v", route, err)
				}
			}
		})
	}
}
