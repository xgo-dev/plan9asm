package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateWasmDiagnostics(t *testing.T) {
	resultI64 := FuncSig{Name: "op", Ret: I64}
	frameI64 := FuncSig{
		Name: "op", Args: []LLVMType{I64}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}},
	}
	frameF64 := FuncSig{
		Name: "op", Args: []LLVMType{"double"}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: "double", Index: 0, Field: -1}}},
	}
	tests := []struct {
		name  string
		body  string
		sig   FuncSig
		extra map[string]FuncSig
		want  string
	}{
		{name: "stack underflow", body: "Drop", want: "operand stack underflow"},
		{name: "stack address cast", body: "Get SP\nI32WrapI64", want: "stack-address marker"},
		{name: "unsupported cast", body: "MOVD x+0(FP), R0", sig: frameF64, want: "unsupported wasm cast double to i64"},
		{name: "unknown frame parameter", body: "MOVD x+8(FP), R0", sig: frameI64, want: "unknown FP parameter"},
		{name: "invalid frame argument index", body: "MOVD x+0(FP), R0", sig: FuncSig{
			Name: "op", Args: []LLVMType{I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I64, Index: 2, Field: -1}}},
		}, want: "invalid argument index"},
		{name: "unsupported source", body: "MOVD symbol, R0", want: "unsupported wasm source operand"},
		{name: "unsupported destination", body: "MOVD R0, symbol", want: "unsupported wasm destination operand"},
		{name: "linear stack memory", body: "MOVD 0(SP), R0", want: "linear-memory SP operands"},
		{name: "unknown result", body: "Get SP\nI64Const $1\nI64Store ret+0(FP)", want: "unknown FP result"},
		{name: "return result type", body: "Get SP\nI32Const $1\nI32Store ret+0(FP)\nRET", sig: FuncSig{
			Name: "op", Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}}},
		}, want: "return type i64 does not match stored result i32"},
		{name: "missing result", body: "RET", sig: resultI64, want: "missing i64 return value"},
		{name: "implicit missing result", body: "NOP", sig: resultI64, want: "missing i64 return value"},
		{name: "multiple frame results", body: "Get SP\nI64Const $1\nI64Store ret0+0(FP)\nGet SP\nI64Const $2\nI64Store ret1+8(FP)\nRET", sig: FuncSig{
			Name: "op", Ret: I64, Frame: FrameLayout{Results: []FrameSlot{
				{Offset: 0, Type: I64, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
			}},
		}, want: "multiple FP result slots are unsupported"},
		{name: "argument register cast", body: "Get R0\nI64Const $1\nI64Add\nDrop\nRET", sig: FuncSig{
			Name: "op", Args: []LLVMType{"double"}, Ret: Void, ArgRegs: []Reg{"R0"},
		}, want: "unsupported wasm cast double to i64"},
		{name: "tail operand", body: "JMP R0", want: "direct (SB) symbol"},
		{name: "tail signature", body: "JMP target(SB)", want: "missing signature for tail target"},
		{name: "tail argument count", body: "JMP target(SB)", sig: FuncSig{Name: "op", Ret: Void}, extra: map[string]FuncSig{
			"target": {Name: "target", Args: []LLVMType{I32}, Ret: Void},
		}, want: "needs 1 arguments"},
		{name: "tail argument type", body: "JMP target(SB)", sig: FuncSig{Name: "op", Args: []LLVMType{I64}, Ret: Void}, extra: map[string]FuncSig{
			"target": {Name: "target", Args: []LLVMType{I32}, Ret: Void},
		}, want: "argument 0 has type i32"},
		{name: "tail return type", body: "JMP target(SB)", sig: resultI64, extra: map[string]FuncSig{
			"target": {Name: "target", Ret: I32},
		}, want: "returns i32"},
		{name: "nonlocal call", body: "Call target(SB)", want: "file-local wasm helpers only"},
		{name: "missing local call signature", body: "Call target<>(SB)", want: "missing signature for local call"},
		{name: "local call arguments", body: "Call target<>(SB)", extra: map[string]FuncSig{
			"target": {Name: "target", Args: []LLVMType{I32}, Ret: Void},
		}, want: "needs 1 stack arguments"},
		{name: "local call cast", body: "F64Load x+0(FP)\nCall target<>(SB)", sig: frameF64, extra: map[string]FuncSig{
			"target": {Name: "target", Args: []LLVMType{I32}, Ret: Void},
		}, want: "argument 0"},
		{name: "block type operand", body: "Block R0", want: "block type must be an immediate"},
		{name: "block type value", body: "Block $9", want: "unsupported block type"},
		{name: "block argument count", body: "Block $1, $2", want: "expects at most one block type"},
		{name: "if condition", body: "If", want: "operand stack underflow"},
		{name: "else without if", body: "Else", want: "Else without matching If"},
		{name: "duplicate else", body: "I32Const $1\nIf\nElse\nElse", want: "duplicate Else"},
		{name: "end without block", body: "End", want: "End without active control"},
		{name: "result if without else", body: "I32Const $1\nIf $1\nI32Const $2\nEnd", sig: FuncSig{Name: "op", Ret: I32}, want: "requires Else"},
		{name: "block missing result", body: "Block $1\nEnd", want: "missing its i32 result"},
		{name: "block result cast", body: "Block $1\nF64Load x+0(FP)\nEnd", sig: frameF64, want: "unsupported wasm cast double to i32"},
		{name: "branch depth", body: "Block\nBr $2", want: "branch depth 2 exceeds"},
		{name: "conditional branch condition", body: "Block\nBrIf $0", want: "operand stack underflow"},
		{name: "branch result cast", body: "Block $1\nF64Load x+0(FP)\nBr $0", sig: frameF64, want: "unsupported wasm cast double to i32"},
		{name: "branch argument count", body: "Block\nBr\nEnd", want: "expects one target"},
		{name: "branch operand", body: "Block\nBr R0", want: "unsupported branch target"},
		{name: "branch label", body: "Block\nBr missing", want: "unknown structured branch target"},
		{name: "get arguments", body: "Get", want: "Get expects one register"},
		{name: "set arguments", body: "Set", want: "SET expects one register"},
		{name: "set underflow", body: "Set R0", want: "operand stack underflow"},
		{name: "set cast", body: "F64Load x+0(FP)\nSet R0", sig: frameF64, want: "unsupported wasm cast double to i64"},
		{name: "move arguments", body: "MOVD R0", want: "expects source and destination"},
		{name: "constant arguments", body: "I64Const", want: "expects one integer immediate"},
		{name: "binary empty", body: "I32Add", want: "operand stack underflow"},
		{name: "binary left empty", body: "I32Const $1\nI32Add", want: "operand stack underflow"},
		{name: "binary left cast", body: "F64Load x+0(FP)\nI32Const $1\nI32Add", sig: frameF64, want: "unsupported wasm cast double to i32"},
		{name: "binary right cast", body: "I32Const $1\nF64Load x+0(FP)\nI32Add", sig: frameF64, want: "unsupported wasm cast double to i32"},
		{name: "compare empty", body: "I32Eq", want: "operand stack underflow"},
		{name: "compare left cast", body: "F64Load x+0(FP)\nI32Const $1\nI32Eq", sig: frameF64, want: "unsupported wasm cast double to i32"},
		{name: "compare right cast", body: "I32Const $1\nF64Load x+0(FP)\nI32Eq", sig: frameF64, want: "unsupported wasm cast double to i32"},
		{name: "load arguments", body: "I64Load", want: "expects one operand"},
		{name: "load operand", body: "I64Load R0", want: "expects an FP slot or immediate memory offset"},
		{name: "float load operand", body: "F64Load R0", want: "expects an FP slot"},
		{name: "wrap cast", body: "F64Load x+0(FP)\nI32WrapI64", sig: frameF64, want: "unsupported wasm cast double to i32"},
		{name: "extend cast", body: "F64Load x+0(FP)\nI64ExtendI32U", sig: frameF64, want: "unsupported wasm cast double to i64"},
		{name: "eqz cast", body: "F64Load x+0(FP)\nI64Eqz", sig: frameF64, want: "unsupported wasm cast double to i64"},
		{name: "select condition underflow", body: "Select", want: "operand stack underflow"},
		{name: "select false underflow", body: "I32Const $1\nSelect", want: "operand stack underflow"},
		{name: "select true underflow", body: "I32Const $1\nI32Const $1\nSelect", want: "operand stack underflow"},
		{name: "select condition cast", body: "I32Const $1\nI32Const $2\nF64Load x+0(FP)\nSelect", sig: frameF64, want: "unsupported wasm cast double to i32"},
		{name: "unknown float result", body: "F64Load x+0(FP)\nF64Store ret+8(FP)", sig: frameF64, want: "unknown FP result"},
		{name: "unknown float result with stack value", body: "I64Const $1\nF64Load x+0(FP)\nF64Store ret+8(FP)", sig: frameF64, want: "unknown FP result"},
		{name: "float operation underflow", body: "F64Floor", want: "operand stack underflow"},
		{name: "float operation type", body: "I64Const $1\nF64Floor", want: "expects f64"},
		{name: "select mismatch", body: "I32Const $1\nI64Const $2\nI32Const $1\nSelect", want: "Select value type mismatch"},
		{name: "integer store operand", body: "I64Store", want: "expects one operand"},
		{name: "integer store value", body: "I64Store $0", want: "operand stack underflow"},
		{name: "integer store address", body: "I64Const $1\nI64Store $0", want: "operand stack underflow"},
		{name: "integer store destination", body: "I64Const $1\nI64Const $2\nI64Store R0", want: "expects an FP slot or immediate memory offset"},
		{name: "unknown integer result", body: "I64Const $1\nI64Store ret+0(FP)", want: "unknown FP result"},
		{name: "integer store cast", body: "Get SP\nF64Load x+0(FP)\nI32Store ret+8(FP)", sig: frameF64, want: "unsupported wasm cast double to i32"},
		{name: "i32 store operand", body: "I32Store", want: "expects one operand"},
		{name: "unknown i32 result", body: "I32Const $1\nI32Store ret+0(FP)", want: "unknown FP result"},
		{name: "grow underflow", body: "GrowMemory", want: "operand stack underflow"},
		{name: "grow cast", body: "F64Load x+0(FP)\nGrowMemory", sig: frameF64, want: "unsupported wasm cast double to i32"},
		{name: "copy underflow", body: "MemoryCopy", want: "operand stack underflow"},
		{name: "fill underflow", body: "MemoryFill", want: "operand stack underflow"},
		{name: "copy source underflow", body: "I32Const $1\nMemoryCopy", want: "operand stack underflow"},
		{name: "copy destination underflow", body: "I32Const $1\nI32Const $2\nMemoryCopy", want: "operand stack underflow"},
		{name: "fill value underflow", body: "I32Const $1\nMemoryFill", want: "operand stack underflow"},
		{name: "fill destination underflow", body: "I32Const $1\nI32Const $2\nMemoryFill", want: "operand stack underflow"},
		{name: "copy length cast", body: "I32Const $1\nI32Const $2\nF64Load x+0(FP)\nMemoryCopy", sig: frameF64, want: "unsupported wasm cast double to i32"},
		{name: "copy source cast", body: "I32Const $1\nF64Load x+0(FP)\nI32Const $2\nMemoryCopy", sig: frameF64, want: "unsupported wasm cast double to ptr"},
		{name: "copy destination cast", body: "F64Load x+0(FP)\nI32Const $1\nI32Const $2\nMemoryCopy", sig: frameF64, want: "unsupported wasm cast double to ptr"},
		{name: "fill length cast", body: "I32Const $1\nI32Const $2\nF64Load x+0(FP)\nMemoryFill", sig: frameF64, want: "unsupported wasm cast double to i32"},
		{name: "fill value cast", body: "I32Const $1\nF64Load x+0(FP)\nI32Const $2\nMemoryFill", sig: frameF64, want: "unsupported wasm cast double to i8"},
		{name: "fill destination cast", body: "F64Load x+0(FP)\nI32Const $1\nI32Const $2\nMemoryFill", sig: frameF64, want: "unsupported wasm cast double to ptr"},
		{name: "jump arguments", body: "JMP", want: "expects one target"},
		{name: "call arguments", body: "Call", want: "expects one target"},
		{name: "count underflow", body: "I32Clz", want: "operand stack underflow"},
		// Use an intentionally nonexistent name: implemented instruction
		// families must not invalidate this unsupported-name diagnostic.
		{name: "unsupported opcode", body: "InvalidWasmOpcode", want: "unsupported wasm instruction"},
		{name: "unterminated block", body: "Block", want: "unterminated wasm control blocks"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sig := tc.sig
			if sig.Name == "" {
				sig = FuncSig{Name: "op", Ret: Void}
			}
			sigs := map[string]FuncSig{"op": sig}
			for name, extra := range tc.extra {
				sigs[name] = extra
			}
			file, err := Parse(ArchWASM, "TEXT op(SB), NOSPLIT, $0\n"+tc.body+"\n")
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{
				TargetTriple: "wasm32-unknown-unknown",
				ResolveSym:   trimWasmLocalSuffix,
				Sigs:         sigs,
				Goarch:       "wasm",
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Translate error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestTranslateWasmCallingAndRegisterSuccessPaths(t *testing.T) {
	t.Run("void tail", func(t *testing.T) {
		file, err := Parse(ArchWASM, "TEXT op(SB), NOSPLIT, $0\nJMP target(SB)\n")
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{TargetTriple: "wasm32-unknown-unknown", ResolveSym: trimWasmLocalSuffix, Goarch: "wasm", Sigs: map[string]FuncSig{
			"op":     {Name: "op", Args: []LLVMType{I32}, Ret: Void},
			"target": {Name: "target", Args: []LLVMType{I32}, Ret: Void},
		}})
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("void local call", func(t *testing.T) {
		file, err := Parse(ArchWASM, "TEXT op(SB), NOSPLIT, $0\nI32Const $1\nCall target<>(SB)\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{TargetTriple: "wasm32-unknown-unknown", ResolveSym: trimWasmLocalSuffix, Goarch: "wasm", Sigs: map[string]FuncSig{
			"op":     {Name: "op", Ret: Void},
			"target": {Name: "target", Args: []LLVMType{I32}, Ret: Void},
		}})
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("value local call", func(t *testing.T) {
		file, err := Parse(ArchWASM, "TEXT op(SB), NOSPLIT, $0\nI32Const $1\nCall target<>(SB)\nReturn\n")
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{TargetTriple: "wasm32-unknown-unknown", ResolveSym: trimWasmLocalSuffix, Goarch: "wasm", Sigs: map[string]FuncSig{
			"op":     {Name: "op", Ret: I32, Attrs: "nounwind"},
			"target": {Name: "target", Args: []LLVMType{I32}, Ret: I32},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(ir, "nounwind") || !strings.Contains(ir, "call i32 @target") {
			t.Fatalf("value call IR is incomplete:\n%s", ir)
		}
	})
	t.Run("function branch", func(t *testing.T) {
		file, err := Parse(ArchWASM, "TEXT op(SB), NOSPLIT, $0\nBr $0\nI32Const $1\n")
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{TargetTriple: "wasm32-unknown-unknown", Goarch: "wasm", Sigs: map[string]FuncSig{
			"op": {Name: "op", Ret: Void},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(ir, "wasm_function_return:") || !strings.Contains(ir, "ret void") {
			t.Fatalf("function branch IR is incomplete:\n%s", ir)
		}
	})
	t.Run("move immediate and memory", func(t *testing.T) {
		file, err := Parse(ArchWASM, `TEXT op(SB), NOSPLIT, $0
	MOVD ptr+0(FP), R0
	MOVD $17, R1
	MOVD R1, 8(R0)
	MOVD 8(R0), R1
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{TargetTriple: "wasm32-unknown-unknown", Goarch: "wasm", Sigs: map[string]FuncSig{
			"op": {
				Name: "op", Args: []LLVMType{Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
			},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(ir, "getelementptr i8") || !strings.Contains(ir, "store i64") || !strings.Contains(ir, "load i64") {
			t.Fatalf("memory move IR is incomplete:\n%s", ir)
		}
	})
	t.Run("narrow direct memory load", func(t *testing.T) {
		file, err := Parse(ArchWASM, "TEXT op(SB), NOSPLIT, $0\nI32Load8S 0(R0)\nReturn\n")
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{TargetTriple: "wasm32-unknown-unknown", Goarch: "wasm", Sigs: map[string]FuncSig{
			"op": {Name: "op", Args: []LLVMType{I32}, ArgRegs: []Reg{"R0"}, Ret: I32},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(ir, "load i8") || !strings.Contains(ir, "sext i8") {
			t.Fatalf("narrow memory load IR is incomplete:\n%s", ir)
		}
	})
	t.Run("narrow frame move", func(t *testing.T) {
		file, err := Parse(ArchWASM, "TEXT op(SB), NOSPLIT, $0\nMOVB x+0(FP), R0\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ir, err := Translate(file, Options{TargetTriple: "wasm32-unknown-unknown", Goarch: "wasm", Sigs: map[string]FuncSig{
			"op": {
				Name: "op", Args: []LLVMType{I16}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I16, Index: 0, Field: -1}}},
			},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(ir, "trunc i16") {
			t.Fatalf("narrow frame move IR is incomplete:\n%s", ir)
		}
	})
	t.Run("typed registers", func(t *testing.T) {
		file, err := Parse(ArchWASM, `TEXT op(SB), NOSPLIT, $0
	Get PC_B
	Drop
	Get F0
	Drop
	Get F16
	Drop
	Get V0
	Drop
	RET
`)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{TargetTriple: "wasm32-unknown-unknown", Goarch: "wasm", Sigs: map[string]FuncSig{
			"op": {
				Name: "op", Args: []LLVMType{I32, "float", "double", "<4 x i32>"}, Ret: Void,
				ArgRegs: []Reg{"PC_B", "F0", "F16", "V0"},
			},
		}, AnnotateSource: true})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func trimWasmLocalSuffix(sym string) string {
	return strings.TrimSuffix(sym, "<>")
}
