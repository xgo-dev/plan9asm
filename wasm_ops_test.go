package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateWasmIntegerOperations(t *testing.T) {
	for op, spec := range wasmIntegerCompareOps {
		t.Run(op, func(t *testing.T) {
			translateWasmIntegerComparison(t, op, spec)
		})
	}
}

func translateWasmIntegerComparison(t *testing.T, op string, spec wasmIntegerComparisonOp) {
	t.Helper()
	constant := "I32Const"
	if spec.typ == I64 {
		constant = "I64Const"
	}
	body := constant + " $17\n"
	if spec.arity == 2 {
		body += constant + " $3\n"
	}
	file, err := Parse(ArchWASM, fmt.Sprintf("TEXT op(SB), NOSPLIT, $0\n%s%s\nReturn\n", body, op))
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "wasm32-unknown-unknown",
		Sigs:         map[string]FuncSig{"op": {Name: "op", Ret: I32}},
		Goarch:       "wasm",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, " = icmp "+spec.predicate+" "+string(spec.typ)) {
		t.Fatalf("translated %s IR does not contain %s %s:\n%s", op, spec.predicate, spec.typ, ir)
	}
}

func TestWasmRegisterMetadata(t *testing.T) {
	for _, tc := range []struct {
		reg  Reg
		want LLVMType
	}{
		{reg: "R0", want: I64},
		{reg: "F0", want: "float"},
		{reg: "F16", want: "double"},
		{reg: "V0", want: "<4 x i32>"},
		{reg: "PC_B", want: I32},
	} {
		if got := wasmDefaultRegisterType(tc.reg); got != tc.want {
			t.Fatalf("wasmDefaultRegisterType(%s) = %s, want %s", tc.reg, got, tc.want)
		}
	}
	if !(wasmRegOrder("R15") < wasmRegOrder("F0") && wasmRegOrder("F31") < wasmRegOrder("V0")) {
		t.Fatal("wasm register ordering does not keep R, F, and V groups stable")
	}
	if got := wasmRegOrder("CTXT"); got != 1000 {
		t.Fatalf("wasmRegOrder(CTXT) = %d, want fallback order 1000", got)
	}
}

func TestParseWasmMemoryOperands(t *testing.T) {
	file, err := Parse(ArchWASM, `TEXT op(SB), NOSPLIT, $0
	MOVD R1, 8(R0)
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	got := file.Funcs[0].Instrs[1].Args[1]
	if got.Kind != OpMem || got.Mem.Base != "R0" || got.Mem.Off != 8 {
		t.Fatalf("8(R0) = %#v, want wasm R0 memory operand", got)
	}
	file, err = Parse(ArchWASM, `TEXT op(SB), NOSPLIT, $0
	MOVD R1, unresolved(R0)
`)
	if err != nil {
		t.Fatal(err)
	}
	got = file.Funcs[0].Instrs[1].Args[1]
	if got.Kind != OpMem || got.Mem.Base != "R0" || got.Mem.OffRaw != "unresolved" {
		t.Fatalf("unresolved(R0) = %#v, want a deferred wasm memory offset", got)
	}
	if _, err := Translate(file, Options{Sigs: map[string]FuncSig{
		"op": {Name: "op", Ret: Void},
	}, Goarch: "wasm"}); err == nil || !strings.Contains(err.Error(), "unresolved wasm memory offset") {
		t.Fatalf("Translate unresolved wasm memory offset error = %v", err)
	}
}
