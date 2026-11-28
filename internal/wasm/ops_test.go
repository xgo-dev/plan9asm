package wasm

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
	"testing"
)

func TestTranslateWasmIntegerOperations(t *testing.T) {
	for op, spec := range wasmIntegerBinaryOps {
		t.Run(op, func(t *testing.T) {
			translateWasmIntegerOperation(t, op, spec, spec.typ)
		})
	}
	for op, spec := range wasmIntegerCompareOps {
		t.Run(op, func(t *testing.T) {
			translateWasmIntegerOperation(t, op, spec, asm.I32)
		})
	}
}

func translateWasmForTest(file *asm.File, sig asm.FuncSig) (string, error) {
	var b strings.Builder
	err := TranslateFunc(&b, file.Funcs[0], sig, func(s string) string { return s }, map[string]asm.FuncSig{sig.Name: sig}, asm.WASMABIDirect, false)
	return b.String(), err
}

func TestTranslateWasmMemoryOperations(t *testing.T) {
	for op, spec := range wasmMemoryLoadOps {
		t.Run(op, func(t *testing.T) {
			file, err := asm.Parse(asm.ArchWASM, fmt.Sprintf(`TEXT op(SB), NOSPLIT, $0
	I32Const $1024
	%s $3
	Return
`, op))
			if err != nil {
				t.Fatal(err)
			}
			ir, err := translateWasmForTest(file, asm.FuncSig{Name: "op", Ret: spec.resultType})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "load volatile "+string(spec.loadType)) {
				t.Fatalf("translated %s IR does not load %s:\n%s", op, spec.loadType, ir)
			}
			if spec.loadType != spec.resultType {
				extend := "zext"
				if spec.signed {
					extend = "sext"
				}
				if !strings.Contains(ir, extend+" "+string(spec.loadType)) {
					t.Fatalf("translated %s IR does not contain %s:\n%s", op, extend, ir)
				}
			}
		})
	}

	for op, spec := range wasmMemoryStoreOps {
		t.Run(op, func(t *testing.T) {
			constant := "I32Const"
			if strings.HasPrefix(op, "I64") {
				constant = "I64Const"
			}
			file, err := asm.Parse(asm.ArchWASM, fmt.Sprintf(`TEXT op(SB), NOSPLIT, $0
	I32Const $1024
	%s $17
	%s $3
	Return
`, constant, op))
			if err != nil {
				t.Fatal(err)
			}
			ir, err := translateWasmForTest(file, asm.FuncSig{Name: "op", Ret: asm.Void})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "store volatile "+string(spec.storeType)) {
				t.Fatalf("translated %s IR does not store %s:\n%s", op, spec.storeType, ir)
			}
		})
	}
}

func translateWasmIntegerOperation(t *testing.T, op string, spec wasmIntegerOp, result asm.LLVMType) {
	t.Helper()
	constant := "I32Const"
	if spec.typ == asm.I64 {
		constant = "I64Const"
	}
	file, err := asm.Parse(asm.ArchWASM, fmt.Sprintf(`TEXT op(SB), NOSPLIT, $0
	%s $17
	%s $3
	%s
	Return
`, constant, constant, op))
	if err != nil {
		t.Fatal(err)
	}
	ir, err := translateWasmForTest(file, asm.FuncSig{Name: "op", Ret: result})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, " = "+spec.op+" "+string(spec.typ)) &&
		!strings.Contains(ir, " = icmp "+spec.op+" "+string(spec.typ)) {
		t.Fatalf("translated %s IR does not contain %s %s:\n%s", op, spec.op, spec.typ, ir)
	}
}

func TestWasmRegisterMetadata(t *testing.T) {
	for _, tc := range []struct {
		reg  asm.Reg
		want asm.LLVMType
	}{
		{reg: "R0", want: asm.I64},
		{reg: "F0", want: "float"},
		{reg: "F16", want: "double"},
		{reg: "V0", want: "<4 x i32>"},
		{reg: "PC_B", want: asm.I32},
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

func TestSIMDRejectsInvalidLaneImmediate(t *testing.T) {
	for _, body := range []string{
		"V128Const $1,$2\nI32x4ExtractLane $4",
		"V128Const $1,$2\nI32x4ExtractLane $-1",
		"V128Const $1,$2\nI32Const $1\nI32x4ReplaceLane $4",
		"I32Const $0\nV128Const $1,$2\nV128Load8Lane $0,$16",
		"I32Const $0\nV128Const $1,$2\nV128Store64Lane $0,$2",
		"V128Const $1,$2\nV128Const $3,$4\nI8x16Shuffle $0",
	} {
		f, err := asm.Parse(asm.ArchWASM, "TEXT op(SB),NOSPLIT,$0\n"+body+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := translateWasmForTest(f, asm.FuncSig{Name: "op", Ret: asm.Void}); err == nil {
			t.Errorf("accepted invalid lane in %s", body)
		}
	}
}
