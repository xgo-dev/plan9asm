package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestInferOfficialWasmLocalHelperSignatures(t *testing.T) {
	tests := []struct {
		name string
		src  string
		args []LLVMType
		regs []Reg
		ret  LLVMType
	}{
		{
			name: "memeqbody",
			src: `TEXT memeqbody<>(SB), NOSPLIT, $0
	Get R0
	Get R1
	I64Eq
	If
		I64Const $1
		Return
	End
	Get R2
	I64Eqz
	If
		I64Const $0
		Return
	End
	UNDEF`,
			args: []LLVMType{I64, I64, I64}, regs: []Reg{"R0", "R1", "R2"}, ret: I64,
		},
		{
			name: "memcmp",
			src: `TEXT memcmp<>(SB), NOSPLIT, $0
	Get R2
	If $1
		Get R0
		I32Load8S $0
		Get R1
		I32Load8S $0
		I32Sub
	Else
		I32Const $0
	End
	Return`,
			args: []LLVMType{I32, I32, I32}, regs: []Reg{"R0", "R1", "R2"}, ret: I32,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			file, err := Parse(ArchWASM, tc.src)
			if err != nil {
				t.Fatal(err)
			}
			got, err := InferWASMAssemblyFuncSig(file.Funcs[0], tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if got.Ret != tc.ret || len(got.Args) != len(tc.args) {
				t.Fatalf("signature = %#v, want args %v return %s", got, tc.args, tc.ret)
			}
			for i := range tc.args {
				if got.Args[i] != tc.args[i] || got.ArgRegs[i] != tc.regs[i] {
					t.Fatalf("signature = %#v, want args %v in R0.. return %s", got, tc.args, tc.ret)
				}
			}
		})
	}
}

func TestInferWasmIntegerAndMemoryOperations(t *testing.T) {
	for op, spec := range wasmIntegerBinaryOps {
		t.Run(op, func(t *testing.T) {
			assertInferredWasmSig(t, fmt.Sprintf(`TEXT helper<>(SB), NOSPLIT, $0
	Get R0
	Get R1
	%s
	Return
`, op), []LLVMType{spec.typ, spec.typ}, spec.typ)
		})
	}
	for op, spec := range wasmIntegerCompareOps {
		t.Run(op, func(t *testing.T) {
			assertInferredWasmSig(t, fmt.Sprintf(`TEXT helper<>(SB), NOSPLIT, $0
	Get R0
	Get R1
	%s
	Return
`, op), []LLVMType{spec.typ, spec.typ}, I32)
		})
	}
	for op, spec := range wasmMemoryLoadOps {
		t.Run(op, func(t *testing.T) {
			assertInferredWasmSig(t, fmt.Sprintf(`TEXT helper<>(SB), NOSPLIT, $0
	Get R0
	%s $0
	Return
`, op), []LLVMType{I32}, spec.resultType)
		})
	}
	for op := range wasmMemoryStoreOps {
		t.Run(op, func(t *testing.T) {
			valueType := I32
			if strings.HasPrefix(op, "I64") {
				valueType = I64
			}
			assertInferredWasmSig(t, fmt.Sprintf(`TEXT helper<>(SB), NOSPLIT, $0
	Get R0
	Get R1
	%s $0
	Return
`, op), []LLVMType{I32, valueType}, Void)
		})
	}
}

func TestInferWasmControlAndScalarOperations(t *testing.T) {
	tests := []struct {
		name string
		src  string
		args []LLVMType
		ret  LLVMType
	}{
		{name: "i32 wrap", src: "Get R0\nI32WrapI64\nReturn", args: []LLVMType{I64}, ret: I32},
		{name: "i64 extend", src: "Get R0\nI64ExtendI32S\nReturn", args: []LLVMType{I32}, ret: I64},
		{name: "i32 eqz", src: "Get R0\nI32Eqz\nReturn", args: []LLVMType{I32}, ret: I32},
		{name: "i64 eqz", src: "Get R0\nI64Eqz\nReturn", args: []LLVMType{I64}, ret: I32},
		{name: "select", src: "I64Const $1\nI64Const $2\nGet R0\nSelect\nReturn", args: []LLVMType{I32}, ret: I64},
		{name: "if else result", src: "Get R0\nIf $2\nI64Const $1\nElse\nI64Const $2\nEnd\nReturn", args: []LLVMType{I32}, ret: I64},
		{name: "block result", src: "Block $3\nGet F0\nEnd\nReturn", args: []LLVMType{"float"}, ret: "float"},
		{name: "loop result", src: "Loop $4\nGet F16\nEnd\nReturn", args: []LLVMType{"double"}, ret: "double"},
		{name: "conditional branch", src: "Block\nGet R0\nBrIf $0\nEnd\nReturn", args: []LLVMType{I32}, ret: Void},
		{name: "call result constraint", src: "Get R0\nCall local<>(SB)\nI64ExtendI32U\nReturn", args: []LLVMType{I64}, ret: I64},
		{name: "written register is not an input", src: "I32Const $1\nSet R0\nGet R0\nReturn", ret: I32},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertInferredWasmSig(t, "TEXT helper<>(SB), NOSPLIT, $0\n"+tc.src+"\n", tc.args, tc.ret)
		})
	}
}

func TestInferWasmDiagnostics(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
		ret  LLVMType
	}{
		{name: "empty pop remains unknown", src: "Drop\nReturn"},
		{name: "malformed get is ignored", src: "Get\nReturn"},
		{name: "malformed set is ignored", src: "Set\nReturn"},
		{name: "register conflict", src: "I32Const $1\nSet R0\nI64Const $1\nSet R0", want: "register R0 has conflicting types"},
		{name: "wrap input", src: "I32Const $1\nI32WrapI64", want: "conflicting stack types"},
		{name: "extend input", src: "I64Const $1\nI64ExtendI32S", want: "conflicting stack types"},
		{name: "i32 binary lhs", src: "I64Const $1\nI32Const $2\nI32Add", want: "conflicting stack types"},
		{name: "i32 binary rhs", src: "I32Const $1\nI64Const $2\nI32Add", want: "conflicting stack types"},
		{name: "i64 binary", src: "I32Const $1\nI64Const $2\nI64Add", want: "conflicting stack types"},
		{name: "i32 compare", src: "I64Const $1\nI32Const $2\nI32Eq", want: "conflicting stack types"},
		{name: "i64 compare", src: "I32Const $1\nI64Const $2\nI64Eq", want: "conflicting stack types"},
		{name: "i32 eqz", src: "I64Const $1\nI32Eqz", want: "conflicting stack types"},
		{name: "i64 eqz", src: "I32Const $1\nI64Eqz", want: "conflicting stack types"},
		{name: "i32 load address", src: "I64Const $1\nI32Load $0", want: "conflicting stack types"},
		{name: "i64 load address", src: "I64Const $1\nI64Load $0", want: "conflicting stack types"},
		{name: "i32 store value", src: "I32Const $1\nI64Const $2\nI32Store $0", want: "conflicting stack types"},
		{name: "i32 store address", src: "I64Const $1\nI32Const $2\nI32Store $0", want: "conflicting stack types"},
		{name: "i64 store value", src: "I32Const $1\nI32Const $2\nI64Store $0", want: "conflicting stack types"},
		{name: "i64 store address", src: "I64Const $1\nI64Const $2\nI64Store $0", want: "conflicting stack types"},
		{name: "select condition", src: "I32Const $1\nI32Const $2\nI64Const $3\nSelect", want: "conflicting stack types"},
		{name: "select values", src: "I32Const $1\nI64Const $2\nI32Const $1\nSelect", want: "Select type mismatch"},
		{name: "if condition", src: "I64Const $1\nIf\nEnd", want: "conflicting stack types"},
		{name: "else result", src: "I32Const $1\nIf $1\nI64Const $2\nElse\nI32Const $3\nEnd", want: "conflicting stack types"},
		{name: "end result", src: "Block $1\nI64Const $1\nEnd", want: "conflicting stack types"},
		{name: "branch result", src: "Block $1\nI64Const $1\nBr $0", want: "conflicting stack types"},
		{name: "return types", src: "I32Const $1\nReturn\nI64Const $1\nReturn", ret: I32},
		{name: "reachable return types", src: "Get R0\nIf\nI32Const $1\nReturn\nElse\nI64Const $1\nReturn\nEnd", want: "conflicting return types"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			file, err := Parse(ArchWASM, "TEXT helper<>(SB), NOSPLIT, $0\n"+tc.src+"\n")
			if err != nil {
				t.Fatal(err)
			}
			got, err := InferWASMAssemblyFuncSig(file.Funcs[0], "helper")
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				if tc.ret != "" && got.Ret != tc.ret {
					t.Fatalf("return type = %s, want %s", got.Ret, tc.ret)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("InferWASMAssemblyFuncSig error = %v, want %q", err, tc.want)
			}
		})
	}
}

func assertInferredWasmSig(t *testing.T, src string, args []LLVMType, ret LLVMType) {
	t.Helper()
	file, err := Parse(ArchWASM, src)
	if err != nil {
		t.Fatal(err)
	}
	got, err := InferWASMAssemblyFuncSig(file.Funcs[0], "helper")
	if err != nil {
		t.Fatal(err)
	}
	if got.Ret != ret || len(got.Args) != len(args) {
		t.Fatalf("signature = %#v, want args %v return %s", got, args, ret)
	}
	for i, want := range args {
		if got.Args[i] != want {
			t.Fatalf("argument %d = %s, want %s; signature %#v", i, got.Args[i], want, got)
		}
	}
}
