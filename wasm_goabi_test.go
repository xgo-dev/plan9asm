package plan9asm

import (
	"strings"
	"testing"
)

func TestWasmGoABICallerStackAndUnwindLowering(t *testing.T) {
	file, err := Parse(ArchWASM, `TEXT caller(SB), NOSPLIT, $16-0
	CALL callee(SB)
	RET

TEXT callee(SB), NOSPLIT, $0-0
	RET

TEXT unwind(SB), NOSPLIT, $0-0
	RETUNWIND
`)
	if err != nil {
		t.Fatal(err)
	}
	if file.Funcs[0].FrameSize != 16 || file.Funcs[0].ArgSize != 0 {
		t.Fatalf("caller TEXT frame = (%d, %d), want (16, 0)", file.Funcs[0].FrameSize, file.Funcs[0].ArgSize)
	}
	sigs := map[string]FuncSig{
		"caller": {Name: "caller", Ret: Void},
		"callee": {Name: "callee", Ret: Void},
		"unwind": {Name: "unwind", Ret: Void},
	}
	ir, err := Translate(file, Options{
		TargetTriple: "wasm32-unknown-unknown",
		Sigs:         sigs,
		Goarch:       "wasm",
		WASMABI:      WASMABIGo,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"@SP = external addrspace(1) global i32",
		"@CTXT = external addrspace(1) global i64",
		"define i32 @caller(i32 %pc_b)",
		"switch i32 %pc_b, label %wasm_entry_body [",
		"i32 1, label %wasm_resume_1",
		"sub i32",
		"ptrtoint ptr @caller to i64",
		"shl i64",
		"or i64",
		"store i64",
		"call i32 @callee(i32 0)",
		"wasm_call_unwind_",
		"ret i32 1",
		"add i32",
		"ret i32 0",
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("Go wasm ABI IR is missing %q:\n%s", want, ir)
		}
	}
}

func TestWasmGoABIResumeDispatchOmitsCallsAfterTerminatingTailReturn(t *testing.T) {
	file, err := Parse(ArchWASM, `TEXT caller(SB), NOSPLIT, $0-0
	CALL first(SB)
	RET tail(SB)
	CALL unreachable(SB)
`)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{
		"caller":      {Name: "caller", Ret: Void},
		"first":       {Name: "first", Ret: Void},
		"tail":        {Name: "tail", Ret: Void},
		"unreachable": {Name: "unreachable", Ret: Void},
	}
	ir, err := Translate(file, Options{
		TargetTriple: "wasm32-unknown-unknown",
		Sigs:         sigs,
		Goarch:       "wasm",
		WASMABI:      WASMABIGo,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "i32 1, label %wasm_resume_1") {
		t.Fatalf("reachable CALL is absent from resume dispatch:\n%s", ir)
	}
	if strings.Contains(ir, "wasm_resume_2") {
		t.Fatalf("unreachable CALL leaked into resume dispatch:\n%s", ir)
	}
}

func TestWasmRETUNWINDRequiresGoABI(t *testing.T) {
	file, err := Parse(ArchWASM, "TEXT unwind(SB), NOSPLIT, $0-0\nRETUNWIND\n")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		Sigs:   map[string]FuncSig{"unwind": {Name: "unwind", Ret: Void}},
		Goarch: "wasm",
	})
	if err == nil || !strings.Contains(err.Error(), "requires the Go WebAssembly ABI") {
		t.Fatalf("Translate direct RETUNWIND error = %v", err)
	}
}

func TestWasmGoABICallImportUsesResolvedSymbol(t *testing.T) {
	file, err := Parse(ArchWASM, "TEXT ·host(SB), NOSPLIT, $0-0\nCallImport\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(sym string) string {
		return strings.ReplaceAll(sym, "·", "example.com/pkg.")
	}
	ir, err := Translate(file, Options{
		TargetTriple: "wasm32-unknown-unknown",
		ResolveSym:   resolve,
		Sigs: map[string]FuncSig{
			"example.com/pkg.host": {Name: "example.com/pkg.host", Ret: Void},
		},
		Goarch:  "wasm",
		WASMABI: WASMABIGo,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`declare void @"example.com/pkg.host$wasmimport"(i32)`,
		`call void @"example.com/pkg.host$wasmimport"(i32 %`,
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("Go wasm CallImport IR is missing %q:\n%s", want, ir)
		}
	}
}

func TestWasmGoWriteBarrierNativeSignatures(t *testing.T) {
	tests := []struct {
		name string
		args []LLVMType
		ret  LLVMType
	}{
		{name: "runtime.gcWriteBarrier", args: []LLVMType{I64, I64}, ret: Void},
		{name: "runtime.gcWriteBarrier$local", args: []LLVMType{I64}, ret: I64},
		{name: "runtime.gcWriteBarrier1", ret: I64},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sig, ok := wasmGoNativeFuncSig(test.name)
			if !ok {
				t.Fatalf("wasmGoNativeFuncSig(%q) not found", test.name)
			}
			if sig.Ret != test.ret || len(sig.Args) != len(test.args) {
				t.Fatalf("wasmGoNativeFuncSig(%q) = (%v) %s, want (%v) %s", test.name, sig.Args, sig.Ret, test.args, test.ret)
			}
			for i := range test.args {
				if sig.Args[i] != test.args[i] {
					t.Fatalf("wasmGoNativeFuncSig(%q) arg %d = %s, want %s", test.name, i, sig.Args[i], test.args[i])
				}
			}
		})
	}
}

func TestWasmGoABIDynamicCallsAndTailCalls(t *testing.T) {
	file, err := Parse(ArchWASM, `TEXT dynamicCall(SB), NOSPLIT, $0-0
	I64Const $65536
	CALL
	RET

TEXT dynamicTail(SB), NOSPLIT, $0-0
	I64Const $65536
	JMP

TEXT indirectCall(SB), NOSPLIT, $0-0
	I32Const $7
	I32Const $4096
	CallIndirect $0
	Drop
	RET

TEXT noResume(SB), NOSPLIT, $0-0
	CALLNORESUME callee(SB)
	RET

TEXT directTail(SB), NOSPLIT, $0-0
	JMP callee(SB)

TEXT callee(SB), NOSPLIT, $0-0
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(map[string]FuncSig)
	for _, name := range []string{"dynamicCall", "dynamicTail", "indirectCall", "noResume", "directTail", "callee"} {
		sigs[name] = FuncSig{Name: name, Ret: Void}
	}
	ir, err := Translate(file, Options{
		TargetTriple: "wasm32-unknown-unknown",
		Sigs:         sigs,
		Goarch:       "wasm",
		WASMABI:      WASMABIGo,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"inttoptr i32",
		"tail call i32",
		"call i32 %",
		"call i32 @callee(i32 0)",
		"wasm_call_continue_",
		"unreachable",
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("dynamic Go wasm call IR is missing %q:\n%s", want, ir)
		}
	}
}

func TestWasmGoABINativeHelpers(t *testing.T) {
	file, err := Parse(ArchWASM, `TEXT nativeValue<>(SB), NOSPLIT, $0-0
	I64Const $7
	Return

TEXT nativeVoid<>(SB), NOSPLIT, $0-0
	Return

TEXT nativeLoop<>(SB), NOSPLIT, $0-0
	Loop
		Br $0
	End

TEXT nativeCaller<>(SB), NOSPLIT, $0-0
	CALL callee(SB)
	Return

TEXT callee(SB), NOSPLIT, $0-0
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "wasm32-unknown-unknown",
		Sigs: map[string]FuncSig{
			"nativeValue$local":  {Name: "nativeValue$local", Ret: I64, WASMNative: true},
			"nativeVoid$local":   {Name: "nativeVoid$local", Ret: Void, WASMNative: true},
			"nativeLoop$local":   {Name: "nativeLoop$local", Ret: I64, WASMNative: true},
			"nativeCaller$local": {Name: "nativeCaller$local", Ret: Void, WASMNative: true},
			"callee":             {Name: "callee", Ret: Void},
		},
		ResolveSym: resolveWasmTestLocal,
		Goarch:     "wasm",
		WASMABI:    WASMABIGo,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`define i64 @"nativeValue$local"()`,
		"ret i64 7",
		`define void @"nativeVoid$local"()`,
		"ret void",
		`define i64 @"nativeLoop$local"()`,
		"br label %wasm_loop_",
		"unreachable",
		`define void @"nativeCaller$local"()`,
		"call i32 @callee(i32 0)",
		"wasm_call_continue_",
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("native Go wasm helper IR is missing %q:\n%s", want, ir)
		}
	}
	if strings.Contains(ir, "label %\n") {
		t.Fatalf("native Go wasm helper emitted an empty branch label:\n%s", ir)
	}
}

func TestWasmDirectABIClosureContextCalls(t *testing.T) {
	file, err := Parse(ArchWASM, `TEXT caller(SB), NOSPLIT, $0-0
	Get CTXT
	Drop
	I32Const $7
	Call helper<>(SB)
	Drop
	RET

TEXT tailer(SB), NOSPLIT, $0-0
	Get CTXT
	Drop
	JMP target(SB)

TEXT helper<>(SB), NOSPLIT, $0-0
	Get R0
	Return
`)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "wasm32-unknown-unknown",
		Sigs: map[string]FuncSig{
			"caller":       {Name: "caller", Ret: Void, WASMContext: Ptr},
			"tailer":       {Name: "tailer", Ret: Void, WASMContext: Ptr},
			"target":       {Name: "target", Ret: Void, WASMContext: Ptr},
			"helper$local": {Name: "helper$local", Args: []LLVMType{I32}, ArgRegs: []Reg{"R0"}, Ret: I32, WASMContext: Ptr},
		},
		ResolveSym: resolveWasmTestLocal,
		Goarch:     "wasm",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"define void @caller(ptr %wasm_context)",
		`call i32 @"helper$local"(ptr %`,
		"tail call void @target(ptr %",
		`define i32 @"helper$local"(ptr %wasm_context, i32 %arg0)`,
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("closure-context call IR is missing %q:\n%s", want, ir)
		}
	}
}

func TestWasmGoABIFrameAndSymbolMemory(t *testing.T) {
	file, err := Parse(ArchWASM, `TEXT memory(SB), NOSPLIT, $16-16
	MOVD value+0(FP), R0
	MOVD R0, result+8(FP)
	MOVD $data+8(SB), R1
	MOVD R0, data+8(SB)
	MOVD data+8(SB), R2
	MOVD $16(R1), R3
	MOVD R2, 0(R3)
	MOVD 0(R3), R4
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "wasm32-unknown-unknown",
		Sigs: map[string]FuncSig{
			"memory": {
				Name: "memory", Args: []LLVMType{I64}, Ret: I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				},
			},
		},
		Goarch:  "wasm",
		WASMABI: WASMABIGo,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"getelementptr i8, ptr",
		"load i64",
		"store i64",
		`@"\C2\B7data"`,
		"ret i32 0",
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("Go wasm frame/symbol IR is missing %q:\n%s", want, ir)
		}
	}
}

func TestWasmFloatComparisonAndConversion(t *testing.T) {
	file, err := Parse(ArchWASM, `TEXT ne(SB), NOSPLIT, $0-0
	F64Const $4607182418800017408
	F64Const $4611686018427387904
	F64Ne
	Return

TEXT gt(SB), NOSPLIT, $0-0
	F64Const $4611686018427387904
	F64Const $4607182418800017408
	F64Gt
	Return

TEXT lt(SB), NOSPLIT, $0-0
	F64Const $4607182418800017408
	F64Const $4611686018427387904
	F64Lt
	Return

TEXT signed(SB), NOSPLIT, $0-0
	F64Const $4607182418800017408
	I64TruncF64S
	Return

TEXT unsigned(SB), NOSPLIT, $0-0
	F64Const $4607182418800017408
	I64TruncF64U
	Return
`)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{
		"ne": {Name: "ne", Ret: I32}, "gt": {Name: "gt", Ret: I32}, "lt": {Name: "lt", Ret: I32},
		"signed": {Name: "signed", Ret: I64}, "unsigned": {Name: "unsigned", Ret: I64},
	}
	ir, err := Translate(file, Options{TargetTriple: "wasm32-unknown-unknown", Sigs: sigs, Goarch: "wasm"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fcmp une double", "fcmp ogt double", "fcmp olt double", "fptosi double", "fptoui double"} {
		if !strings.Contains(ir, want) {
			t.Fatalf("floating wasm IR is missing %q:\n%s", want, ir)
		}
	}
}

func TestWasmNeedsIncomingContextOrder(t *testing.T) {
	parseFunc := func(t *testing.T, body string) Func {
		t.Helper()
		file, err := Parse(ArchWASM, "TEXT context(SB), NOSPLIT, $0-0\n"+body+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		return file.Funcs[0]
	}
	if !wasmNeedsIncomingContext(parseFunc(t, "Get CTXT\nDrop")) {
		t.Fatal("read-before-write CTXT was not detected")
	}
	if wasmNeedsIncomingContext(parseFunc(t, "I64Const $1\nSet CTXT\nGet CTXT\nDrop")) {
		t.Fatal("write-before-read CTXT was incorrectly treated as an incoming context")
	}
	if got := wasmGoGlobalName(Reg("ret0")); got != "RET0" {
		t.Fatalf("wasmGoGlobalName(ret0) = %q, want RET0", got)
	}
}

func resolveWasmTestLocal(sym string) string {
	if strings.HasSuffix(sym, "<>") {
		return strings.TrimSuffix(sym, "<>") + "$local"
	}
	return sym
}
