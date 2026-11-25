package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestTranslateIRTextCoverage(t *testing.T) {
	resolve := testResolveSym("example")
	if _, err := translateIRText(nil, Options{}); err == nil {
		t.Fatalf("translateIRText(nil) unexpectedly succeeded")
	}
	if _, err := translateIRText(&File{Arch: ArchAMD64}, Options{}); err == nil {
		t.Fatalf("translateIRText(empty) unexpectedly succeeded")
	}

	file := &File{
		Arch: ArchAMD64,
		Funcs: []Func{{
			Sym: "·f",
			Instrs: []Instr{
				{Op: OpTEXT, Raw: "TEXT ·f(SB),NOSPLIT,$0-0"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpSym, Sym: "other+8(SB)"}, {Kind: OpReg, Reg: AX}}, Raw: "MOVQ other+8(SB), AX"},
				{Op: OpRET, Raw: "RET"},
			},
		}},
		Data:  []DataStmt{{Sym: "tbl", Off: 0, Width: 4, Value: 0x11223344}},
		Globl: []GloblStmt{{Sym: "tbl", Flags: "RODATA", Size: 8}},
	}
	opt := Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym:   resolve,
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"example.f":      {Name: "example.f", Ret: I64},
			"example.helper": {Name: "example.helper", Args: []LLVMType{I64}, Ret: Void},
		},
	}
	ir, err := translateIRText(file, opt)
	if err != nil {
		t.Fatalf("translateIRText() error = %v", err)
	}
	for _, want := range []string{
		`target triple = "x86_64-unknown-linux-gnu"`,
		`@"example.other" = external global i8`,
		`@"example.tbl" = constant [8 x i8] [i8 68, i8 51, i8 34, i8 17`,
		`declare void @"example.helper"(i64)`,
		`define i64 @"example.f"()`,
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("missing %q in IR:\n%s", want, ir)
		}
	}

	mismatch := *file
	if _, err := translateIRText(&mismatch, Options{
		ResolveSym: resolve,
		Sigs: map[string]FuncSig{
			"example.f": {Name: "bad.name", Ret: I64},
		},
	}); err == nil {
		t.Fatalf("translateIRText(name mismatch) unexpectedly succeeded")
	}
	if _, err := translateIRText(&mismatch, Options{
		ResolveSym: resolve,
		Sigs: map[string]FuncSig{
			"example.f": {Name: "example.f"},
		},
	}); err == nil {
		t.Fatalf("translateIRText(missing ret) unexpectedly succeeded")
	}

	armFile := &File{
		Arch: ArchARM,
		Funcs: []Func{{
			Sym: "·armbad",
			Instrs: []Instr{
				{Op: OpTEXT, Raw: "TEXT ·armbad(SB),NOSPLIT,$0-0"},
				{Op: "MOVW", Args: []Operand{{Kind: OpImm, ImmRaw: "$(sym)"}}, Raw: "MOVW $(sym), R0"},
				{Op: OpRET, Raw: "RET"},
			},
		}},
	}
	if _, err := translateIRText(armFile, Options{
		ResolveSym: resolve,
		Sigs: map[string]FuncSig{
			"example.armbad": {Name: "example.armbad", Ret: Void},
		},
	}); err == nil {
		t.Fatalf("translateIRText(unresolved arm imm) unexpectedly succeeded")
	}

	if err := validateResolvedImmediates(ArchARM, Func{
		Instrs: []Instr{{Args: []Operand{{Kind: OpImm, ImmRaw: "$(sym)"}}}},
	}); err == nil {
		t.Fatalf("validateResolvedImmediates(arm) unexpectedly succeeded")
	}
	if err := validateResolvedImmediates(ArchAMD64, Func{
		Instrs: []Instr{{Args: []Operand{{Kind: OpImm, ImmRaw: "$(sym)"}}}},
	}); err != nil {
		t.Fatalf("validateResolvedImmediates(amd64) error = %v", err)
	}

	var dataIR strings.Builder
	if err := emitDataGlobals(&dataIR, &File{
		Data: []DataStmt{{Sym: "bad", Off: 0, Width: -1, Value: 1}},
	}, resolve); err == nil {
		t.Fatalf("emitDataGlobals(invalid width) unexpectedly succeeded")
	}
	if err := emitDataGlobals(&dataIR, &File{
		Globl: []GloblStmt{{Sym: "bad", Size: 2}},
		Data:  []DataStmt{{Sym: "bad", Off: -1, Width: 1, Value: 1}},
	}, resolve); err == nil {
		t.Fatalf("emitDataGlobals(oob) unexpectedly succeeded")
	}
	if err := emitDataGlobals(&dataIR, &File{
		Globl: []GloblStmt{{Sym: "huge", Size: maxDataGlobalSize + 1}},
	}, resolve); err == nil {
		t.Fatalf("emitDataGlobals(huge) unexpectedly succeeded")
	}
	if err := emitDataGlobals(&dataIR, &File{
		Data: []DataStmt{{Sym: "dataOnly", Width: 1, Value: 1}},
	}, resolve); err != nil {
		t.Fatalf("emitDataGlobals(data-only) error = %v", err)
	}

	if got := bestAlign(32); got != 16 {
		t.Fatalf("bestAlign(32) = %d", got)
	}
	if got := bestAlign(3); got != 1 {
		t.Fatalf("bestAlign(3) = %d", got)
	}
	if got := llvmI8ArrayInit(nil); got != "zeroinitializer" {
		t.Fatalf("llvmI8ArrayInit(nil) = %q", got)
	}
	if got := llvmI8ArrayInit([]byte{1, 2, 3}); got != "[i8 1, i8 2, i8 3]" {
		t.Fatalf("llvmI8ArrayInit([1 2 3]) = %q", got)
	}
}

func TestTranslateHelpersCoverage(t *testing.T) {
	resolve := testResolveSym("example")

	file := &File{
		Arch: ArchAMD64,
		Funcs: []Func{{
			Sym: "·entry",
			Instrs: []Instr{
				{Op: OpTEXT, Raw: "TEXT ·entry(SB),NOSPLIT,$0-0"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpSym, Sym: "data<>(SB)"}, {Kind: OpReg, Reg: AX}}, Raw: "MOVQ data<>(SB), AX"},
				{Op: "CALL", Args: []Operand{{Kind: OpSym, Sym: "helper(SB)"}}, Raw: "CALL helper(SB)"},
				{Op: OpRET, Raw: "RET"},
			},
		}},
		Globl: []GloblStmt{{Sym: "data", Size: 8}},
		Data:  []DataStmt{{Sym: "data", Off: 0, Width: 8, Value: 1}},
	}
	got, err := Translate(file, Options{
		ResolveSym: resolve,
		Goarch:     "amd64",
		Sigs: map[string]FuncSig{
			"example.entry":  {Name: "example.entry", Ret: I64},
			"example.helper": {Name: "example.helper", Ret: Void},
		},
	})
	if err != nil {
		t.Fatalf("Translate() error = %v", err)
	}
	for _, want := range []string{`@example.entry`, `@example.data`} {
		if !strings.Contains(got, want) {
			t.Fatalf("Translate() missing %q in:\n%s", want, got)
		}
	}
	if _, err := Translate(file, Options{
		ResolveSym: resolve,
		Goarch:     "amd64",
		Sigs:       map[string]FuncSig{},
	}); err == nil {
		t.Fatalf("Translate(missing sig) unexpectedly succeeded")
	}

	var decls strings.Builder
	emitExternFuncDecls(&decls, file, resolve, map[string]FuncSig{
		"example.entry":  {Name: "example.entry", Ret: I64},
		"example.helper": {Name: "example.helper", Ret: Void, Args: []LLVMType{I64}, Attrs: "#7"},
		"example.zed":    {Name: "example.zed"},
	}, WASMABIDirect)
	declOut := decls.String()
	if strings.Contains(declOut, "example.entry") || (!strings.Contains(declOut, `declare void @example.helper(i64) #7`) && !strings.Contains(declOut, `declare void @"example.helper"(i64) #7`)) {
		t.Fatalf("emitExternFuncDecls() output = %q", declOut)
	}

	var exts strings.Builder
	emitExternSBGlobals(&exts, &File{
		Funcs: []Func{{
			Sym: "·f",
			Instrs: []Instr{
				{Op: OpMOVQ, Args: []Operand{{Kind: OpSym, Sym: "data+8(SB)"}, {Kind: OpReg, Reg: AX}}},
				{Op: "CALL", Args: []Operand{{Kind: OpSym, Sym: "callee(SB)"}}},
				{Op: "JMP", Args: []Operand{{Kind: OpSym, Sym: "skip(SB)"}}},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpSym, Sym: "pkg/path.sym(SB)"}, {Kind: OpReg, Reg: AX}}},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpSym, Sym: "$const+4(SB)"}, {Kind: OpReg, Reg: AX}}},
			},
		}},
	}, resolve, map[string]FuncSig{
		"example.callee": {Name: "example.callee", Ret: Void},
	})
	extOut := exts.String()
	for _, want := range []string{`@"example.data" = external global i8`, `@"pkg/path.sym" = external global i8`, `@"example.const" = external global i8`} {
		if !strings.Contains(extOut, want) {
			t.Fatalf("emitExternSBGlobals() missing %q in:\n%s", want, extOut)
		}
	}
	for _, bad := range []string{`@"example.callee" = external global i8`, `@"example.skip" = external global i8`} {
		if strings.Contains(extOut, bad) {
			t.Fatalf("emitExternSBGlobals() unexpectedly included %q in:\n%s", bad, extOut)
		}
	}
}

func TestTranslateModuleDirectAndFallbackCoverage(t *testing.T) {
	resolve := testResolveSym("example")
	if _, err := translateModuleDirect(nil, Options{}); err == nil {
		t.Fatalf("translateModuleDirect(nil) unexpectedly succeeded")
	}
	if _, err := translateModuleDirect(&File{Arch: ArchAMD64}, Options{}); err == nil {
		t.Fatalf("translateModuleDirect(empty) unexpectedly succeeded")
	}
	if _, err := translateModuleDirect(&File{
		Arch:  ArchAMD64,
		Funcs: []Func{{Sym: "·f", Instrs: []Instr{{Op: OpTEXT}, {Op: OpRET}}}},
	}, Options{
		AnnotateSource: true,
		ResolveSym:     resolve,
		Sigs:           map[string]FuncSig{"example.f": {Name: "example.f", Ret: Void}},
	}); !errors.Is(err, errDirectModuleUnsupported) {
		t.Fatalf("translateModuleDirect(annotate) error = %v", err)
	}

	file := &File{
		Arch: ArchAMD64,
		Funcs: []Func{
			{
				Sym: "·linear",
				Instrs: []Instr{
					{Op: OpTEXT, Raw: "TEXT ·linear(SB),NOSPLIT,$0-0"},
					{Op: OpMOVQ, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}, Raw: "MOVQ $1, AX"},
					{Op: OpMOVL, Args: []Operand{{Kind: OpImm, Imm: 2}, {Kind: OpReg, Reg: BX}}, Raw: "MOVL $2, BX"},
					{Op: OpADDQ, Args: []Operand{{Kind: OpReg, Reg: BX}, {Kind: OpReg, Reg: AX}}, Raw: "ADDQ BX, AX"},
					{Op: OpSUBQ, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}, Raw: "SUBQ $1, AX"},
					{Op: OpXORQ, Args: []Operand{{Kind: OpReg, Reg: BX}, {Kind: OpReg, Reg: AX}}, Raw: "XORQ BX, AX"},
					{Op: OpCPUID, Raw: "CPUID"},
					{Op: OpXGETBV, Raw: "XGETBV"},
					{Op: OpRET, Raw: "RET"},
				},
			},
			{
				Sym: "·pair",
				Instrs: []Instr{
					{Op: OpTEXT, Raw: "TEXT ·pair(SB),NOSPLIT,$0-16"},
					{Op: OpMOVL, Args: []Operand{{Kind: OpImm, Imm: 7}, {Kind: OpFP, FPOffset: 8}}, Raw: "MOVL $7, ret+8(FP)"},
					{Op: OpMOVQ, Args: []Operand{{Kind: OpImm, Imm: 9}, {Kind: OpFP, FPOffset: 16}}, Raw: "MOVQ $9, ret+16(FP)"},
					{Op: OpRET, Raw: "RET"},
				},
			},
		},
		Data:  []DataStmt{{Sym: "blob", Off: 0, Width: 2, Value: 0x2211}},
		Globl: []GloblStmt{{Sym: "blob", Size: 4}},
	}
	mod, err := translateModuleDirect(file, Options{
		ResolveSym: resolve,
		Goarch:     "amd64",
		Sigs: map[string]FuncSig{
			"example.linear": {Name: "example.linear", Ret: I64},
			"example.pair": {
				Name: "example.pair",
				Ret:  LLVMType("{i32, i64}"),
				Frame: FrameLayout{
					Results: []FrameSlot{
						{Offset: 8, Type: I32, Index: 0, Field: -1},
						{Offset: 16, Type: I64, Index: 1, Field: -1},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("translateModuleDirect(amd64) error = %v", err)
	}
	defer mod.Dispose()
	modIR := mod.String()
	for _, want := range []string{`@example.linear`, `@example.pair`, `@example.blob`} {
		if !strings.Contains(modIR, want) {
			t.Fatalf("missing %q in direct module:\n%s", want, modIR)
		}
	}

	arm64File := &File{
		Arch: ArchARM64,
		Funcs: []Func{{
			Sym: "·arm64m",
			Instrs: []Instr{
				{Op: OpTEXT, Raw: "TEXT ·arm64m(SB),NOSPLIT,$0-0"},
				{Op: OpMRS, Args: []Operand{{Kind: OpIdent, Ident: "MIDR_EL1"}, {Kind: OpReg, Reg: "R1"}}, Raw: "MRS MIDR_EL1, R1"},
				{Op: OpMOVD, Args: []Operand{{Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R0"}}, Raw: "MOVD R1, R0"},
				{Op: OpRET, Raw: "RET"},
			},
		}},
	}
	armMod, err := translateModuleDirect(arm64File, Options{
		ResolveSym: resolve,
		Goarch:     "arm64",
		Sigs:       map[string]FuncSig{"example.arm64m": {Name: "example.arm64m", Ret: I64}},
	})
	if err != nil {
		t.Fatalf("translateModuleDirect(arm64) error = %v", err)
	}
	defer armMod.Dispose()
	if !strings.Contains(armMod.String(), `@example.arm64m`) {
		t.Fatalf("arm64 direct module missing function:\n%s", armMod.String())
	}

	cfgFile := &File{
		Arch: ArchAMD64,
		Funcs: []Func{{
			Sym: "·cfg",
			Instrs: []Instr{
				{Op: OpTEXT, Raw: "TEXT ·cfg(SB),NOSPLIT,$0-0"},
				{Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: "loop"}}, Raw: "loop:"},
				{Op: OpRET, Raw: "RET"},
			},
		}},
	}
	fallbackMod, err := TranslateModule(cfgFile, Options{
		ResolveSym: resolve,
		Goarch:     "amd64",
		Sigs:       map[string]FuncSig{"example.cfg": {Name: "example.cfg", Ret: I64}},
	})
	if err != nil {
		t.Fatalf("TranslateModule(fallback) error = %v", err)
	}
	defer fallbackMod.Dispose()
	if !strings.Contains(fallbackMod.String(), `@example.cfg`) {
		t.Fatalf("fallback module missing function:\n%s", fallbackMod.String())
	}

	if _, err := translateModuleDirect(&File{
		Arch: ArchAMD64,
		Funcs: []Func{{
			Sym:    "·noret",
			Instrs: []Instr{{Op: OpTEXT, Raw: "TEXT ·noret(SB),NOSPLIT,$0-0"}},
		}},
	}, Options{
		ResolveSym: resolve,
		Goarch:     "amd64",
		Sigs:       map[string]FuncSig{"example.noret": {Name: "example.noret", Ret: I64}},
	}); !errors.Is(err, errDirectModuleUnsupported) {
		t.Fatalf("translateModuleDirect(noret) error = %v", err)
	}
	if _, err := translateModuleDirect(&File{
		Arch: ArchAMD64,
		Funcs: []Func{{
			Sym:    "·afterret",
			Instrs: []Instr{{Op: OpTEXT}, {Op: OpRET}, {Op: OpMOVQ}},
		}},
	}, Options{
		ResolveSym: resolve,
		Goarch:     "amd64",
		Sigs:       map[string]FuncSig{"example.afterret": {Name: "example.afterret", Ret: I64}},
	}); !errors.Is(err, errDirectModuleUnsupported) {
		t.Fatalf("translateModuleDirect(afterret) error = %v", err)
	}

	ctx := llvm.GlobalContext()
	tmpMod := ctx.NewModule("tmp")
	defer tmpMod.Dispose()
	if err := emitDataGlobalsModule(tmpMod, &File{
		Data: []DataStmt{{Sym: "bad", Width: -1, Value: 1}},
	}, resolve); err == nil {
		t.Fatalf("emitDataGlobalsModule(invalid width) unexpectedly succeeded")
	}
	if err := emitDataGlobalsModule(tmpMod, &File{
		Globl: []GloblStmt{{Sym: "bad", Size: 2}},
		Data:  []DataStmt{{Sym: "bad", Off: -1, Width: 1, Value: 1}},
	}, resolve); err == nil {
		t.Fatalf("emitDataGlobalsModule(oob) unexpectedly succeeded")
	}

	if ty, err := llvmTypeFromLLVMType(ctx, LLVMType("{i32, i64}")); err != nil || ty.C == nil {
		t.Fatalf("llvmTypeFromLLVMType(struct) = (%v, %v)", ty, err)
	}
	if _, err := llvmTypeFromLLVMType(ctx, LLVMType("v2i64")); !errors.Is(err, errDirectModuleUnsupported) {
		t.Fatalf("llvmTypeFromLLVMType(v2i64) error = %v", err)
	}
	if bits, ok := llvmIntBits(I32); !ok || bits != 32 {
		t.Fatalf("llvmIntBits(I32) = (%d, %v)", bits, ok)
	}
	if _, ok := llvmIntBits(Ptr); ok {
		t.Fatalf("llvmIntBits(ptr) unexpectedly succeeded")
	}
}

func TestTranslateModuleDirectErrorCoverage(t *testing.T) {
	resolve := testResolveSym("example")

	baseFile := &File{
		Arch: ArchAMD64,
		Funcs: []Func{{
			Sym:    "·f",
			Instrs: []Instr{{Op: OpTEXT, Raw: "TEXT ·f(SB),NOSPLIT,$0-0"}, {Op: OpRET, Raw: "RET"}},
		}},
	}
	if _, err := translateModuleDirect(baseFile, Options{ResolveSym: resolve, Goarch: "amd64"}); err == nil {
		t.Fatalf("translateModuleDirect(missing sig) unexpectedly succeeded")
	}
	if _, err := translateModuleDirect(baseFile, Options{
		ResolveSym: resolve,
		Goarch:     "amd64",
		Sigs:       map[string]FuncSig{"example.f": {Name: "bad.name", Ret: I64}},
	}); err == nil {
		t.Fatalf("translateModuleDirect(name mismatch) unexpectedly succeeded")
	}
	if _, err := translateModuleDirect(baseFile, Options{
		ResolveSym: resolve,
		Goarch:     "amd64",
		Sigs:       map[string]FuncSig{"example.f": {Name: "example.f"}},
	}); err == nil {
		t.Fatalf("translateModuleDirect(missing ret) unexpectedly succeeded")
	}
	if _, err := translateModuleDirect(baseFile, Options{
		ResolveSym: resolve,
		Goarch:     "386",
		Sigs:       map[string]FuncSig{"example.f": {Name: "example.f", Ret: Void}},
	}); err == nil || !strings.Contains(err.Error(), "x86 CFG lowering required") {
		t.Fatalf("translateModuleDirect(386) error = %v", err)
	}

	for _, tc := range []struct {
		name string
		file *File
		opt  Options
	}{
		{
			name: "unresolved-arm-imm",
			file: &File{Arch: ArchARM, Funcs: []Func{{
				Sym:    "·armbad",
				Instrs: []Instr{{Op: OpTEXT}, {Op: "MOVW", Args: []Operand{{Kind: OpImm, ImmRaw: "$(sym)"}, {Kind: OpReg, Reg: "R0"}}}, {Op: OpRET}},
			}}},
			opt: Options{ResolveSym: resolve, Sigs: map[string]FuncSig{"example.armbad": {Name: "example.armbad", Ret: Void}}},
		},
		{
			name: "arm-cfg",
			file: &File{Arch: ArchARM, Funcs: []Func{{
				Sym:    "·armcfg",
				Instrs: []Instr{{Op: OpTEXT}, {Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: "loop"}}}, {Op: OpRET}},
			}}},
			opt: Options{ResolveSym: resolve, Sigs: map[string]FuncSig{"example.armcfg": {Name: "example.armcfg", Ret: Void}}},
		},
		{
			name: "arm64-cfg",
			file: &File{Arch: ArchARM64, Funcs: []Func{{
				Sym:    "·arm64cfg",
				Instrs: []Instr{{Op: OpTEXT}, {Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: "loop"}}}, {Op: OpRET}},
			}}},
			opt: Options{ResolveSym: resolve, Goarch: "arm64", Sigs: map[string]FuncSig{"example.arm64cfg": {Name: "example.arm64cfg", Ret: Void}}},
		},
		{
			name: "amd64-cfg",
			file: &File{Arch: ArchAMD64, Funcs: []Func{{
				Sym:    "·amd64cfg",
				Instrs: []Instr{{Op: OpTEXT}, {Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: "loop"}}}, {Op: OpRET}},
			}}},
			opt: Options{ResolveSym: resolve, Goarch: "amd64", Sigs: map[string]FuncSig{"example.amd64cfg": {Name: "example.amd64cfg", Ret: I64}}},
		},
	} {
		if _, err := translateModuleDirect(tc.file, tc.opt); !errors.Is(err, errDirectModuleUnsupported) {
			t.Fatalf("%s error = %v", tc.name, err)
		}
	}

	ctx := llvm.GlobalContext()
	for _, tc := range []struct {
		name string
		fn   Func
		sig  FuncSig
	}{
		{
			name: "mrs-arity",
			fn:   Func{Sym: "example.bad1", Instrs: []Instr{{Op: OpTEXT}, {Op: OpMRS, Args: []Operand{{Kind: OpIdent, Ident: "MIDR_EL1"}}}, {Op: OpRET}}},
			sig:  FuncSig{Name: "example.bad1", Ret: I64},
		},
		{
			name: "movd-bad-dst",
			fn:   Func{Sym: "example.bad2", Instrs: []Instr{{Op: OpTEXT}, {Op: OpMOVD, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpIdent, Ident: "label"}}}, {Op: OpRET}}},
			sig:  FuncSig{Name: "example.bad2", Ret: I64},
		},
		{
			name: "movl-bad-dst",
			fn:   Func{Sym: "example.bad3", Instrs: []Instr{{Op: OpTEXT}, {Op: OpMOVL, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpIdent, Ident: "label"}}}, {Op: OpRET}}},
			sig:  FuncSig{Name: "example.bad3", Ret: I64},
		},
		{
			name: "addq-bad-dst",
			fn:   Func{Sym: "example.bad4", Instrs: []Instr{{Op: OpTEXT}, {Op: OpADDQ, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpIdent, Ident: "label"}}}, {Op: OpRET}}},
			sig:  FuncSig{Name: "example.bad4", Ret: I64},
		},
		{
			name: "invalid-op-kind",
			fn:   Func{Sym: "example.bad5", Instrs: []Instr{{Op: OpTEXT}, {Op: OpMOVQ, Args: []Operand{{Kind: OpLabel, Sym: "x"}, {Kind: OpReg, Reg: AX}}}, {Op: OpRET}}},
			sig:  FuncSig{Name: "example.bad5", Ret: I64},
		},
		{
			name: "bad-result-index",
			fn:   Func{Sym: "example.bad6", Instrs: []Instr{{Op: OpTEXT}, {Op: OpMOVQ, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpFP, FPOffset: 8}}}, {Op: OpRET}}},
			sig:  FuncSig{Name: "example.bad6", Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Offset: 8, Type: I64, Index: 3}}}},
		},
		{
			name: "bad-fp-read",
			fn:   Func{Sym: "example.bad7", Instrs: []Instr{{Op: OpTEXT}, {Op: OpMOVQ, Args: []Operand{{Kind: OpFP, FPOffset: 8}, {Kind: OpReg, Reg: AX}}}, {Op: OpRET}}},
			sig:  FuncSig{Name: "example.bad7", Ret: I64, Frame: FrameLayout{Params: []FrameSlot{{Offset: 8, Type: I64, Index: 9}}}},
		},
		{
			name: "unsupported-insn",
			fn:   Func{Sym: "example.bad8", Instrs: []Instr{{Op: OpTEXT}, {Op: "UNDEF"}, {Op: OpRET}}},
			sig:  FuncSig{Name: "example.bad8", Ret: I64},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mod := ctx.NewModule("direct-errors-" + tc.name)
			defer mod.Dispose()
			if err := translateFuncLinearModule(mod, ArchAMD64, tc.fn, tc.sig); !errors.Is(err, errDirectModuleUnsupported) {
				t.Fatalf("%s error = %v", tc.name, err)
			}
		})
	}

	okMod := ctx.NewModule("direct-ok")
	defer okMod.Dispose()
	if err := translateFuncLinearModule(okMod, ArchAMD64, Func{
		Sym:    "example.byteok",
		Instrs: []Instr{{Op: OpTEXT}, {Op: OpRET}, {Op: OpBYTE}},
	}, FuncSig{Name: "example.byteok", Ret: I64}); err != nil {
		t.Fatalf("translateFuncLinearModule(byte-after-ret) error = %v", err)
	}
}

func TestTranslateFuncLinearCoverage(t *testing.T) {
	t.Run("AMD64AggregateAndCasts", func(t *testing.T) {
		fn := Func{
			Sym: "·linearAmd64",
			Instrs: []Instr{
				{Op: OpTEXT, Raw: "TEXT ·linearAmd64(SB),NOSPLIT,$0-16"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpFP, FPOffset: 0}, {Kind: OpReg, Reg: AX}}, Raw: "MOVQ arg+0(FP), AX"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpFP, FPOffset: 56}, {Kind: OpReg, Reg: BX}}, Raw: "MOVQ arg+56(FP), BX"},
				{Op: OpMOVL, Args: []Operand{{Kind: OpFP, FPOffset: 24}, {Kind: OpReg, Reg: CX}}, Raw: "MOVL arg+24(FP), CX"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: AX, Index: BX, Scale: 2, Off: 8}}, {Kind: OpReg, Reg: DX}}, Raw: "MOVQ 8(AX)(BX*2), DX"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpSym, Sym: "other(SB)"}, {Kind: OpReg, Reg: SI}}, Raw: "MOVQ other(SB), SI"},
				{Op: OpADDQ, Args: []Operand{{Kind: OpReg, Reg: BX}, {Kind: OpReg, Reg: AX}}, Raw: "ADDQ BX, AX"},
				{Op: OpSUBQ, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}, Raw: "SUBQ $1, AX"},
				{Op: OpXORQ, Args: []Operand{{Kind: OpReg, Reg: DX}, {Kind: OpReg, Reg: AX}}, Raw: "XORQ DX, AX"},
				{Op: OpCPUID, Raw: "CPUID"},
				{Op: OpXGETBV, Raw: "XGETBV"},
				{Op: OpMOVL, Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpFP, FPOffset: 80}}, Raw: "MOVL AX, ret+80(FP)"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpFP, FPOffset: 88}}, Raw: "MOVQ AX, ret+88(FP)"},
				{Op: OpRET, Raw: "RET"},
			},
		}
		sig := FuncSig{
			Name: "example.linearAmd64",
			Args: []LLVMType{Ptr, I1, I8, I16, I32, I64, LLVMType("float"), LLVMType("double")},
			Ret:  LLVMType("{i32, i64}"),
			Frame: FrameLayout{
				Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I1, Index: 1, Field: -1},
					{Offset: 16, Type: I8, Index: 2, Field: -1},
					{Offset: 24, Type: I16, Index: 3, Field: -1},
					{Offset: 32, Type: I32, Index: 4, Field: -1},
					{Offset: 40, Type: I64, Index: 5, Field: -1},
					{Offset: 48, Type: LLVMType("float"), Index: 6, Field: -1},
					{Offset: 56, Type: LLVMType("double"), Index: 7, Field: -1},
				},
				Results: []FrameSlot{
					{Offset: 80, Type: I32, Index: 0, Field: -1},
					{Offset: 88, Type: I64, Index: 1, Field: -1},
				},
			},
		}
		var b strings.Builder
		if err := translateFuncLinear(&b, ArchAMD64, fn, sig, true); err != nil {
			t.Fatalf("translateFuncLinear(amd64) error = %v", err)
		}
		out := b.String()
		for _, want := range []string{
			`define {i32, i64} @"example.linearAmd64"(ptr %arg0, i1 %arg1, i8 %arg2, i16 %arg3, i32 %arg4, i64 %arg5, float %arg6, double %arg7)`,
			"; s: MOVQ arg+0(FP), AX",
			"ptrtoint ptr %arg0 to i64",
			"fptoui double %arg7 to i64",
			"zext i16 %arg3 to i32",
			"mul i64",
			"inttoptr i64",
			"call { i32, i32, i32, i32 } asm sideeffect",
			"call { i32, i32 } asm sideeffect",
			"insertvalue {i32, i64}",
			"ret {i32, i64}",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %q in amd64 linear output:\n%s", want, out)
			}
		}
	})

	t.Run("ARMRegShiftAndRet", func(t *testing.T) {
		fn := Func{
			Sym: "·linearArm",
			Instrs: []Instr{
				{Op: OpTEXT, Raw: "TEXT ·linearArm(SB),NOSPLIT,$0-4"},
				{Op: "MOVW", Args: []Operand{{Kind: OpFP, FPOffset: 0}, {Kind: OpReg, Reg: "R0"}}, Raw: "MOVW arg+0(FP), R0"},
				{Op: "MOVBU", Args: []Operand{{Kind: OpFP, FPOffset: 8}, {Kind: OpReg, Reg: "R1"}}, Raw: "MOVBU arg+8(FP), R1"},
				{Op: "ADD", Args: []Operand{{Kind: OpRegShift, Reg: "R1", ShiftOp: ShiftLeft, ShiftAmount: 2}, {Kind: OpReg, Reg: "R0"}}, Raw: "ADD R1<<2, R0"},
				{Op: "SUB", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R2"}}, Raw: "SUB R0, R1, R2"},
				{Op: "AND", Args: []Operand{{Kind: OpReg, Reg: "R2"}, {Kind: OpReg, Reg: "R1"}}, Raw: "AND R2, R1"},
				{Op: "ORR", Args: []Operand{{Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R2"}, {Kind: OpReg, Reg: "R3"}}, Raw: "ORR R1, R2, R3"},
				{Op: "EOR", Args: []Operand{{Kind: OpReg, Reg: "R3"}, {Kind: OpReg, Reg: "R2"}, {Kind: OpReg, Reg: "R4"}}, Raw: "EOR R3, R2, R4"},
				{Op: "RSB", Args: []Operand{{Kind: OpReg, Reg: "R4"}, {Kind: OpReg, Reg: "R3"}, {Kind: OpReg, Reg: "R5"}}, Raw: "RSB R4, R3, R5"},
				{Op: "MOVW", Args: []Operand{{Kind: OpReg, Reg: "R5"}, {Kind: OpFP, FPOffset: 16}}, Raw: "MOVW R5, ret+16(FP)"},
				{Op: OpRET, Raw: "RET"},
			},
		}
		sig := FuncSig{
			Name: "example.linearArm",
			Args: []LLVMType{I32, I8},
			Ret:  I32,
			Frame: FrameLayout{
				Params: []FrameSlot{
					{Offset: 0, Type: I32, Index: 0, Field: -1},
					{Offset: 8, Type: I8, Index: 1, Field: -1},
				},
				Results: []FrameSlot{{Offset: 16, Type: I32, Index: 0, Field: -1}},
			},
		}
		var b strings.Builder
		if err := translateFuncLinear(&b, ArchARM, fn, sig, false); err != nil {
			t.Fatalf("translateFuncLinear(arm) error = %v", err)
		}
		out := b.String()
		for _, want := range []string{
			"shl i32",
			"add i32",
			"sub i32",
			"and i32",
			"or i32",
			"xor i32",
			"ret i32",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %q in arm linear output:\n%s", want, out)
			}
		}
	})

	t.Run("ARM64MRSAndDefaultReturn", func(t *testing.T) {
		fn := Func{
			Sym: "·linearArm64",
			Instrs: []Instr{
				{Op: OpTEXT, Raw: "TEXT ·linearArm64(SB),NOSPLIT,$0-8"},
				{Op: OpMRS, Args: []Operand{{Kind: OpIdent, Ident: "MIDR_EL1"}, {Kind: OpReg, Reg: "R1"}}, Raw: "MRS MIDR_EL1, R1"},
				{Op: OpMOVD, Args: []Operand{{Kind: OpFP, FPOffset: 0}, {Kind: OpReg, Reg: "R0"}}, Raw: "MOVD arg+0(FP), R0"},
				{Op: OpBYTE, Raw: "BYTE $0"},
			},
		}
		sig := FuncSig{
			Name: "example.linearArm64",
			Args: []LLVMType{I64},
			Ret:  I64,
			Frame: FrameLayout{
				Params: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
			},
		}
		var b strings.Builder
		if err := translateFuncLinear(&b, ArchARM64, fn, sig, false); err != nil {
			t.Fatalf("translateFuncLinear(arm64) error = %v", err)
		}
		out := b.String()
		for _, want := range []string{
			`define i64 @"example.linearArm64"(i64 %arg0)`,
			"ret i64 0",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %q in arm64 linear output:\n%s", want, out)
			}
		}
	})

	t.Run("VoidFastPath", func(t *testing.T) {
		var b strings.Builder
		if err := translateFuncLinear(&b, ArchAMD64, Func{Sym: "·void"}, FuncSig{Name: "example.void", Ret: Void}, false); err != nil {
			t.Fatalf("translateFuncLinear(void) error = %v", err)
		}
		if !strings.Contains(b.String(), "ret void") {
			t.Fatalf("void fast path missing ret void:\n%s", b.String())
		}
	})
}

func TestDirectModuleTypeHelperCoverage(t *testing.T) {
	ctx := llvm.GlobalContext()
	for _, tc := range []struct {
		ty   LLVMType
		ok   bool
		bits int
	}{
		{Void, true, 0},
		{I1, true, 1},
		{I8, true, 8},
		{I16, true, 16},
		{I32, true, 32},
		{I64, true, 64},
		{Ptr, true, 0},
		{LLVMType("float"), true, 0},
		{LLVMType("double"), true, 0},
		{LLVMType("{ i32, i64 }"), true, 0},
		{LLVMType("v2i64"), false, 0},
	} {
		_, err := llvmTypeFromLLVMType(ctx, tc.ty)
		if (err == nil) != tc.ok {
			t.Fatalf("llvmTypeFromLLVMType(%q) error = %v, want ok=%v", tc.ty, err, tc.ok)
		}
		if bits, ok := llvmIntBits(tc.ty); tc.bits == 0 {
			if (tc.ty == I1 || tc.ty == I8 || tc.ty == I16 || tc.ty == I32 || tc.ty == I64) && (!ok || bits != tc.bits) {
				t.Fatalf("llvmIntBits(%q) = (%d, %v)", tc.ty, bits, ok)
			}
		} else if bits != tc.bits || !ok {
			t.Fatalf("llvmIntBits(%q) = (%d, %v), want (%d, true)", tc.ty, bits, ok, tc.bits)
		}
	}
	if bits, ok := llvmIntBits(Ptr); ok || bits != 0 {
		t.Fatalf("llvmIntBits(ptr) = (%d, %v)", bits, ok)
	}

	mod := ctx.NewModule("data-helper")
	defer mod.Dispose()
	if err := emitDataGlobalsModule(mod, &File{Globl: []GloblStmt{{Sym: "huge", Size: maxDataGlobalSize + 1}}}, testResolveSym("example")); err == nil {
		t.Fatalf("emitDataGlobalsModule(huge) unexpectedly succeeded")
	}
	if err := emitDataGlobalsModule(mod, &File{Data: []DataStmt{{Sym: "bad", Width: 0}}}, testResolveSym("example")); err == nil {
		t.Fatalf("emitDataGlobalsModule(width=0) unexpectedly succeeded")
	}
	if err := emitDataGlobalsModule(mod, &File{Data: []DataStmt{{Sym: "dataOnly", Width: 1, Value: 1}}}, testResolveSym("example")); err != nil {
		t.Fatalf("emitDataGlobalsModule(data-only) error = %v", err)
	}
	if err := emitDataGlobalsModule(mod, &File{
		Globl: []GloblStmt{{Sym: "small", Size: 1}},
		Data:  []DataStmt{{Sym: "small", Off: -1, Width: 1, Value: 1}},
	}, testResolveSym("example")); err == nil {
		t.Fatalf("emitDataGlobalsModule(oob) unexpectedly succeeded")
	}
}

func TestTranslateFuncLinearModuleSuccessCoverage(t *testing.T) {
	ctx := llvm.GlobalContext()

	mod1 := ctx.NewModule("direct-success-1")
	defer mod1.Dispose()
	err := translateFuncLinearModule(mod1, ArchARM64, Func{
		Sym: "example.aggregate",
		Instrs: []Instr{
			{Op: OpTEXT},
			{Op: OpMOVD, Args: []Operand{{Kind: OpFP, FPOffset: 0}, {Kind: OpReg, Reg: "R2"}}, Raw: "MOVD pair+0(FP), R2"},
			{Op: OpMOVL, Args: []Operand{{Kind: OpFP, FPOffset: 8}, {Kind: OpReg, Reg: "R3"}}, Raw: "MOVL pair+8(FP), R3"},
			{Op: OpMOVD, Args: []Operand{{Kind: OpReg, Reg: "R2"}, {Kind: OpFP, FPOffset: 24}}, Raw: "MOVD R2, ret+24(FP)"},
			{Op: OpMOVL, Args: []Operand{{Kind: OpReg, Reg: "R3"}, {Kind: OpFP, FPOffset: 32}}, Raw: "MOVL R3, ret+32(FP)"},
			{Op: OpRET},
		},
	}, FuncSig{
		Name: "example.aggregate",
		Args: []LLVMType{LLVMType("{ ptr, i32 }")},
		Ret:  LLVMType("{ i64, i32 }"),
		Frame: FrameLayout{
			Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: 0},
				{Offset: 8, Type: I32, Index: 0, Field: 1},
			},
			Results: []FrameSlot{
				{Offset: 24, Type: I64, Index: 0},
				{Offset: 32, Type: I32, Index: 1},
			},
		},
	})
	if err != nil {
		t.Fatalf("translateFuncLinearModule(aggregate) error = %v", err)
	}

	mod2 := ctx.NewModule("direct-success-2")
	defer mod2.Dispose()
	err = translateFuncLinearModule(mod2, ArchARM, Func{
		Sym: "example.armret",
		Instrs: []Instr{
			{Op: OpTEXT},
			{Op: OpMOVD, Args: []Operand{{Kind: OpImm, Imm: 5}, {Kind: OpReg, Reg: "R0"}}, Raw: "MOVD $5, R0"},
			{Op: OpRET},
		},
	}, FuncSig{Name: "example.armret", Ret: I64})
	if err != nil {
		t.Fatalf("translateFuncLinearModule(arm-ret) error = %v", err)
	}

	mod3 := ctx.NewModule("direct-success-3")
	defer mod3.Dispose()
	err = translateFuncLinearModule(mod3, ArchAMD64, Func{
		Sym:    "example.zero",
		Instrs: []Instr{{Op: OpTEXT}, {Op: OpRET}},
	}, FuncSig{Name: "example.zero", Ret: I64})
	if err != nil {
		t.Fatalf("translateFuncLinearModule(zero-ret) error = %v", err)
	}

	mod4 := ctx.NewModule("direct-success-4")
	defer mod4.Dispose()
	err = translateFuncLinearModule(mod4, ArchAMD64, Func{
		Sym: "example.ptrcast",
		Instrs: []Instr{
			{Op: OpTEXT},
			{Op: OpMOVQ, Args: []Operand{{Kind: OpImm, Imm: 9}, {Kind: OpFP, FPOffset: 8}}, Raw: "MOVQ $9, ret+8(FP)"},
			{Op: OpRET},
		},
	}, FuncSig{
		Name: "example.ptrcast",
		Ret:  Ptr,
		Frame: FrameLayout{
			Results: []FrameSlot{{Offset: 8, Type: Ptr, Index: 0}},
		},
	})
	if err != nil {
		t.Fatalf("translateFuncLinearModule(ptrcast) error = %v", err)
	}
}

func TestTranslateFuncLinearCastAndErrorCoverage(t *testing.T) {
	t.Run("CastMatrix", func(t *testing.T) {
		fn := Func{
			Sym: "·casts",
			Instrs: []Instr{
				{Op: OpTEXT, Raw: "TEXT ·casts(SB),NOSPLIT,$0-0"},
				{Op: OpMOVL, Args: []Operand{{Kind: OpFP, FPOffset: 0}, {Kind: OpReg, Reg: AX}}, Raw: "MOVL argp+0(FP), AX"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpFP, FPOffset: 8}, {Kind: OpReg, Reg: BX}}, Raw: "MOVQ arg1+8(FP), BX"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpFP, FPOffset: 16}, {Kind: OpReg, Reg: CX}}, Raw: "MOVQ arg8+16(FP), CX"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpFP, FPOffset: 24}, {Kind: OpReg, Reg: DX}}, Raw: "MOVQ arg16+24(FP), DX"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpFP, FPOffset: 32}, {Kind: OpReg, Reg: SI}}, Raw: "MOVQ arg32+32(FP), SI"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpFP, FPOffset: 40}, {Kind: OpReg, Reg: DI}}, Raw: "MOVQ argptr+40(FP), DI"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpFP, FPOffset: 48}, {Kind: OpReg, Reg: Reg("R8")}}, Raw: "MOVQ argf32+48(FP), R8"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpFP, FPOffset: 56}, {Kind: OpReg, Reg: Reg("R9")}}, Raw: "MOVQ argf64+56(FP), R9"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpImm, Imm: 123}, {Kind: OpFP, FPOffset: 80}}, Raw: "MOVQ $123, ret+80(FP)"},
				{Op: OpMOVL, Args: []Operand{{Kind: OpImm, Imm: 9}, {Kind: OpFP, FPOffset: 88}}, Raw: "MOVL $9, ret+88(FP)"},
				{Op: OpMOVL, Args: []Operand{{Kind: OpFP, FPOffset: 40}, {Kind: OpFP, FPOffset: 96}}, Raw: "MOVL argptr+40(FP), ret+96(FP)"},
				{Op: OpRET, Raw: "RET"},
			},
		}
		sig := FuncSig{
			Name: "example.casts",
			Args: []LLVMType{Ptr, I1, I8, I16, I32, Ptr, LLVMType("float"), LLVMType("double")},
			Ret:  LLVMType("{ptr, ptr, i32}"),
			Frame: FrameLayout{
				Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I1, Index: 1, Field: -1},
					{Offset: 16, Type: I8, Index: 2, Field: -1},
					{Offset: 24, Type: I16, Index: 3, Field: -1},
					{Offset: 32, Type: I32, Index: 4, Field: -1},
					{Offset: 40, Type: Ptr, Index: 5, Field: -1},
					{Offset: 48, Type: LLVMType("float"), Index: 6, Field: -1},
					{Offset: 56, Type: LLVMType("double"), Index: 7, Field: -1},
				},
				Results: []FrameSlot{
					{Offset: 80, Type: Ptr, Index: 0, Field: -1},
					{Offset: 88, Type: Ptr, Index: 1, Field: -1},
					{Offset: 96, Type: I32, Index: 2, Field: -1},
				},
			},
		}
		var b strings.Builder
		if err := translateFuncLinear(&b, ArchAMD64, fn, sig, false); err != nil {
			t.Fatalf("translateFuncLinear(cast matrix) error = %v", err)
		}
		out := b.String()
		for _, want := range []string{
			"ptrtoint ptr %arg0 to i32",
			"zext i1 %arg1 to i64",
			"zext i8 %arg2 to i64",
			"zext i16 %arg3 to i64",
			"zext i32 %arg4 to i64",
			"ptrtoint ptr %arg5 to i64",
			"fptoui float %arg6 to i64",
			"fptoui double %arg7 to i64",
			"inttoptr i64 %t9 to ptr",
			"inttoptr i32 %t11 to ptr",
			"insertvalue {ptr, ptr, i32}",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %q in cast matrix output:\n%s", want, out)
			}
		}
	})

	t.Run("AggregateAndFallbacks", func(t *testing.T) {
		fn := Func{
			Sym: "·aggLinear",
			Instrs: []Instr{
				{Op: OpTEXT, Raw: "TEXT ·aggLinear(SB),NOSPLIT,$0-0"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpFP, FPOffset: 0}, {Kind: OpReg, Reg: AX}}, Raw: "MOVQ pair+0(FP), AX"},
				{Op: OpMOVL, Args: []Operand{{Kind: OpFP, FPOffset: 8}, {Kind: OpReg, Reg: BX}}, Raw: "MOVL pair+8(FP), BX"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpFP, FPOffset: 99}, {Kind: OpReg, Reg: CX}}, Raw: "MOVQ missing+99(FP), CX"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: AX, Index: BX, Scale: 0, Off: 4}}, {Kind: OpReg, Reg: DX}}, Raw: "MOVQ 4(AX)(BX*0), DX"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpReg, Reg: DX}, {Kind: OpFP, FPOffset: 24}}, Raw: "MOVQ DX, ret+24(FP)"},
				{Op: OpRET, Raw: "RET"},
			},
		}
		sig := FuncSig{
			Name: "example.aggLinear",
			Args: []LLVMType{LLVMType("{i64, i32}")},
			Ret:  I64,
			Frame: FrameLayout{
				Params: []FrameSlot{
					{Offset: 0, Type: I64, Index: 0, Field: 0},
					{Offset: 8, Type: I32, Index: 0, Field: 1},
				},
				Results: []FrameSlot{{Offset: 24, Type: I64, Index: 0}},
			},
		}
		var b strings.Builder
		if err := translateFuncLinear(&b, ArchAMD64, fn, sig, false); err != nil {
			t.Fatalf("translateFuncLinear(aggregate) error = %v", err)
		}
		out := b.String()
		for _, want := range []string{
			"extractvalue {i64, i32} %arg0, 0",
			"extractvalue {i64, i32} %arg0, 1",
			"mul i64",
			"add i64",
			"load i64, ptr",
			"ret i64",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %q in aggregate output:\n%s", want, out)
			}
		}
	})

	t.Run("ErrorAndFallbackPaths", func(t *testing.T) {
		cases := []struct {
			name    string
			arch    Arch
			fn      Func
			sig     FuncSig
			wantErr string
			wantIR  string
		}{
			{
				name: "AggregateMemBaseFallsBackToZero",
				arch: ArchAMD64,
				fn: Func{
					Sym: "·aggmem",
					Instrs: []Instr{
						{Op: OpTEXT, Raw: "TEXT ·aggmem(SB),NOSPLIT,$0-0"},
						{Op: OpMOVQ, Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: AX}}, {Kind: OpReg, Reg: AX}}, Raw: "MOVQ (AX), AX"},
						{Op: OpRET, Raw: "RET"},
					},
				},
				sig: FuncSig{
					Name:    "example.aggmem",
					Args:    []LLVMType{LLVMType("{i64, i32}")},
					ArgRegs: []Reg{AX},
					Ret:     I64,
				},
				wantIR: "add i64 0, 0",
			},
			{
				name: "BadSetResultCast",
				arch: ArchAMD64,
				fn: Func{
					Sym: "·badres",
					Instrs: []Instr{
						{Op: OpTEXT, Raw: "TEXT ·badres(SB),NOSPLIT,$0-0"},
						{Op: OpMOVQ, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpFP, FPOffset: 8}}, Raw: "MOVQ $1, ret+8(FP)"},
						{Op: OpRET, Raw: "RET"},
					},
				},
				sig: FuncSig{
					Name: "example.badres",
					Ret:  LLVMType("v2i64"),
					Frame: FrameLayout{
						Results: []FrameSlot{{Offset: 8, Type: LLVMType("v2i64"), Index: 0}},
					},
				},
				wantErr: "unsupported cast i64 -> v2i64",
			},
			{
				name: "BadAddDst",
				arch: ArchAMD64,
				fn: Func{
					Sym: "·badadd",
					Instrs: []Instr{
						{Op: OpTEXT, Raw: "TEXT ·badadd(SB),NOSPLIT,$0-0"},
						{Op: OpADDQ, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpFP, FPOffset: 8}}, Raw: "ADDQ $1, ret+8(FP)"},
						{Op: OpRET, Raw: "RET"},
					},
				},
				sig:     FuncSig{Name: "example.badadd", Ret: I64},
				wantErr: "dst must be register",
			},
			{
				name: "BadMRSArgs",
				arch: ArchARM64,
				fn: Func{
					Sym: "·badmrs",
					Instrs: []Instr{
						{Op: OpTEXT, Raw: "TEXT ·badmrs(SB),NOSPLIT,$0-0"},
						{Op: OpMRS, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: "R0"}}, Raw: "MRS $1, R0"},
						{Op: OpRET, Raw: "RET"},
					},
				},
				sig:     FuncSig{Name: "example.badmrs", Ret: I64},
				wantErr: "MRS expects ident, reg",
			},
			{
				name: "BadScalarReturnCast",
				arch: ArchAMD64,
				fn: Func{
					Sym: "·badretcast",
					Instrs: []Instr{
						{Op: OpTEXT, Raw: "TEXT ·badretcast(SB),NOSPLIT,$0-0"},
						{Op: OpMOVQ, Args: []Operand{{Kind: OpImm, Imm: 7}, {Kind: OpReg, Reg: AX}}, Raw: "MOVQ $7, AX"},
						{Op: OpRET, Raw: "RET"},
					},
				},
				sig:     FuncSig{Name: "example.badretcast", Ret: LLVMType("v2i64")},
				wantErr: "unsupported cast i64 -> v2i64",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var b strings.Builder
				err := translateFuncLinear(&b, tc.arch, tc.fn, tc.sig, false)
				if tc.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
						t.Fatalf("translateFuncLinear(%s) error = %v, want substring %q", tc.name, err, tc.wantErr)
					}
					return
				}
				if err != nil {
					t.Fatalf("translateFuncLinear(%s) error = %v", tc.name, err)
				}
				if tc.wantIR != "" && !strings.Contains(b.String(), tc.wantIR) {
					t.Fatalf("translateFuncLinear(%s) missing %q:\n%s", tc.name, tc.wantIR, b.String())
				}
			})
		}
	})

	t.Run("CPUIDAndXGETBVZeroInputs", func(t *testing.T) {
		fn := Func{
			Sym: "·cpux",
			Instrs: []Instr{
				{Op: OpTEXT, Raw: "TEXT ·cpux(SB),NOSPLIT,$0-0"},
				{Op: OpCPUID, Raw: "CPUID"},
				{Op: OpXGETBV, Raw: "XGETBV"},
				{Op: OpRET, Raw: "RET"},
			},
		}
		var b strings.Builder
		if err := translateFuncLinear(&b, ArchAMD64, fn, FuncSig{Name: "example.cpux", Ret: I64}, false); err != nil {
			t.Fatalf("translateFuncLinear(cpux) error = %v", err)
		}
		out := b.String()
		for _, want := range []string{
			"add i32 0, 0",
			"call { i32, i32, i32, i32 } asm sideeffect",
			"call { i32, i32 } asm sideeffect",
			"zext i32",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %q in cpux output:\n%s", want, out)
			}
		}
	})
}

func TestTranslateFuncLinearModuleEdgeCoverage(t *testing.T) {
	ctx := llvm.GlobalContext()

	t.Run("DirectSuccessAndFallbacks", func(t *testing.T) {
		mod := ctx.NewModule("direct-edge-success")
		defer mod.Dispose()

		err := translateFuncLinearModule(mod, ArchARM64, Func{
			Sym: "example.directedge",
			Instrs: []Instr{
				{Op: OpTEXT},
				{Op: OpMOVD, Args: []Operand{{Kind: OpFP, FPOffset: 0}, {Kind: OpReg, Reg: "R0"}}, Raw: "MOVD arg+0(FP), R0"},
				{Op: OpMOVL, Args: []Operand{{Kind: OpFP, FPOffset: 8}, {Kind: OpReg, Reg: "R1"}}, Raw: "MOVL arg+8(FP), R1"},
				{Op: OpADDQ, Args: []Operand{{Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R0"}}, Raw: "ADDQ R1, R0"},
				{Op: OpMOVD, Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpFP, FPOffset: 24}}, Raw: "MOVD R0, ret+24(FP)"},
				{Op: OpRET},
			},
		}, FuncSig{
			Name: "example.directedge",
			Args: []LLVMType{Ptr, I32},
			Ret:  I64,
			Frame: FrameLayout{
				Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: I32, Index: 1, Field: -1},
				},
				Results: []FrameSlot{{Offset: 24, Type: I64, Index: 0}},
			},
		})
		if err != nil {
			t.Fatalf("translateFuncLinearModule(success) error = %v", err)
		}
	})

	t.Run("DirectCPUXGETBVAndMRS", func(t *testing.T) {
		mod := ctx.NewModule("direct-edge-cpu-mrs")
		defer mod.Dispose()

		err := translateFuncLinearModule(mod, ArchARM64, Func{
			Sym: "example.directcpumrs",
			Instrs: []Instr{
				{Op: OpTEXT},
				{Op: OpMOVD, Args: []Operand{{Kind: OpImm, Imm: 7}, {Kind: OpReg, Reg: AX}}, Raw: "MOVD $7, AX"},
				{Op: OpMOVD, Args: []Operand{{Kind: OpImm, Imm: 11}, {Kind: OpReg, Reg: CX}}, Raw: "MOVD $11, CX"},
				{Op: OpCPUID, Raw: "CPUID"},
				{Op: OpXGETBV, Raw: "XGETBV"},
				{Op: OpMRS, Args: []Operand{{Kind: OpIdent, Ident: "MIDR_EL1"}, {Kind: OpReg, Reg: "R0"}}, Raw: "MRS MIDR_EL1, R0"},
				{Op: OpMRS, Args: []Operand{{Kind: OpIdent, Ident: "TPIDR_EL0"}, {Kind: OpReg, Reg: "R1"}}, Raw: "MRS TPIDR_EL0, R1"},
				{Op: OpRET},
			},
		}, FuncSig{Name: "example.directcpumrs", Ret: I64})
		if err != nil {
			t.Fatalf("translateFuncLinearModule(cpu+mrs) error = %v", err)
		}

		ir := mod.String()
		for _, want := range []string{
			"call { i32, i32, i32, i32 } asm sideeffect \"cpuid\"",
			"call { i32, i32 } asm sideeffect \"xgetbv\"",
			"call i64 asm \"mrs $0, TPIDR_EL0\"",
			"ret i64 0",
		} {
			if !strings.Contains(ir, want) {
				t.Fatalf("missing %q in module IR:\n%s", want, ir)
			}
		}
	})

	t.Run("DirectErrors", func(t *testing.T) {
		cases := []struct {
			name string
			fn   Func
			sig  FuncSig
		}{
			{
				name: "UnresolvedImm",
				fn: Func{
					Sym: "badimm",
					Instrs: []Instr{
						{Op: OpTEXT},
						{Op: OpMOVD, Args: []Operand{{Kind: OpImm, ImmRaw: "sym+4(SB)"}, {Kind: OpReg, Reg: AX}}, Raw: "MOVD $sym+4(SB), AX"},
						{Op: OpRET},
					},
				},
				sig: FuncSig{Name: "example.badimm", Ret: I64},
			},
			{
				name: "BadOperandKind",
				fn: Func{
					Sym: "badopkind",
					Instrs: []Instr{
						{Op: OpTEXT},
						{Op: OpMOVD, Args: []Operand{{Kind: OpLabel, Sym: "target"}, {Kind: OpReg, Reg: AX}}, Raw: "MOVD target, AX"},
						{Op: OpRET},
					},
				},
				sig: FuncSig{Name: "example.badopkind", Ret: I64},
			},
			{
				name: "BadRetType",
				fn:   Func{Sym: "badret", Instrs: []Instr{{Op: OpTEXT}, {Op: OpRET}}},
				sig:  FuncSig{Name: "example.badret", Ret: LLVMType("v2i64")},
			},
			{
				name: "BadArgType",
				fn:   Func{Sym: "badarg", Instrs: []Instr{{Op: OpTEXT}, {Op: OpRET}}},
				sig:  FuncSig{Name: "example.badarg", Args: []LLVMType{LLVMType("v2i64")}, Ret: I64},
			},
			{
				name: "BadFPReadSlot",
				fn: Func{
					Sym: "badfprd",
					Instrs: []Instr{
						{Op: OpTEXT},
						{Op: OpMOVD, Args: []Operand{{Kind: OpFP, FPOffset: 8}, {Kind: OpReg, Reg: AX}}, Raw: "MOVD arg+8(FP), AX"},
						{Op: OpRET},
					},
				},
				sig: FuncSig{Name: "example.badfprd", Ret: I64},
			},
			{
				name: "BadFPArgIndex",
				fn: Func{
					Sym: "badfpidx",
					Instrs: []Instr{
						{Op: OpTEXT},
						{Op: OpMOVD, Args: []Operand{{Kind: OpFP, FPOffset: 8}, {Kind: OpReg, Reg: AX}}, Raw: "MOVD arg+8(FP), AX"},
						{Op: OpRET},
					},
				},
				sig: FuncSig{
					Name: "example.badfpidx",
					Args: []LLVMType{I64},
					Ret:  I64,
					Frame: FrameLayout{
						Params: []FrameSlot{{Offset: 8, Type: I64, Index: 2}},
					},
				},
			},
			{
				name: "BadFPWriteSlot",
				fn: Func{
					Sym: "badfpwr",
					Instrs: []Instr{
						{Op: OpTEXT},
						{Op: OpMOVD, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpFP, FPOffset: 8}}, Raw: "MOVD $1, ret+8(FP)"},
						{Op: OpRET},
					},
				},
				sig: FuncSig{Name: "example.badfpwr", Ret: I64},
			},
			{
				name: "BadFPResultIndex",
				fn: Func{
					Sym: "badresidx",
					Instrs: []Instr{
						{Op: OpTEXT},
						{Op: OpMOVD, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpFP, FPOffset: 8}}, Raw: "MOVD $1, ret+8(FP)"},
						{Op: OpRET},
					},
				},
				sig: FuncSig{
					Name: "example.badresidx",
					Ret:  I64,
					Frame: FrameLayout{
						Results: []FrameSlot{{Offset: 8, Type: I64, Index: 2}},
					},
				},
			},
			{
				name: "BadMRSArgs",
				fn: Func{
					Sym:    "badmrs",
					Instrs: []Instr{{Op: OpTEXT}, {Op: OpMRS, Args: []Operand{{Kind: OpImm, Imm: 1}}, Raw: "MRS $1"}, {Op: OpRET}},
				},
				sig: FuncSig{Name: "example.badmrs", Ret: I64},
			},
			{
				name: "BadMRSKinds",
				fn: Func{
					Sym:    "badmrskind",
					Instrs: []Instr{{Op: OpTEXT}, {Op: OpMRS, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}, Raw: "MRS $1, AX"}, {Op: OpRET}},
				},
				sig: FuncSig{Name: "example.badmrskind", Ret: I64},
			},
			{
				name: "BadMOVDArgs",
				fn: Func{
					Sym:    "badmovd",
					Instrs: []Instr{{Op: OpTEXT}, {Op: OpMOVD, Args: []Operand{{Kind: OpImm, Imm: 1}}, Raw: "MOVD $1"}, {Op: OpRET}},
				},
				sig: FuncSig{Name: "example.badmovd", Ret: I64},
			},
			{
				name: "BadMOVDDst",
				fn: Func{
					Sym:    "badmovddst",
					Instrs: []Instr{{Op: OpTEXT}, {Op: OpMOVD, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpIdent, Ident: "label"}}, Raw: "MOVD $1, label"}, {Op: OpRET}},
				},
				sig: FuncSig{Name: "example.badmovddst", Ret: I64},
			},
			{
				name: "BadMOVLArgs",
				fn: Func{
					Sym:    "badmovl",
					Instrs: []Instr{{Op: OpTEXT}, {Op: OpMOVL, Args: []Operand{{Kind: OpImm, Imm: 1}}, Raw: "MOVL $1"}, {Op: OpRET}},
				},
				sig: FuncSig{Name: "example.badmovl", Ret: I64},
			},
			{
				name: "BadMOVLDst",
				fn: Func{
					Sym:    "badmovldst",
					Instrs: []Instr{{Op: OpTEXT}, {Op: OpMOVL, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpIdent, Ident: "label"}}, Raw: "MOVL $1, label"}, {Op: OpRET}},
				},
				sig: FuncSig{Name: "example.badmovldst", Ret: I64},
			},
			{
				name: "BadADDArgs",
				fn: Func{
					Sym:    "badaddargs",
					Instrs: []Instr{{Op: OpTEXT}, {Op: OpADDQ, Args: []Operand{{Kind: OpImm, Imm: 1}}, Raw: "ADDQ $1"}, {Op: OpRET}},
				},
				sig: FuncSig{Name: "example.badaddargs", Ret: I64},
			},
			{
				name: "BadADDDst",
				fn: Func{
					Sym:    "badadddst",
					Instrs: []Instr{{Op: OpTEXT}, {Op: OpADDQ, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpFP, FPOffset: 8}}, Raw: "ADDQ $1, ret+8(FP)"}, {Op: OpRET}},
				},
				sig: FuncSig{Name: "example.badadddst", Ret: I64},
			},
			{
				name: "UnsupportedInstruction",
				fn: Func{
					Sym:    "badop",
					Instrs: []Instr{{Op: OpTEXT}, {Op: "NOP", Raw: "NOP"}, {Op: OpRET}},
				},
				sig: FuncSig{Name: "example.badop", Ret: I64},
			},
			{
				name: "InstructionAfterRET",
				fn: Func{
					Sym:    "afterret",
					Instrs: []Instr{{Op: OpTEXT}, {Op: OpRET}, {Op: OpMOVD, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}, Raw: "MOVD $1, AX"}},
				},
				sig: FuncSig{Name: "example.afterret", Ret: I64},
			},
			{
				name: "NoRET",
				fn: Func{
					Sym:    "noret",
					Instrs: []Instr{{Op: OpTEXT}, {Op: OpMOVD, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: AX}}, Raw: "MOVD $1, AX"}},
				},
				sig: FuncSig{Name: "example.noret", Ret: I64},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				mod := ctx.NewModule("direct-" + tc.name)
				defer mod.Dispose()
				if err := translateFuncLinearModule(mod, ArchAMD64, tc.fn, tc.sig); !errors.Is(err, errDirectModuleUnsupported) {
					t.Fatalf("translateFuncLinearModule(%s) error = %v", tc.name, err)
				}
			})
		}
	})
}

func TestTranslateFuncLinearReturnCastCoverage(t *testing.T) {
	cases := []struct {
		name string
		sig  FuncSig
		want []string
	}{
		{
			name: "I1ToDouble",
			sig:  FuncSig{Name: "example.i1tod", Args: []LLVMType{I1}, ArgRegs: []Reg{AX}, Ret: LLVMType("double")},
			want: []string{"zext i1 %arg0 to i32", "uitofp i32 %"},
		},
		{
			name: "I8ToFloat",
			sig:  FuncSig{Name: "example.i8tof", Args: []LLVMType{I8}, ArgRegs: []Reg{AX}, Ret: LLVMType("float")},
			want: []string{"zext i8 %arg0 to i32", "uitofp i32 %"},
		},
		{
			name: "I16ToDouble",
			sig:  FuncSig{Name: "example.i16tod", Args: []LLVMType{I16}, ArgRegs: []Reg{AX}, Ret: LLVMType("double")},
			want: []string{"zext i16 %arg0 to i32", "uitofp i32 %"},
		},
		{
			name: "I32ToI1",
			sig:  FuncSig{Name: "example.i32toi1", Args: []LLVMType{I32}, ArgRegs: []Reg{AX}, Ret: I1},
			want: []string{"trunc i32 %arg0 to i1", "ret i1 %"},
		},
		{
			name: "I32ToI8",
			sig:  FuncSig{Name: "example.i32toi8", Args: []LLVMType{I32}, ArgRegs: []Reg{AX}, Ret: I8},
			want: []string{"trunc i32 %arg0 to i8", "ret i8 %"},
		},
		{
			name: "I32ToI16",
			sig:  FuncSig{Name: "example.i32toi16", Args: []LLVMType{I32}, ArgRegs: []Reg{AX}, Ret: I16},
			want: []string{"trunc i32 %arg0 to i16", "ret i16 %"},
		},
		{
			name: "PtrToI32",
			sig:  FuncSig{Name: "example.ptoi32", Args: []LLVMType{Ptr}, ArgRegs: []Reg{AX}, Ret: I32},
			want: []string{"ptrtoint ptr %arg0 to i32", "ret i32 %"},
		},
		{
			name: "PtrToI64",
			sig:  FuncSig{Name: "example.ptoi64", Args: []LLVMType{Ptr}, ArgRegs: []Reg{AX}, Ret: I64},
			want: []string{"ptrtoint ptr %arg0 to i64", "ret i64 %"},
		},
		{
			name: "I32ToPtr",
			sig:  FuncSig{Name: "example.i32top", Args: []LLVMType{I32}, ArgRegs: []Reg{AX}, Ret: Ptr},
			want: []string{"inttoptr i32 %arg0 to ptr", "ret ptr %"},
		},
		{
			name: "FloatToI32",
			sig:  FuncSig{Name: "example.ftoi32", Args: []LLVMType{LLVMType("float")}, ArgRegs: []Reg{AX}, Ret: I32},
			want: []string{"fptoui float %arg0 to i32", "ret i32 %"},
		},
		{
			name: "DoubleToI64",
			sig:  FuncSig{Name: "example.dtoi64", Args: []LLVMType{LLVMType("double")}, ArgRegs: []Reg{AX}, Ret: I64},
			want: []string{"fptoui double %arg0 to i64", "ret i64 %"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			if err := translateFuncLinear(&b, ArchAMD64, Func{
				Sym:    "·retcast",
				Instrs: []Instr{{Op: OpTEXT, Raw: "TEXT ·retcast(SB),NOSPLIT,$0-0"}, {Op: OpRET, Raw: "RET"}},
			}, tc.sig, false); err != nil {
				t.Fatalf("translateFuncLinear(%s) error = %v", tc.name, err)
			}
			out := b.String()
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Fatalf("%s missing %q:\n%s", tc.name, want, out)
				}
			}
		})
	}

	t.Run("AggregateZeroAndIgnoredWrite", func(t *testing.T) {
		var b strings.Builder
		err := translateFuncLinear(&b, ArchAMD64, Func{
			Sym: "·aggzero",
			Instrs: []Instr{
				{Op: OpTEXT, Raw: "TEXT ·aggzero(SB),NOSPLIT,$0-0"},
				{Op: OpMOVQ, Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpFP, FPOffset: 99}}, Raw: "MOVQ $1, ignored+99(FP)"},
				{Op: OpRET, Raw: "RET"},
			},
		}, FuncSig{
			Name: "example.aggzero",
			Ret:  LLVMType("{i64, i32}"),
			Frame: FrameLayout{
				Results: []FrameSlot{
					{Offset: 8, Type: I64, Index: 0},
					{Offset: 16, Type: I32, Index: 1},
				},
			},
		}, false)
		if err != nil {
			t.Fatalf("translateFuncLinear(aggzero) error = %v", err)
		}
		out := b.String()
		for _, want := range []string{
			"add i64 0, 0",
			"add i32 0, 0",
			"insertvalue {i64, i32}",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("aggzero missing %q:\n%s", want, out)
			}
		}
	})
}
