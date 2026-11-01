package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParse386NamedStackOffset(t *testing.T) {
	op, err := parseOperand("control-4(SP)")
	if err != nil {
		t.Fatal(err)
	}
	if op.Kind != OpMem || op.Mem.Base != SP || op.Mem.Off != -4 {
		t.Fatalf("parseOperand(control-4(SP)) = %#v", op)
	}
}

func TestTranslate386SymbolIndexedMemory(t *testing.T) {
	for _, invalid := range []string{
		"masks<>(SB)(BX*8)junk",
		"masks<>(SB)(BAD*8)",
	} {
		if _, ok := parseMem(invalid); ok {
			t.Fatalf("parseMem(%q) unexpectedly succeeded", invalid)
		}
	}
	var invalidIR strings.Builder
	invalidCtx := newX86Ctx(&invalidIR, Func{}, FuncSig{Name: "example.invalid", Ret: Void}, testResolveSym("example"), nil, "386", "i386-pc-windows-gnu", false)
	if _, err := invalidCtx.addrFromPlainMem(MemRef{Sym: "(SB)"}); err == nil {
		t.Fatal("symbol-indexed address with an empty symbol unexpectedly succeeded")
	}

	const source = `
GLOBL masks<>(SB), RODATA, $256
TEXT lookup(SB),NOSPLIT,$0-0
	PAND masks<>(SB)(BX*8), X1
	RET
`
	file, signatures := x86UnboundVoidFormatSource(t, source, "lookup", "386", "i386-pc-windows-gnu")
	src := file.Funcs[0].Instrs[1].Args[0]
	if src.Kind != OpMem || src.Mem.Sym != "masks<>(SB)" || src.Mem.Index != BX || src.Mem.Scale != 8 {
		t.Fatalf("parse symbol-indexed memory = %#v", src)
	}
	if got := src.String(); got != "masks<>(SB)(BX*8)" {
		t.Fatalf("symbol-indexed memory string = %q", got)
	}
	ir := x86ScalarFormatObjectUnit(t, file, signatures, "386", "i386-pc-windows-gnu", 0)
	if strings.Contains(ir, `masks<>(SB)(BX*8)`) ||
		!strings.Contains(ir, "ptrtoint ptr @") ||
		!strings.Contains(ir, "mul i64") {
		t.Fatalf("symbol-indexed address was not lowered:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	compileLLVMToObject(t, llc, "i386-pc-windows-gnu", "symbol-indexed.ll", "symbol-indexed.o", ir)
}

func TestParse386MMXRegister(t *testing.T) {
	file, err := Parse(ArchAMD64, `TEXT ·load(SB),NOSPLIT,$0-0
	MOVQ (AX), M0
	MOVQ M0, (AX)
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	for i, operand := range []Operand{
		file.Funcs[0].Instrs[1].Args[1],
		file.Funcs[0].Instrs[2].Args[0],
	} {
		if operand.Kind != OpReg || operand.Reg != "M0" {
			t.Fatalf("MMX operand %d = (%v, %q), want (%v, M0)", i, operand.Kind, operand.Reg, OpReg)
		}
	}
}

func TestTranslate386AlwaysUsesX86CFG(t *testing.T) {
	file, err := Parse(ArchAMD64, `TEXT add(SB),NOSPLIT,$0-0
	MOVL $1, AX
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "i386-pc-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"add": {Name: "add", Ret: I32},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The CFG lowering uses a simulated AX slot; the linear prototype does not.
	if !strings.Contains(ir, "%reg_AX = alloca i64") {
		t.Fatalf("386 translation used the linear lowering path:\n%s", ir)
	}
}

func TestTranslate386RejectsRepeatPrefixBeforeNonStringInstruction(t *testing.T) {
	for _, next := range []string{"NOP", "RET", "REP"} {
		t.Run(next, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\nREP; "+next+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			})
			if err == nil || !strings.Contains(err.Error(), "REP prefix is unsupported for "+next) {
				t.Fatalf("Translate(REP; %s) error = %v", next, err)
			}
		})
	}
	t.Run("missing instruction", func(t *testing.T) {
		file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\nREP\n")
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		})
		if err == nil || !strings.Contains(err.Error(), "REP prefix has no following string instruction") {
			t.Fatalf("Translate(dangling REP) error = %v", err)
		}
	})
}

func TestTranslate386RejectsInvalidInstructionForms(t *testing.T) {
	tests := []struct {
		name        string
		instruction string
		want        string
		goarch      string
		triple      string
	}{
		{name: "adjsp operand", instruction: "ADJSP AX", want: "ADJSP expects an immediate"},
		{name: "cld operand", instruction: "CLD AX", want: "CLD takes no operands"},
		{name: "std operand", instruction: "STD AX", want: "STD takes no operands"},
		{name: "rep operand", instruction: "REP AX", want: "REP takes no operands"},
		{name: "movsb operand", instruction: "MOVSB AX", want: "MOVSB takes no operands"},
		{name: "rdtsc operand", instruction: "RDTSC AX", want: "RDTSC takes no operands"},
		{name: "rdtscp operand", instruction: "RDTSCP AX", want: "RDTSCP takes no operands"},
		{name: "int register", instruction: "INT AX", want: "INT expects an immediate vector"},
		{name: "linux syscall on windows", instruction: "INT $0x80", want: "requires a Linux target triple", triple: "i686-pc-windows-msvc"},
		{name: "pushl count", instruction: "PUSHL", want: "PUSHL expects src"},
		{name: "popl count", instruction: "POPL", want: "POPL expects dst"},
		{name: "popl destination", instruction: "POPL $1", want: "POPL expects reg/mem dst"},
		{name: "pushfl operand", instruction: "PUSHFL AX", want: "PUSHFL takes no operands"},
		{name: "popfl operand", instruction: "POPFL AX", want: "POPFL takes no operands"},
		{name: "pushal operand", instruction: "PUSHAL AX", want: "PUSHAL takes no operands"},
		{name: "popal operand", instruction: "POPAL AX", want: "POPAL takes no operands"},
		{name: "unmodeled direct sp write", instruction: "XORL AX, SP", want: "direct SP write is unsupported"},
		{name: "fmovd count", instruction: "FMOVD F0", want: "FMOVD expects src, dst"},
		{name: "fmovd destination", instruction: "FMOVD F0, AX", want: "FMOVD expects memory,F0"},
		{name: "fmovdp count", instruction: "FMOVDP F0", want: "FMOVDP expects F0 source"},
		{name: "fmovdp destination", instruction: "FMOVDP F0, AX", want: "FMOVDP expects F0 source"},
		{name: "fmovv count", instruction: "FMOVV AX", want: "FMOVV expects src, dst"},
		{name: "fmovv destination", instruction: "FMOVV AX, F1", want: "FMOVV expects signed integer memory,F0"},
		{name: "fmovvp count", instruction: "FMOVVP F0", want: "FMOVVP expects src, dst"},
		{name: "fmovvp source", instruction: "FMOVVP F1, 0(SP)", want: "FMOVVP expects F0 source"},
		{name: "fmovvp destination", instruction: "FMOVVP F0, AX", want: "FMOVVP expects F0 source"},
		{name: "fxchd count", instruction: "FXCHD F0", want: "FXCHD expects Fsrc, Fdst"},
		{name: "fxchd registers", instruction: "FXCHD AX, BX", want: "FXCHD expects x87 registers"},
		{name: "fdivd count", instruction: "FDIVD F0", want: "FDIVD expects src, dst"},
		{name: "fdivd destination", instruction: "FDIVD F0, $1", want: "FDIVD expects memory,F0"},
		{name: "fadddp count", instruction: "FADDDP F0", want: "FADDDP expects src, dst"},
		{name: "fadddp destination", instruction: "FADDDP F0, $1", want: "FADDDP expects F0 source"},
		{name: "fstcw count", instruction: "FSTCW", want: "FSTCW expects memory destination"},
		{name: "fstcw undeclared FP destination", instruction: "FSTCW ret+0(FP)", want: "unsupported FP write slot"},
		{name: "fldcw count", instruction: "FLDCW", want: "FLDCW expects memory source"},
		{name: "frndint operand", instruction: "FRNDINT AX", want: "FRNDINT takes no operands"},
		{name: "fabs operand", instruction: "FABS AX", want: "FABS takes no operands"},
		{name: "fucomi count", instruction: "FUCOMI F0", want: "FUCOMI expects lhs, rhs"},
		{name: "ftst operand", instruction: "FTST AX", want: "FTST takes no operands"},
		{name: "fstsw count", instruction: "FSTSW", want: "FSTSW expects memory destination"},
		{name: "fstsw undeclared FP destination", instruction: "FSTSW ret+0(FP)", want: "unsupported FP write slot"},
		{name: "fld1 operand", instruction: "FLD1 AX", want: "FLD1 takes no operands"},
		{name: "pushl on amd64", instruction: "PUSHL AX", want: "requires GOARCH=386", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "popl on amd64", instruction: "POPL AX", want: "requires GOARCH=386", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "pushfl on amd64", instruction: "PUSHFL", want: "requires GOARCH=386", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "popfl on amd64", instruction: "POPFL", want: "requires GOARCH=386", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "pushal on amd64", instruction: "PUSHAL", want: "requires GOARCH=386", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "popal on amd64", instruction: "POPAL", want: "requires GOARCH=386", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "vector low destination", instruction: "MOVL X0, $1", want: "386 MOVL outside complete Go GP/X transfer grammar"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			goarch := tt.goarch
			if goarch == "" {
				goarch = "386"
			}
			triple := tt.triple
			if triple == "" {
				triple = "i386-unknown-linux-gnu"
			}
			file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n"+tt.instruction+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{
				TargetTriple: triple,
				Goarch:       goarch,
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Translate(%q) error = %v, want substring %q", tt.instruction, err, tt.want)
			}
		})
	}
}

func TestTranslate386ModelsOfficialDirectSPWrites(t *testing.T) {
	const source = `TEXT stack(SB),NOSPLIT,$0-0
	MOVL AX, SP
	SUBL $256, SP
	ADDL AX, SP
	ADDL $32, SP
	ANDL $~15, SP
	LEAL 4(SP), SP
	POPL SP
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86OriginalUnbalancedStackGoRejection(t, source, triple)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func stack()", "386", triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("original unknown/unbalanced SP acquired a public frame", api, err)
				}
			}
			ir := x86OriginalStackFormatObject(t, file.Funcs[0], Void, "386", triple)
			for _, want := range []string{"%local_stack = alloca [770 x i8]", "sub i32", "add i32", "and i32"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("386 direct SP format lowering missing %q:\n%s", want, ir)
				}
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, text, level)
				}
			}
		})
	}
}

func TestTranslate386FUCOMIClearsSignedCondition(t *testing.T) {
	fn := Func{Instrs: []Instr{{
		Op:   "FUCOMI",
		Args: []Operand{{Kind: OpReg, Reg: "F0"}, {Kind: OpReg, Reg: "F1"}},
	}}}
	var b strings.Builder
	c := newX86Ctx(&b, fn, FuncSig{Name: "example.fucomi", Ret: Void}, testResolveSym("example"), nil, "386", "i386-unknown-linux-gnu", false)
	if err := c.emitEntryAllocas(); err != nil {
		t.Fatal(err)
	}
	start := b.Len()
	ok, terminated, err := c.lowerX87("FUCOMI", fn.Instrs[0])
	if !ok || terminated || err != nil {
		t.Fatalf("lowerX87(FUCOMI) = (%v, %v, %v)", ok, terminated, err)
	}
	got := b.String()[start:]
	for _, want := range []string{"fcmp ueq double", "fcmp ult double", "store i1 false, ptr %flags_slt"} {
		if !strings.Contains(got, want) {
			t.Fatalf("FUCOMI lowering missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "fcmp olt double") {
		t.Fatalf("FUCOMI incorrectly synthesized a signed-less flag:\n%s", got)
	}
}

func Test386LoweringEdgeCases(t *testing.T) {
	fn := Func{Instrs: []Instr{
		{Op: "FLD1"},
		{Op: "MOVL", Args: []Operand{{Kind: OpReg, Reg: AX}, {Kind: OpReg, Reg: BX}}},
	}}
	sig := FuncSig{Name: "example.edges", Ret: Void}
	var b strings.Builder
	c := newX86Ctx(&b, fn, sig, testResolveSym("example"), nil, "386", "i386-unknown-linux-gnu", false)
	if err := c.emitEntryAllocas(); err != nil {
		t.Fatal(err)
	}
	expectError := func(name string, lower func() (bool, bool, error)) {
		t.Helper()
		ok, terminated, err := lower()
		if !ok || terminated || err == nil {
			t.Fatalf("%s = (%v, %v, %v), want handled non-terminating error", name, ok, terminated, err)
		}
	}
	ident := Operand{Kind: OpIdent, Ident: "invalid"}
	imm := Operand{Kind: OpImm, Imm: 1}
	reg := Operand{Kind: OpReg, Reg: AX}

	for _, test := range []struct {
		name string
		op   Op
		args []Operand
	}{
		{name: "ADCL operand count", op: "ADCL"},
		{name: "ADCL source", op: "ADCL", args: []Operand{ident, reg}},
		{name: "ADCL destination", op: "ADCL", args: []Operand{imm, ident}},
		{name: "ADDL source", op: "ADDL", args: []Operand{ident, reg}},
		{name: "ADDL destination", op: "ADDL", args: []Operand{imm, ident}},
		{name: "ADDB source", op: "ADDB", args: []Operand{ident, reg}},
		{name: "ANDW operand count", op: "ANDW"},
		{name: "ANDW source", op: "ANDW", args: []Operand{ident, reg}},
		{name: "ANDW destination", op: "ANDW", args: []Operand{imm, ident}},
		{name: "SETEQ destination", op: "SETEQ", args: []Operand{ident}},
		{name: "IMULL source", op: "IMULL", args: []Operand{ident}},
		{name: "IMULL destination", op: "IMULL", args: []Operand{imm, imm}},
		{name: "IMULL two-operand source", op: "IMULL", args: []Operand{ident, reg}},
		{name: "IMUL3L destination", op: "IMUL3L", args: []Operand{imm, reg, imm}},
		{name: "IMUL3L immediate", op: "IMUL3L", args: []Operand{ident, reg, reg}},
		{name: "IMUL3L source", op: "IMUL3L", args: []Operand{imm, ident, reg}},
		{name: "IMULL operand count", op: "IMULL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			expectError(test.name, func() (bool, bool, error) {
				return c.lowerArith(test.op, Instr{Raw: test.name, Args: test.args})
			})
		})
	}

	for _, test := range []struct {
		name string
		op   Op
		args []Operand
	}{
		{name: "FMOVD source", op: "FMOVD", args: []Operand{ident, {Kind: OpReg, Reg: "F0"}}},
		{name: "FMOVDP source", op: "FMOVDP", args: []Operand{ident, reg}},
		{name: "FMOVV source", op: "FMOVV", args: []Operand{ident, {Kind: OpReg, Reg: "F0"}}},
		{name: "FMOVVP source", op: "FMOVVP", args: []Operand{ident, reg}},
		{name: "FDIVD source", op: "FDIVD", args: []Operand{ident, {Kind: OpReg, Reg: "F0"}}},
		{name: "FDIVD destination", op: "FDIVD", args: []Operand{{Kind: OpReg, Reg: "F0"}, ident}},
		{name: "FADDDP source", op: "FADDDP", args: []Operand{ident, {Kind: OpReg, Reg: "F0"}}},
		{name: "FADDDP destination", op: "FADDDP", args: []Operand{{Kind: OpReg, Reg: "F0"}, ident}},
		{name: "FLDCW source", op: "FLDCW", args: []Operand{ident}},
		{name: "FUCOMI lhs", op: "FUCOMI", args: []Operand{ident, {Kind: OpReg, Reg: "F0"}}},
		{name: "FUCOMI rhs", op: "FUCOMI", args: []Operand{{Kind: OpReg, Reg: "F0"}, ident}},
	} {
		t.Run(test.name, func(t *testing.T) {
			expectError(test.name, func() (bool, bool, error) {
				return c.lowerX87(test.op, Instr{Raw: test.name, Args: test.args})
			})
		})
	}

	if _, err := c.amd64AtomicPtrFromMem(MemRef{Segment: FS}); err == nil {
		t.Fatal("segment-relative atomic destination unexpectedly succeeded")
	}
	if got := x86FrameTypeSize(I16); got != 2 {
		t.Fatalf("x86FrameTypeSize(i16) = %d, want 2", got)
	}
	if got := x86FrameTypeSize(LLVMType("{ i32, i32 }")); got != 16 {
		t.Fatalf("x86FrameTypeSize(aggregate) = %d, want 16", got)
	}
	if _, ok := amd64ParseX87Reg("F8"); ok {
		t.Fatal("amd64ParseX87Reg(F8) unexpectedly succeeded")
	}
}

func Test386LoweringErrorPaths(t *testing.T) {
	fn := Func{Instrs: []Instr{
		{Op: "FLD1"},
		{Op: "MOVL", Args: []Operand{{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: AX}}},
	}}
	var b strings.Builder
	c := newX86Ctx(&b, fn, FuncSig{Name: "example.errors", Ret: Void}, testResolveSym("example"), nil, "386", "i386-unknown-linux-gnu", false)
	if err := c.emitEntryAllocas(); err != nil {
		t.Fatal(err)
	}

	badMem := Operand{Kind: OpMem, Mem: MemRef{Segment: Reg("BAD")}}
	badSym := Operand{Kind: OpSym, Sym: "(SB)"}
	wantLowerError := func(name string, lower func() (bool, bool, error)) {
		t.Helper()
		ok, terminated, err := lower()
		if !ok || terminated || err == nil {
			t.Fatalf("%s = (%v, %v, %v), want handled non-terminating error", name, ok, terminated, err)
		}
	}

	if _, _, err := c.loadIntDestination(badMem, I32); err == nil {
		t.Fatal("loadIntDestination with an invalid segment unexpectedly succeeded")
	}
	wantLowerError("PUSHL source", func() (bool, bool, error) {
		return c.lowerArith("PUSHL", Instr{Raw: "PUSHL invalid", Args: []Operand{{Kind: OpIdent, Ident: "invalid"}}})
	})
	wantLowerError("POPL destination", func() (bool, bool, error) {
		return c.lowerArith("POPL", Instr{Raw: "POPL 0(BAD)", Args: []Operand{badMem}})
	})
	wantLowerError("SETEQ destination", func() (bool, bool, error) {
		return c.lowerArith("SETEQ", Instr{Raw: "SETEQ 0(BAD)", Args: []Operand{badMem}})
	})
	wantLowerError("CMPXCHG8B destination", func() (bool, bool, error) {
		return c.lowerAtomic("CMPXCHG8B", Instr{Raw: "CMPXCHG8B 0(BAD)", Args: []Operand{badMem}})
	})
	wantLowerError("vector memory destination", func() (bool, bool, error) {
		return c.lowerVectorScalarIntegerMove("MOVL", Instr{Op: "MOVL", Raw: "MOVL X0, 0(BAD)", Args: []Operand{{Kind: OpReg, Reg: "X0"}, badMem}})
	})
	wantLowerError("vector symbol destination", func() (bool, bool, error) {
		return c.lowerVectorScalarIntegerMove("MOVL", Instr{Op: "MOVL", Raw: "MOVL X0, (SB)", Args: []Operand{{Kind: OpReg, Reg: "X0"}, badSym}})
	})

	for _, test := range []struct {
		name  string
		store func(Operand) error
	}{
		{name: "x87 double memory", store: func(dst Operand) error { return c.storeX87F64(dst, "0.0") }},
		{name: "x87 word memory", store: func(dst Operand) error { return c.storeX87I16(dst, "0") }},
		{name: "x87 integer memory", store: func(dst Operand) error { return c.storeX87I64(dst, "0") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.store(badMem); err == nil {
				t.Fatal("invalid segment unexpectedly succeeded")
			}
			if err := test.store(badSym); err == nil {
				t.Fatal("invalid symbol unexpectedly succeeded")
			}
		})
	}
	if ok, terminated, err := c.lowerX87("NOP", Instr{Raw: "NOP"}); ok || terminated || err != nil {
		t.Fatalf("lowerX87(NOP) = (%v, %v, %v), want unhandled", ok, terminated, err)
	}
	if _, err := c.evalIntSized(Operand{Kind: OpSym, Sym: "$(SB)"}, I32); err == nil {
		t.Fatal("invalid symbolic address unexpectedly succeeded")
	}

	oldArch := c.goarch
	c.goarch = "amd64"
	wantLowerError("amd64 MOVL FP source", func() (bool, bool, error) {
		return c.lowerMov("MOVL", Instr{Raw: "MOVL $1, ret+0(FP)", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpFP, FPOffset: 0}}})
	})
	c.goarch = oldArch

	var fp strings.Builder
	fpCtx := newX86Ctx(&fp, Func{}, FuncSig{Name: "example.fp", Ret: Void}, testResolveSym("example"), nil, "386", "i386-unknown-linux-gnu", false)
	fpCtx.fpParams[0] = FrameSlot{Offset: 0, Type: I64, Index: 9, Field: -1}
	fpCtx.fpParams[8] = FrameSlot{Offset: 8, Type: I32, Index: 0, Field: -1}
	if _, err := fpCtx.evalFPToI64(100); err != nil {
		t.Fatal(err)
	}
	if _, err := fpCtx.evalFPToI64(4); err == nil {
		t.Fatal("high-word read of an invalid frame parameter unexpectedly succeeded")
	}

	var result strings.Builder
	resultCtx := newX86Ctx(&result, Func{}, FuncSig{Name: "example.result", Ret: Void}, testResolveSym("example"), nil, "386", "i386-unknown-linux-gnu", false)
	resultCtx.fpResults = []FrameSlot{
		{Offset: 0, Type: I64, Index: 0, Field: -1},
		{Offset: 8, Type: I32, Index: 1, Field: -1},
	}
	resultCtx.fpResAllocaOff[0] = "%result0"
	resultCtx.fpResAllocaIdx[0] = "%result0"
	resultCtx.classicFrame = "%classic_frame"
	resultCtx.classicSize = 16
	if _, err := resultCtx.evalFPToI64(100); err != nil {
		t.Fatal(err)
	}
	if got, err := resultCtx.evalFPToI64(4); err != nil || got == "" {
		t.Fatalf("high-word result read = (%q, %v)", got, err)
	}
	// LEA takes the address of a memory operand. OpFPAddr represents
	// $ret+0(FP), an immediate address that Go does not accept as its source.
	lea, err := Parse(ArchAMD64, "TEXT resultAddress(SB),$0-8\n\tLEAL ret+0(FP), AX\n\tRET\n")
	if err != nil {
		t.Fatal(err)
	}
	ins := lea.Funcs[0].Instrs[1]
	if ins.Args[0].Kind != OpFP {
		t.Fatalf("LEAL FP source kind = %v, want memory FP operand", ins.Args[0].Kind)
	}
	ok, terminated, err := resultCtx.lowerArith("LEAL", ins)
	if !ok || terminated || err != nil {
		t.Fatalf("LEAL classic result address = (%v, %v, %v)", ok, terminated, err)
	}
	wantLowerError("LEAL immediate FP source", func() (bool, bool, error) {
		return resultCtx.lowerArith("LEAL", Instr{Raw: "LEAL $ret+0(FP), AX", Args: []Operand{{Kind: OpFPAddr, FPOffset: 0}, {Kind: OpReg, Reg: AX}}})
	})
}

func Test386FDirectiveDoesNotAllocateX87State(t *testing.T) {
	fn := Func{Instrs: []Instr{{Op: "FUNCDATA"}}}
	var b strings.Builder
	c := newX86Ctx(&b, fn, FuncSig{Name: "example.directive", Ret: Void}, testResolveSym("example"), nil, "386", "i386-unknown-linux-gnu", false)
	if err := c.emitEntryAllocas(); err != nil {
		t.Fatal(err)
	}
	if c.usedX87 || strings.Contains(b.String(), "%x87_") {
		t.Fatalf("non-x87 F-prefixed directive allocated x87 state:\n%s", b.String())
	}
}

func Test386RejectsInvalidClassicFrameIndex(t *testing.T) {
	var b strings.Builder
	c := newX86Ctx(&b, Func{}, FuncSig{
		Name: "example.badframe",
		Args: []LLVMType{I32},
		Ret:  Void,
		Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: I32, Index: 1, Field: -1},
		}},
	}, testResolveSym("example"), nil, "386", "i386-unknown-linux-gnu", false)
	if err := c.emitEntryAllocas(); err == nil || !strings.Contains(err.Error(), "invalid arg index 1") {
		t.Fatalf("emitEntryAllocas() error = %v, want invalid frame index", err)
	}
}

func TestAMD64Ignores386ControlInstructions(t *testing.T) {
	c, _ := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.amd64", Ret: Void}, nil)
	for _, op := range []Op{"ADJSP", "CLD", "STD", "REP"} {
		args := []Operand(nil)
		if op == "ADJSP" {
			args = []Operand{{Kind: OpImm, Imm: 8}}
		}
		terminated, err := c.lowerInstr(0, 0, Instr{Op: op, Raw: string(op), Args: args}, nil, nil)
		if err != nil || terminated {
			t.Fatalf("lowerInstr(%s) = (%v, %v), want ignored instruction", op, terminated, err)
		}
	}
}

func TestTranslate386DestinationForms(t *testing.T) {
	const source = `
TEXT vectorResult(SB),NOSPLIT,$0-4
	MOVL $1, AX
	MOVL AX, X0
	MOVL X0, ret+0(FP)
	RET

TEXT vectorMemory(SB),NOSPLIT,$0-0
	MOVL X0, 0(AX)
	RET

TEXT vectorSymbol(SB),NOSPLIT,$0-0
	MOVL X0, vectorSink(SB)
	RET

TEXT x87DoubleMemory(SB),NOSPLIT,$0-0
	FMOVD F0, 0(SP)
	RET

TEXT x87DoubleSymbol(SB),NOSPLIT,$0-0
	FMOVD F0, doubleSink(SB)
	RET

TEXT x87ControlSymbol(SB),NOSPLIT,$0-0
	FSTCW controlSink(SB)
	RET

TEXT x87IntegerMemory(SB),NOSPLIT,$0-0
	FMOVVP F0, 0(SP)
	RET

TEXT x87IntegerSymbol(SB),NOSPLIT,$0-0
	FMOVVP F0, integerSink(SB)
	RET
`
	// The standalone assembler helper has no textflag.h include. Resolve only
	// its standard NOSPLIT flag; every original instruction and operand stays
	// unchanged in this independent Go-386 object check.
	goAssemblerOracleOutput(t, "386", strings.ReplaceAll(source, ",NOSPLIT,", ",4,"), "", true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"vectorResult": {
				Name: "vectorResult", Ret: I32,
				Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}}},
			},
			"vectorMemory":     {Name: "vectorMemory", Args: []LLVMType{Ptr}, Ret: Void},
			"vectorSymbol":     {Name: "vectorSymbol", Ret: Void},
			"x87DoubleMemory":  {Name: "x87DoubleMemory", Ret: Void},
			"x87DoubleSymbol":  {Name: "x87DoubleSymbol", Ret: Void},
			"x87ControlSymbol": {Name: "x87ControlSymbol", Ret: Void},
			"x87IntegerMemory": {Name: "x87IntegerMemory", Ret: Void},
			"x87IntegerSymbol": {Name: "x87IntegerSymbol", Ret: Void},
		},
	}
	if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("original unbacked x87 source did not retain Context", err)
	}
	ir := x86CompileOnlyDestinationEmitterModule(t, file, options)
	check386DestinationFormsIR(t, ir)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "destination_forms.ll", "destination_forms.o", ir)
}

func TestTranslate386ClassicAggregateFrame(t *testing.T) {
	file, err := Parse(ArchAMD64, `TEXT sumPair(SB),NOSPLIT,$0-12
	MOVL pair_first+0(FP), AX
	ADDL pair_second+4(FP), AX
	MOVL AX, ret+8(FP)
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	pair := LLVMType("{ i32, i32 }")
	ir, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"sumPair": {
				Name: "sumPair", Args: []LLVMType{pair}, Ret: I32,
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: I32, Index: 0, Field: 0},
						{Offset: 4, Type: I32, Index: 0, Field: 1},
					},
					Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"extractvalue { i32, i32 } %arg0, 0",
		"extractvalue { i32, i32 } %arg0, 1",
		"store i32 %",
		"align 1",
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("386 aggregate frame IR missing %q:\n%s", want, ir)
		}
	}
	compile386IR(t, ir, "classic_aggregate_frame")
}

func TestTranslate386InstructionFamilies(t *testing.T) {
	// Go's 386 MMX-to-GP transfer is MOVL (the physical MOVD), not the
	// MOVQ source family or its MOVD/MOVDQ2Q aliases. Check both actual
	// encoder outcomes before using that transfer in the lowering fixture.
	goAssemblerOracleOutput(t, "386", "TEXT ·valid(SB),4,$0-0\nMOVL M0,AX\nEMMS\nRET\n", "", true)
	for _, opcode := range []string{"MOVQ", "MOVD", "MOVDQ2Q"} {
		goAssemblerOracleOutput(t, "386", "TEXT ·invalid(SB),4,$0-0\n"+opcode+" M0,AX\nEMMS\nRET\n", "", false)
	}

	src := `
TEXT arith(SB),NOSPLIT,$0-12
	MOVL a+0(FP), AX
	MOVL b+4(FP), BX
	CMPL AX, $0
	ADCL BX, AX
	SBBL $1, AX
	ANDW $0xffff, AX
	ORW $1, AX
	XORW $2, AX
	ADDW $3, AX
	SUBW $4, AX
	IMULL BX, AX
	IMUL3L $3, AX, CX
	IMULL BX
	MOVL $0, -4(SP)
	ADCL AX, -4(SP)
	SETLT -8(SP)
	ADCB $1, -8(SP)
	PUSHL AX
	POPL -4(SP)
	PUSHL AX
	PUSHFL
	POPFL
	POPL BX
	PUSHAL
	POPAL
	MOVL AX, ret+8(FP)
	RET

TEXT x87math(SB),NOSPLIT,$0-24
	FMOVD a+0(FP), F0
	FABS
	FMOVD b+8(FP), F0
	FUCOMI F0, F1
	FXCHD F0, F1
	FDIVD F1, F0
	FMULD F0, F0
	FLD1
	FADDDP F0, F1
	FSQRT
	FMULDP F0, F1
	FTST
	FSTSW AX
	FSTCW -2(SP)
	MOVW -2(SP), AX
	FLDCW -2(SP)
	FRNDINT
	FMOVDP F0, ret+16(FP)
	RET

TEXT x87convert(SB),NOSPLIT,$0-16
	FMOVV value+0(FP), F0
	FMOVVP F0, ret+8(FP)
	RET

TEXT strings386(SB),NOSPLIT,$0-0
	CLD
	REP; MOVSB
	STD
	REP; MOVSL
	CLD
	REP; STOSL
	REPN; SCASB
	RET

TEXT atomic64(SB),NOSPLIT,$0-0
	LOCK
	CMPXCHG8B (SI)
	SETEQ AX
	RET

TEXT mmxload(SB),NOSPLIT,$0-0
	MOVQ (SI), M0
	MOVL M0, AX
	EMMS
	RET

TEXT vectorlow(SB),NOSPLIT,$0-0
	MOVOU (SI), X0
	MOVL X0, AX
	RET

TEXT split64(SB),NOSPLIT,$0-16
	MOVL value_lo+0(FP), AX
	MOVL AX, ret_lo+8(FP)
	MOVL value_hi+4(FP), AX
	MOVL AX, ret_hi+12(FP)
	RET

TEXT splitDouble(SB),NOSPLIT,$0-16
	MOVL value_lo+0(FP), AX
	MOVL AX, ret_lo+8(FP)
	MOVL value_hi+4(FP), AX
	MOVL AX, ret_hi+12(FP)
	RET

TEXT resultPointer(SB),NOSPLIT,$0-8
	MOVL value+0(FP), AX
	MOVL AX, ret+4(FP)
	RET

TEXT linuxSyscall(SB),NOSPLIT,$0-0
	INT $0x80
	RET

TEXT timestamp(SB),NOSPLIT,$0-0
	LFENCE
	RDTSC
	RDTSCP
	RET

TEXT stackAdjust(SB),NOSPLIT,$0-0
	PUSHFL
	ADJSP $156
	MOVL AX, 152(SP)
	ADJSP $-156
	POPFL
	RET

TEXT trap(SB),NOSPLIT,$0-0
	INT $3

TEXT undefined(SB),NOSPLIT,$0-0
	UNDEF

TEXT rawret(SB),NOSPLIT,$0-0
	BYTE $0xc2
	WORD $0
	RET

TEXT cpuidProbe(SB),NOSPLIT,$0-0
	PUSHFL
	PUSHFL
	XORL $0x200000, 0(SP)
	POPFL
	PUSHFL
	POPL AX
	XORL 0(SP), AX
	POPFL
	TESTL $0x200000, AX
	JNE cpuidAvailable
	MOVL $0, AX
	RET
cpuidAvailable:
	MOVL $1, AX
	RET

TEXT symbolAddress(SB),NOSPLIT,$0-0
	MOVL $someGlobal(SB), AX
	RET

TEXT frameAddress(SB),NOSPLIT,$0-12
	LEAL a+0(FP), SI
	MOVL $41, 4(SI)
	MOVL b+4(FP), AX
	MOVL AX, ret+8(FP)
	RET
`
	f64 := LLVMType("double")
	sigs := map[string]FuncSig{
		"arith": {
			Name: "arith", Args: []LLVMType{I32, I32}, Ret: I32,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}},
				Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}},
			},
		},
		"x87math": {
			Name: "x87math", Args: []LLVMType{f64, f64}, Ret: f64,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: f64, Index: 0, Field: -1}, {Offset: 8, Type: f64, Index: 1, Field: -1}},
				Results: []FrameSlot{{Offset: 16, Type: f64, Index: 0, Field: -1}},
			},
		},
		"x87convert": {
			Name: "x87convert", Args: []LLVMType{I64}, Ret: I64,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
				Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
			},
		},
		"strings386": {
			Name: "strings386", Args: []LLVMType{Ptr, Ptr, I32, I32}, Ret: Void,
			ArgRegs: []Reg{SI, DI, CX, AX},
		},
		"atomic64": {
			Name: "atomic64", Args: []LLVMType{Ptr, I32, I32, I32, I32}, Ret: I1,
			ArgRegs: []Reg{SI, AX, DX, BX, CX},
		},
		"mmxload":   {Name: "mmxload", Args: []LLVMType{Ptr}, Ret: I32, ArgRegs: []Reg{SI}},
		"vectorlow": {Name: "vectorlow", Args: []LLVMType{Ptr}, Ret: I32, ArgRegs: []Reg{SI}},
		"split64": {
			Name: "split64", Args: []LLVMType{I64}, Ret: I64,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
				Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
			},
		},
		"splitDouble": {
			Name: "splitDouble", Args: []LLVMType{f64}, Ret: f64,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: f64, Index: 0, Field: -1}},
				Results: []FrameSlot{{Offset: 8, Type: f64, Index: 0, Field: -1}},
			},
		},
		"resultPointer": {
			Name: "resultPointer", Args: []LLVMType{I32}, Ret: Ptr,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
				Results: []FrameSlot{{Offset: 4, Type: Ptr, Index: 0, Field: -1}},
			},
		},
		"linuxSyscall": {
			Name: "linuxSyscall", Args: []LLVMType{I32, I32, I32, I32, I32, I32, I32}, Ret: Void,
			ArgRegs: []Reg{AX, BX, CX, DX, SI, DI, BP},
		},
		"timestamp":     {Name: "timestamp", Ret: I32},
		"stackAdjust":   {Name: "stackAdjust", Ret: Void},
		"trap":          {Name: "trap", Ret: Void},
		"undefined":     {Name: "undefined", Ret: Void},
		"rawret":        {Name: "rawret", Ret: Void},
		"cpuidProbe":    {Name: "cpuidProbe", Ret: I32},
		"symbolAddress": {Name: "symbolAddress", Ret: I32},
		"frameAddress": {
			Name: "frameAddress", Args: []LLVMType{I32, I32}, Ret: I32,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}},
				Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}},
			},
		},
	}

	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{
		TargetTriple: "i386-unknown-linux-gnu",
		ResolveSym: func(sym string) string {
			return strings.TrimPrefix(sym, "·")
		},
		Goarch: "386",
		Sigs:   sigs,
	}
	t.Run("complete-original-physical-stack-remains-Context", func(t *testing.T) {
		ir, err := Translate(file, options)
		if !errors.Is(err, ErrProbeNeedsContext) || ir != "" || !strings.Contains(err.Error(), "result initialization AUTO") {
			t.Fatalf("original zero-frame physical-SP/PUSHAL source gained backing: output=%t error=%v", ir != "", err)
		}
	})
	// Keep the complete original file and declarations. This explicitly
	// selected counterpart does not certify arith's unbound physical stack,
	// PUSHAL/POPAL or live-stack memory addressing. Nothing may reference it.
	if len(file.Funcs) != 19 || len(sigs) != 19 {
		t.Fatal("complete instruction-family TEXT/declaration inventory changed")
	}
	for _, fn := range file.Funcs {
		if fn.Sym == "arith" {
			continue
		}
		for _, ins := range fn.Instrs {
			if strings.Contains(ins.Raw, "arith") {
				t.Fatal("partial selection cannot discard a referenced arithmetic TEXT", ins.Raw)
			}
		}
	}
	var ir string
	boundedCounterpart := x86X87InstructionFamiliesBoundedCounterpart(t, src)
	// The old symbolAddress had an external declaration and a bare AX result.
	// Its separate positive counterpart explicitly supplies same-module DATA
	// and a complete ABI0 result slot. Do not infer either from a MOV opcode.
	const oldAddress = "TEXT symbolAddress(SB),NOSPLIT,$0-0\n\tMOVL $someGlobal(SB), AX\n\tRET"
	const boundedAddress = "TEXT symbolAddress(SB),NOSPLIT,$0-4\n\tMOVL $someGlobal(SB), AX\n\tMOVL AX, ret+0(FP)\n\tRET"
	if strings.Count(boundedCounterpart, oldAddress) != 1 {
		t.Fatal("original address counterpart lost its complete source anchor")
	}
	boundedCounterpart = "DATA someGlobal(SB)/4,$0\nGLOBL someGlobal(SB),8,$4\n" +
		strings.Replace(boundedCounterpart, oldAddress, boundedAddress, 1)
	boundedCounterpart = x86Legacy386StackCounterparts(t, boundedCounterpart)
	boundedSigs := make(map[string]FuncSig, len(sigs))
	for name, sig := range sigs {
		boundedSigs[name] = sig
	}
	boundedCounterpart = x86Legacy386RegisterCounterparts(t, boundedCounterpart, boundedSigs)
	addressSig := boundedSigs["symbolAddress"]
	addressSig.Frame.Results = []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}}
	boundedSigs["symbolAddress"] = addressSig
	boundedSigs["stackAdjust"] = FuncSig{
		Name: "stackAdjust", Args: []LLVMType{I32}, Ret: I32,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
			Results: []FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}},
		},
	}
	boundedSigs["cpuidProbe"] = FuncSig{
		Name: "cpuidProbe", Ret: I32,
		Frame: FrameLayout{
			Results: []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
		},
	}
	t.Run("partial-selection-bounded-counterpart-other-18-TEXTs", func(t *testing.T) {
		// KeepFunc belongs to the Go-module API. The empty package grants no
		// Go declaration; every selected signature is exactly the original
		// explicit manual contract, including custom register assignments,
		// except the separately documented bounded scratch, DATA and stack
		// counterparts. Those complete programs explicitly initialize their
		// inputs and ABI0 outputs; they do not certify the original physical
		// stack programs. arith and all other selected TEXTs stay intact.
		pkg := mustGoPackage(t, "families", "package families")
		result, err := TranslateGoModule(pkg, []byte(boundedCounterpart), GoModuleOptions{
			GOOS: "linux", GOARCH: "386", TargetTriple: options.TargetTriple,
			ResolveSym: options.ResolveSym,
			KeepFunc:   func(text, resolved string) bool { return text != "arith" && resolved != "arith" },
			ManualSig:  func(resolved string) (FuncSig, bool) { sig, found := boundedSigs[resolved]; return sig, found },
		})
		if err != nil {
			t.Fatal(err)
		}
		defer result.Module.Dispose()
		if len(result.Functions) != 18 || len(result.Signatures) != 18 {
			t.Fatal("partial selection changed the remaining TEXT/signature inventory")
		}
		ir = result.Module.String()
	})
	if ir == "" {
		t.Fatal("partial selection did not emit its separate module")
	}
	for _, want := range []string{
		`asm sideeffect "lock; cmpxchg8b`,
		"@__plan9asm_rep_stosl",
		"@__plan9asm_rep_scasb",
		"@__plan9asm_movsb",
		"@__plan9asm_movsl",
		`asm sideeffect "fnstcw $0"`,
		`asm sideeffect "fldcw $0"`,
		`asm sideeffect "fldl $1; frndint; fstpl $0"`,
		`asm sideeffect "cmpb $$0, $3; je 1f; fildll $2;`,
		`1: fldl $1; 2: fistpll $0`,
		"@llvm.sqrt.f64",
		"%x87_control = alloca i16",
		"%local_stack = alloca",
		`"target-features"="+sse2"`,
		`asm sideeffect "int $$0x80"`,
		`asm sideeffect "rdtsc"`,
		`asm sideeffect "rdtscp"`,
		`asm sideeffect "int3"`,
		"%flags_id = alloca i1",
		"%classic_frame = alloca",
		"ptrtoint ptr @someGlobal to i64",
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("386 IR missing %q:\n%s", want, ir)
		}
	}
	if strings.Contains(ir, "call double @llvm.roundeven") || strings.Contains(ir, "call float @llvm.roundeven") {
		t.Fatalf("386 x87 lowering unexpectedly depends on external roundeven:\n%s", ir)
	}
	compile386IR(t, ir, "instruction_families")
	// ADJSP belongs to the original physical-stack format. Keep its complete
	// emitter-only object separate from the public initialized counterpart.
	formatIR := x86Legacy386StackFormatObject(t, options.TargetTriple)
	for _, want := range []string{"sub i64 %", ", 156"} {
		if !strings.Contains(formatIR, want) {
			t.Fatalf("original 386 stack format IR missing %q", want)
		}
	}
	compile386IR(t, formatIR, "original_stack_formats")
	t.Run("independent-bounded-named-AUTO-product", func(t *testing.T) {
		const bounded = "TEXT ·Bounded(SB),4,$16-12\nMOVL a+0(FP),AX\nMOVL b+4(FP),BX\nIMULL BX\nMOVL AX,spill-8(SP)\nMOVL spill-8(SP),AX\nMOVL AX,ret+8(FP)\nRET\n"
		const declaration = "func Bounded(a,b uint32) uint32"
		x86LEAActualTargetGoObject(t, "386", options.TargetTriple, bounded)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, bounded, declaration, "386", options.TargetTriple, api)
				if err != nil {
					t.Fatal(err)
				}
				x86ScalarFPNamedConstantResult(t, ir+"define i32 @Probe() { %r = call i32 @Bounded(i32 2,i32 3)\n ret i32 %r }\n", "Probe", []uint64{6})
				compile386IR(t, ir, "bounded_product_"+api)
				for name, invalid := range map[string]string{
					"unknown-input":  strings.Replace(bounded, "MOVL b+4(FP),BX", "NOP", 1),
					"unwritten-AUTO": strings.Replace(bounded, "MOVL AX,spill-8(SP)", "NOP", 1),
					"physical-SP":    strings.ReplaceAll(bounded, "spill-8(SP)", "-8(SP)"),
					"missing-frame":  strings.Replace(bounded, "$16-12", "$0-12", 1),
					"past-frame":     strings.ReplaceAll(bounded, "spill-8(SP)", "spill-20(SP)"),
				} {
					t.Run(name, func(t *testing.T) {
						output, err := x86ScalarFPBitViewAPI(t, invalid, declaration, "386", options.TargetTriple, api)
						if !errors.Is(err, ErrProbeNeedsContext) || output != "" {
							t.Fatal("bounded counterpart borrowed initialization or native backing", err)
						}
					})
				}
			})
		}
	})
}

func TestTranslate386X87MoveFamilyCompleteForms(t *testing.T) {
	const source = `
TEXT x87moves(SB),NOSPLIT,$0-0
	FMOVB 0(SI), F0
	FMOVBP F0, 0(DI)
	FMOVD 0(SI), F0
	FMOVD $(2.928932188134524e-01), F0
	FMOVD F0, 0(DI)
	FMOVD F1, F0
	FMOVD F0, F1
	FMOVDP F0, 0(DI)
	FMOVDP F0, F1
	FMOVF 0(SI), F0
	FMOVF F0, 0(DI)
	FMOVFP F0, 0(DI)
	FMOVL 0(SI), F0
	FMOVL F0, 0(DI)
	FMOVLP F0, 0(DI)
	FMOVV 0(SI), F0
	FMOVVP F0, 0(DI)
	FMOVW 0(SI), F0
	FMOVW F0, 0(DI)
	FMOVWP F0, 0(DI)
	FMOVX 0(SI), F0
	FMOVXP F0, 0(DI)
	RET
`
	goAssemblerOracleOutput(t, "386", "#include \"textflag.h\"\n"+source, "", true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs:         map[string]FuncSig{"x87moves": {Name: "x87moves", Ret: Void}},
		X87Mode:      X87Software,
	})
	if !errors.Is(err, ErrProbeNeedsContext) || ir != "" || !strings.Contains(err.Error(), "FMOVB 0(SI), F0") {
		t.Fatal("complete no-argument move source acquired SI/DI storage or initialized x87 inputs", err)
	}
	compile386IR(t, x86X87LowererObjectUnit(t, file, "386", "i386-unknown-linux-gnu"), "x87_move_family_emitter_only")
}

func TestTranslate386X87MoveFamilyRejectsNonGoForms(t *testing.T) {
	for _, test := range []struct {
		instruction string
		want        string
	}{
		{instruction: "FMOVF F1, F0", want: "FMOVF expects memory,F0, Freg,F0, F0,memory, or F0,Freg"},
		{instruction: "FMOVFP F1, 0(DI)", want: "FMOVFP expects F0 source and memory or x87-register destination"},
		{instruction: "FMOVL 0(SI), F1", want: "FMOVL expects signed integer memory,F0 or the registered F0,memory store row"},
		{instruction: "FMOVLP F0, F1", want: "FMOVLP expects F0 source and signed integer memory destination"},
		{instruction: "FMOVX F0, F1", want: "FMOVX expects memory source and F0 destination"},
		{instruction: "FMOVXP F1, 0(DI)", want: "FMOVXP expects F0 source and memory destination"},
	} {
		t.Run(test.instruction, func(t *testing.T) {
			source := "TEXT bad(SB),NOSPLIT,$0-0\n" + test.instruction + "\nRET\n"
			goAssemblerOracleOutput(t, "386", "#include \"textflag.h\"\n"+source, "", false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			})
			if err == nil || errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Translate(%q) error = %v, want %q", test.instruction, err, test.want)
			}
		})
	}
}

func TestTranslate386X87ConstantUnaryAndTranscendentalFamily(t *testing.T) {
	const source = `
TEXT x87transcendental(SB),NOSPLIT,$0-0
	FBLD 0(SI)
	FBSTP 0(DI)
	FLD1
	FLDL2E
	FLDL2T
	FLDLG2
	FLDLN2
	FLDPI
	FLDZ
	F2XM1
	FABS
	FCHS
	FCLEX
	FCOS
	FDECSTP
	FINCSTP
	FINIT
	FNOP
	FPATAN
	FPREM
	FPREM1
	FPTAN
	FRNDINT
	FSCALE
	FSIN
	FSINCOS
	FSQRT
	FTST
	FXAM
	FXTRACT
	FYL2X
	FYL2XP1
	RET
`
	goAssemblerOracleOutput(t, "386", "#include \"textflag.h\"\n"+source, "", true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs:         map[string]FuncSig{"x87transcendental": {Name: "x87transcendental", Ret: Void}},
		X87Mode:      X87Software,
	})
	if !errors.Is(err, ErrProbeNeedsContext) || ir != "" || !strings.Contains(err.Error(), "FBLD 0(SI)") {
		t.Fatal("complete no-argument transcendental source acquired SI/DI storage or initialized x87 inputs", err)
	}
	compile386IR(t, x86X87LowererObjectUnit(t, file, "386", "i386-unknown-linux-gnu"), "x87_transcendental_emitter_only")
}

func TestTranslate386X87ConstantUnaryAndTranscendentalFamilyRejectsOperands(t *testing.T) {
	for _, op := range []string{
		"F2XM1", "FABS", "FCHS", "FCLEX", "FCOS", "FDECSTP", "FINCSTP", "FINIT",
		"FLD1", "FLDL2E", "FLDL2T", "FLDLG2", "FLDLN2", "FLDPI", "FLDZ", "FNOP",
		"FPATAN", "FPREM", "FPREM1", "FPTAN", "FRNDINT", "FSCALE", "FSIN", "FSINCOS",
		"FSQRT", "FTST", "FXAM", "FXTRACT", "FYL2X", "FYL2XP1",
	} {
		t.Run(op, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n"+op+" AX\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			})
			if err == nil || !strings.Contains(err.Error(), "takes no operands") {
				t.Fatalf("Translate(%s AX) error = %v, want no-operand rejection", op, err)
			}
		})
	}
	for _, test := range []struct {
		instruction string
		want        string
	}{
		{instruction: "FBLD F0", want: "FBLD expects memory source"},
		{instruction: "FBSTP AX", want: "FBSTP expects memory destination"},
	} {
		file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n"+test.instruction+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		})
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("Translate(%q) error = %v, want %q", test.instruction, err, test.want)
		}
	}
}

func TestTranslate386X87ArithmeticFamilyCompleteForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT x87arithmetic(SB),NOSPLIT,$0-0\n")
	for _, stem := range []string{"FADD", "FMUL", "FSUB", "FSUBR", "FDIV", "FDIVR"} {
		for _, width := range []string{"W", "L", "F"} {
			fmt.Fprintf(&src, "\t%s%s 0(SI), F0\n", stem, width)
		}
		fmt.Fprintf(&src, "\t%sD 0(SI), F0\n", stem)
		fmt.Fprintf(&src, "\t%sD F1, F0\n", stem)
		fmt.Fprintf(&src, "\t%sD F0, F1\n", stem)
		fmt.Fprintf(&src, "\t%sDP F0, F1\n", stem)
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs:         map[string]FuncSig{"x87arithmetic": {Name: "x87arithmetic", Ret: Void}},
		X87Mode:      X87Software,
	})
	if err != nil {
		t.Fatalf("Translate(complete x87 arithmetic family) error = %v", err)
	}
	compile386IR(t, ir, "x87_arithmetic_family")
}

func TestTranslate386X87ArithmeticFamilyRejectsNonGoForms(t *testing.T) {
	for _, test := range []struct {
		instruction string
		want        string
	}{
		{instruction: "FADDW F1, F0", want: "FADDW expects memory source and F0 destination"},
		{instruction: "FMULL 0(SI), F1", want: "FMULL expects memory source and F0 destination"},
		{instruction: "FSUBF F0, 0(DI)", want: "FSUBF expects memory source and F0 destination"},
		{instruction: "FDIVD 0(SI), F1", want: "FDIVD expects memory,F0"},
		{instruction: "FSUBRDP 0(SI), F0", want: "FSUBRDP expects F0 source and x87-register destination"},
		{instruction: "FDIVRDP F1, F0", want: "FDIVRDP expects F0 source and x87-register destination"},
	} {
		t.Run(test.instruction, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n"+test.instruction+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Translate(%q) error = %v, want %q", test.instruction, err, test.want)
			}
		})
	}
}

func TestTranslate386X87CompareFamilyCompleteForms(t *testing.T) {
	file, err := Parse(ArchAMD64, `
TEXT x87compare(SB),NOSPLIT,$0-0
	FCOMD 0(SI), F0
	FCOMD F1, F0
	FCOMD F0, F1
	FCOMDP 0(SI), F0
	FCOMDP F1, F0
	FCOMDP F0, F1
	FCOMDPP F0, F1
	FCOMF 0(SI), F0
	FCOMFP 0(SI), F0
	FCOML 0(SI), F0
	FCOMLP 0(SI), F0
	FCOMW 0(SI), F0
	FCOMWP 0(SI), F0
	FCOMI F1, F0
	FCOMIP F1, F0
	FUCOM F0, F1
	FUCOMP F0, F1
	FUCOMPP F0, F1
	FUCOMI F0, F1
	FUCOMIP F0, F1
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs:         map[string]FuncSig{"x87compare": {Name: "x87compare", Ret: Void}},
		X87Mode:      X87Software,
	})
	if err != nil {
		t.Fatalf("Translate(complete x87 compare family) error = %v", err)
	}
	compile386IR(t, ir, "x87_compare_family")
}

func TestTranslate386X87CompareFamilyRejectsNonGoForms(t *testing.T) {
	for _, test := range []struct {
		instruction string
		want        string
	}{
		{instruction: "FCOMF F1, F0", want: "FCOMF expects memory source or x87-register source and F0 destination"},
		{instruction: "FCOMD 0(SI), F1", want: "FCOMD expects memory source or x87-register source and F0 destination"},
		{instruction: "FCOMDPP F1, F0", want: "FCOMDPP expects F0 source and x87-register destination"},
		{instruction: "FCOMI F0, F1", want: "FCOMI expects x87-register source and F0 destination"},
		{instruction: "FUCOM F1, F0", want: "FUCOM expects F0 source and x87-register destination"},
		{instruction: "FUCOMIP 0(SI), F0", want: "FUCOMIP expects F0 source and x87-register destination"},
	} {
		t.Run(test.instruction, func(t *testing.T) {
			source := "TEXT bad(SB),NOSPLIT,$0-0\n" + test.instruction + "\nRET\n"
			goAssemblerOracleOutput(t, "386", "#include \"textflag.h\"\n"+source, "", false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			})
			if err == nil || errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Translate(%q) error = %v, want %q", test.instruction, err, test.want)
			}
		})
	}
}

func TestTranslate386LAHFSAHFFamily(t *testing.T) {
	const source = `
TEXT flags386(SB),NOSPLIT,$0-0
	LAHF
	SAHF
	RET
`
	goAssemblerOracleOutput(t, "386", "#include \"textflag.h\"\n"+source, "", true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs:         map[string]FuncSig{"flags386": {Name: "flags386", Ret: Void}},
	}
	if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("original uninitialized FLAGS format invented input facts", err)
	}
	initialized := strings.Replace(source, "\tLAHF", "\tMOVL $0,AX\n\tCMPL AX,AX\n\tLAHF", 1)
	goAssemblerOracleOutput(t, "386", "#include \"textflag.h\"\n"+initialized, "", true)
	file, err = Parse(ArchAMD64, initialized)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, options)
	if err != nil {
		t.Fatalf("Translate(LAHF/SAHF) error = %v", err)
	}
	compile386IR(t, ir, "lahf_sahf_family")
	for _, op := range []string{"LAHF", "SAHF"} {
		bad, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n"+op+" AX\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(bad, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		})
		if err == nil || !strings.Contains(err.Error(), "takes no operands") {
			t.Fatalf("Translate(%s AX) error = %v, want no-operand rejection", op, err)
		}
	}
}

func TestTranslate386X87EnvironmentAndControlFamily(t *testing.T) {
	file, err := Parse(ArchAMD64, `
TEXT x87environment(SB),NOSPLIT,$0-0
	FLDCW 0(SI)
	FLDENV 0(SI)
	FRSTOR 0(SI)
	FSAVE 0(DI)
	FSTCW 0(DI)
	FSTENV 0(DI)
	FSTSW 0(DI)
	FSTSW AX
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs:         map[string]FuncSig{"x87environment": {Name: "x87environment", Ret: Void}},
		X87Mode:      X87Software,
	})
	if !errors.Is(err, ErrProbeNeedsContext) || ir != "" || !strings.Contains(err.Error(), "FLDCW 0(SI)") {
		t.Fatalf("complete no-argument ENV source acquired native SI/DI storage: output=%t error=%v", ir != "", err)
	}
	// Typed syntax/object witnesses are independent of the original source's
	// missing incoming pointers, restore image and native write contracts.
}

func TestTranslate386X87EnvironmentAndControlFamilyRejectsNonGoForms(t *testing.T) {
	for _, test := range []struct {
		instruction string
		want        string
	}{
		{instruction: "FLDCW AX", want: "FLDCW expects memory source"},
		{instruction: "FLDENV F0", want: "FLDENV expects memory source"},
		{instruction: "FRSTOR AX", want: "FRSTOR expects memory source"},
		{instruction: "FSAVE AX", want: "FSAVE expects memory destination"},
		{instruction: "FSTCW AX", want: "FSTCW expects memory destination"},
		{instruction: "FSTENV F0", want: "FSTENV expects memory destination"},
		{instruction: "FSTSW BX", want: "FSTSW expects memory destination or AX"},
	} {
		t.Run(test.instruction, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n"+test.instruction+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Translate(%q) error = %v, want %q", test.instruction, err, test.want)
			}
		})
	}
}

func TestTranslate386X87Modes(t *testing.T) {
	hardware := translate386RoundingIR(t, X87Auto)
	for _, want := range []string{
		`asm sideeffect "fnstcw $0"`,
		`asm sideeffect "fldcw $0"`,
		`asm sideeffect "fldl $1; frndint; fstpl $0"`,
		`asm sideeffect "cmpb $$0, $3; je 1f; fildll $2;`,
		`1: fldl $1; 2: fistpll $0`,
	} {
		if !strings.Contains(hardware, want) {
			t.Fatalf("hardware x87 IR missing %q:\n%s", want, hardware)
		}
	}
	for _, unwanted := range []string{
		"call double @llvm.floor.f64",
		"call double @llvm.ceil.f64",
		"call double @llvm.trunc.f64",
		"fcmp uge double",
	} {
		if strings.Contains(hardware, unwanted) {
			t.Fatalf("hardware x87 IR unexpectedly contains %q:\n%s", unwanted, hardware)
		}
	}

	software := translate386RoundingIR(t, X87Software)
	for _, want := range []string{
		"call double @llvm.floor.f64",
		"call double @llvm.ceil.f64",
		"call double @llvm.trunc.f64",
		"fcmp uge double",
	} {
		if !strings.Contains(software, want) {
			t.Fatalf("software x87 IR missing %q:\n%s", want, software)
		}
	}
	if strings.Contains(software, "frndint") || strings.Contains(software, "fistpll") {
		t.Fatalf("software x87 IR unexpectedly contains hardware rounding:\n%s", software)
	}
	compile386IR(t, software, "software_x87")

	file, err := Parse(ArchAMD64, "TEXT invalid(SB),NOSPLIT,$0-0\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		Goarch:  "386",
		Sigs:    map[string]FuncSig{"invalid": {Name: "invalid", Ret: Void}},
		X87Mode: X87Mode(255),
	}); err == nil || !strings.Contains(err.Error(), "invalid x87 mode") {
		t.Fatalf("invalid x87 mode error = %v", err)
	}
}

func TestTranslate386X87Codegen(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("llc not found")
	}
	ir := translate386RoundingIR(t, X87Hardware)
	dir := t.TempDir()
	llPath := filepath.Join(dir, "round.ll")
	if err := os.WriteFile(llPath, []byte(ir), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		triple string
		mattr  string
	}{
		{name: "default", triple: "i386-unknown-linux-gnu"},
		{name: "go386-softfloat", triple: "i386-unknown-linux-gnu", mattr: "+soft-float,-x87,-sse,-sse2"},
		{name: "windows-msvc", triple: "i686-pc-windows-msvc"},
		{name: "windows-mingw", triple: "i686-w64-windows-gnu"},
	} {
		t.Run(test.name, func(t *testing.T) {
			asmPath := filepath.Join(dir, test.name+".s")
			args := []string{"-O2", "-mtriple=" + test.triple}
			if test.mattr != "" {
				args = append(args, "-mattr="+test.mattr)
			}
			args = append(args, "-filetype=asm", llPath, "-o", asmPath)
			if output, err := exec.Command(llc, args...).CombinedOutput(); err != nil {
				if unsupported386Target(string(output)) {
					t.Fatalf("llc lacks 386 target: %s", output)
				}
				t.Fatalf("llc failed: %v\n%s", err, output)
			}
			output, err := os.ReadFile(asmPath)
			if err != nil {
				t.Fatal(err)
			}
			asm := strings.ToLower(string(output))
			for _, want := range []string{"fnstcw", "fldcw", "frndint", "fistpll"} {
				if !strings.Contains(asm, want) {
					t.Fatalf("hardware x87 assembly missing %q:\n%s", want, asm)
				}
			}
			for _, unwanted := range []string{"calll\tfloor", "calll\tceil", "calll\ttrunc", "calll\troundeven"} {
				if strings.Contains(asm, unwanted) {
					t.Fatalf("hardware x87 assembly unexpectedly contains %q:\n%s", unwanted, asm)
				}
			}

			objPath := filepath.Join(dir, test.name+".o")
			objArgs := []string{"-O2", "-mtriple=" + test.triple}
			if test.mattr != "" {
				objArgs = append(objArgs, "-mattr="+test.mattr)
			}
			objArgs = append(objArgs, "-filetype=obj", llPath, "-o", objPath)
			if output, err := exec.Command(llc, objArgs...).CombinedOutput(); err != nil {
				t.Fatalf("llc object emission failed: %v\n%s", err, output)
			}
		})
	}

	softwarePath := filepath.Join(dir, "software.ll")
	if err := os.WriteFile(softwarePath, []byte(translate386RoundingIR(t, X87Software)), 0o644); err != nil {
		t.Fatal(err)
	}
	softwareAsmPath := filepath.Join(dir, "software.s")
	softwareArgs := []string{
		"-O2",
		"-mtriple=i386-unknown-linux-gnu",
		"-mattr=+soft-float,-x87,-sse,-sse2",
		"-filetype=asm",
		softwarePath,
		"-o", softwareAsmPath,
	}
	if output, err := exec.Command(llc, softwareArgs...).CombinedOutput(); err != nil {
		t.Fatalf("llc software x87 emission failed: %v\n%s", err, output)
	}
	output, err := os.ReadFile(softwareAsmPath)
	if err != nil {
		t.Fatal(err)
	}
	softwareAsm := strings.ToLower(string(output))
	for _, unwanted := range []string{"fnstcw", "fldcw", "frndint", "fistp"} {
		if strings.Contains(softwareAsm, unwanted) {
			t.Fatalf("software x87 assembly unexpectedly contains %q:\n%s", unwanted, softwareAsm)
		}
	}
	softwareObjArgs := append([]string(nil), softwareArgs[:3]...)
	softwareObjArgs = append(softwareObjArgs, "-filetype=obj", softwarePath, "-o", filepath.Join(dir, "software.o"))
	if output, err := exec.Command(llc, softwareObjArgs...).CombinedOutput(); err != nil {
		t.Fatalf("llc software x87 object emission failed: %v\n%s", err, output)
	}
}

func translate386RoundingIR(t *testing.T, mode X87Mode) string {
	t.Helper()
	file, err := Parse(ArchAMD64, x86X87LegacyBoundedRoundingSource(mode))
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		X87Mode:      mode,
		Sigs: map[string]FuncSig{
			"round": {
				Name: "round",
				Args: []LLVMType{LLVMType("double")},
				Ret:  I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: LLVMType("double"), Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func TestTranslate386LocalHelperRegisterABI(t *testing.T) {
	src := `
TEXT compare(SB),NOSPLIT,$0-12
	MOVL a+0(FP), SI
	MOVL b+4(FP), DI
	LEAL ret+8(FP), AX
	JMP comparebody<>(SB)

TEXT comparebody<>(SB),NOSPLIT,$0-0
	CMPL SI, DI
	SETLT (AX)
	RET
`
	resolve := func(sym string) string {
		return strings.TrimSuffix(sym, "<>")
	}
	sigs := map[string]FuncSig{
		"compare": {
			Name: "compare", Args: []LLVMType{I32, I32}, Ret: I1,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}},
				Results: []FrameSlot{{Offset: 8, Type: I1, Index: 0, Field: -1}},
			},
		},
		"comparebody": {
			Name: "comparebody", Args: []LLVMType{I32, I32, Ptr}, Ret: Void,
			ArgRegs: []Reg{SI, DI, AX},
		},
	}
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		ResolveSym:   resolve,
		Goarch:       "386",
		Sigs:         sigs,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := ir[strings.Index(ir, "define i1 @compare"):]
	if !strings.Contains(body, "call void @comparebody(i32") || !strings.Contains(body, "ptr %") {
		t.Fatalf("tail helper did not receive its register ABI values:\n%s", ir)
	}
	compile386IR(t, ir, "local_helper")
}

func TestParseWORDValidation(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT raw(SB),NOSPLIT,$0-0\nWORD $4\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := file.Funcs[0].Instrs[1].Op; got != OpWORD {
		t.Fatalf("WORD opcode = %q, want %q", got, OpWORD)
	}
	for _, src := range []string{
		"WORD $4\n",
		"TEXT raw(SB),NOSPLIT,$0-0\nWORD AX\nRET\n",
		"TEXT raw(SB),NOSPLIT,$0-0\nWORD $1, $2\nRET\n",
	} {
		if _, err := Parse(ArchAMD64, src); err == nil {
			t.Fatalf("Parse(%q) unexpectedly succeeded", src)
		}
	}
}

func compile386IR(t *testing.T, ir, name string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("llc not found")
	}
	tmp := t.TempDir()
	llPath := filepath.Join(tmp, name+".ll")
	objPath := filepath.Join(tmp, name+".o")
	if err := os.WriteFile(llPath, []byte(ir), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(llc, "-mtriple=i386-unknown-linux-gnu", "-filetype=obj", llPath, "-o", objPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		if unsupported386Target(string(out)) {
			t.Fatalf("llc does not support i386: %s", strings.TrimSpace(string(out)))
		}
		t.Fatalf("llc failed: %v\n%s", err, out)
	}
}

func TestRuntimeExec386Core(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("32-bit executable smoke test runs on Windows")
	}
	llc := findLLVM22Tool("llc")
	clang := findLLVM22Tool("clang")
	if llc == "" || clang == "" {
		t.Fatal("llc/clang not found")
	}
	// Keep all eighteen original operations and manual register transports.
	// Only the separately verified counterpart supplies real local x87 scratch.
	file, err := Parse(ArchAMD64, runtime386BoundedScratchAssembly(t))
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, runtime386CoreOptions())
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	llPath := filepath.Join(tmp, "add.ll")
	objPath := filepath.Join(tmp, "add.obj")
	cPath := filepath.Join(tmp, "main.c")
	exePath := filepath.Join(tmp, "add.exe")
	if err := os.WriteFile(llPath, []byte(ir), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cPath, []byte(runtime386CoreCSource), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(llc, "-mtriple=i686-pc-windows-msvc", "-filetype=obj", llPath, "-o", objPath).CombinedOutput(); err != nil {
		t.Fatalf("llc failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(clang,
		"--target=i686-pc-windows-msvc",
		"-nostdlib",
		"-fno-builtin",
		"-Wl,/entry:main",
		"-Wl,/subsystem:console",
		objPath, cPath, "-O2", "-o", exePath,
	).CombinedOutput(); err != nil {
		t.Fatalf("clang link failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(exePath).CombinedOutput(); err != nil {
		t.Fatalf("386 executable failed: %v\n%s", err, out)
	}
}

func find386Tool(names ...string) string {
	if llvmConfig := os.Getenv("LLVM_CONFIG"); llvmConfig != "" {
		if output, err := exec.Command(llvmConfig, "--bindir").Output(); err == nil {
			binDir := strings.TrimSpace(string(output))
			for _, name := range names {
				if path, err := exec.LookPath(filepath.Join(binDir, name)); err == nil {
					return path
				}
			}
		}
	}
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}

func unsupported386Target(output string) bool {
	return strings.Contains(output, "No available targets") ||
		strings.Contains(output, "no targets are registered") ||
		strings.Contains(output, "unknown target triple") ||
		strings.Contains(output, "unknown target") ||
		strings.Contains(output, "is not a registered target")
}
