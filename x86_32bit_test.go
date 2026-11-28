package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

func TestParse386NamedStackOffset(t *testing.T) {
	op, err := asm.ParseOperand("control-4(SP)")
	if err != nil {
		t.Fatal(err)
	}
	if op.Kind != OpMem || op.Mem.Base != SP || op.Mem.Off != -4 {
		t.Fatalf("ParseOperand(control-4(SP)) = %#v", op)
	}
}

func TestTranslate386SymbolIndexedMemory(t *testing.T) {
	for _, invalid := range []string{
		"masks<>(SB)(BX*8)junk",
		"masks<>(SB)(BAD*8)",
	} {
		if _, ok := asm.ParseMem(invalid); ok {
			t.Fatalf("ParseMem(%q) unexpectedly succeeded", invalid)
		}
	}

	file, err := Parse(ArchAMD64, `
GLOBL masks<>(SB), RODATA, $256
TEXT lookup(SB),NOSPLIT,$0-0
	PAND masks<>(SB)(BX*8), X1
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	src := file.Funcs[0].Instrs[1].Args[0]
	if src.Kind != OpMem || src.Mem.Sym != "masks<>(SB)" || src.Mem.Index != BX || src.Mem.Scale != 8 {
		t.Fatalf("parse symbol-indexed memory = %#v", src)
	}
	if got := src.String(); got != "masks<>(SB)(BX*8)" {
		t.Fatalf("symbol-indexed memory string = %q", got)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "i386-pc-windows-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"lookup": {Name: "lookup", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ir, `masks<>(SB)(BX*8)`) ||
		!strings.Contains(ir, "ptrtoint ptr @") ||
		!strings.Contains(ir, "mul i64") {
		t.Fatalf("symbol-indexed address was not lowered:\n%s", ir)
	}
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
		{name: "repne movs", instruction: "REPN; MOVSB", want: "REPN is unsupported for MOVSB"},
		{name: "rep scas", instruction: "REP; SCASB", want: "REP SCASB is not yet supported"},
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
		{name: "cmpxchg8b destination", instruction: "CMPXCHG8B AX", want: "CMPXCHG8B expects mem"},
		{name: "cmpxchg8b segment", instruction: "CMPXCHG8B 0(FS)", want: "does not support segment-relative memory"},
		{name: "fmovd count", instruction: "FMOVD F0", want: "FMOVD expects src, dst"},
		{name: "fmovd destination", instruction: "FMOVD F0, AX", want: "unsupported x87 double destination"},
		{name: "fmovdp count", instruction: "FMOVDP F0", want: "FMOVDP expects src, dst"},
		{name: "fmovdp destination", instruction: "FMOVDP F0, AX", want: "unsupported x87 double destination"},
		{name: "fmovv count", instruction: "FMOVV AX", want: "FMOVV expects src, dst"},
		{name: "fmovv destination", instruction: "FMOVV AX, F1", want: "FMOVV expects F0 destination"},
		{name: "fmovvp count", instruction: "FMOVVP F0", want: "FMOVVP expects src, dst"},
		{name: "fmovvp source", instruction: "FMOVVP F1, 0(SP)", want: "FMOVVP expects F0 source"},
		{name: "fmovvp destination", instruction: "FMOVVP F0, AX", want: "unsupported x87 integer destination"},
		{name: "fxchd count", instruction: "FXCHD F0", want: "FXCHD expects Fsrc, Fdst"},
		{name: "fxchd registers", instruction: "FXCHD AX, BX", want: "FXCHD expects x87 registers"},
		{name: "fdivd count", instruction: "FDIVD F0", want: "FDIVD expects src, dst"},
		{name: "fdivd destination", instruction: "FDIVD F0, $1", want: "unsupported x87 double destination"},
		{name: "fadddp count", instruction: "FADDDP F0", want: "FADDDP expects src, dst"},
		{name: "fadddp destination", instruction: "FADDDP F0, $1", want: "unsupported x87 double destination"},
		{name: "fstcw count", instruction: "FSTCW", want: "FSTCW expects dst"},
		{name: "fstcw destination", instruction: "FSTCW ret+0(FP)", want: "unsupported x87 word destination"},
		{name: "fldcw count", instruction: "FLDCW", want: "FLDCW expects src"},
		{name: "frndint operand", instruction: "FRNDINT AX", want: "FRNDINT takes no operands"},
		{name: "fabs operand", instruction: "FABS AX", want: "FABS takes no operands"},
		{name: "fucomi count", instruction: "FUCOMI F0", want: "FUCOMI expects lhs, rhs"},
		{name: "ftst operand", instruction: "FTST AX", want: "FTST takes no operands"},
		{name: "fstsw count", instruction: "FSTSW", want: "FSTSW expects dst"},
		{name: "fstsw destination", instruction: "FSTSW ret+0(FP)", want: "unsupported x87 word destination"},
		{name: "fld1 operand", instruction: "FLD1 AX", want: "FLD1 takes no operands"},
		{name: "pushl on amd64", instruction: "PUSHL AX", want: "requires GOARCH=386", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "popl on amd64", instruction: "POPL AX", want: "requires GOARCH=386", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "pushfl on amd64", instruction: "PUSHFL", want: "requires GOARCH=386", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "popfl on amd64", instruction: "POPFL", want: "requires GOARCH=386", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "pushal on amd64", instruction: "PUSHAL", want: "requires GOARCH=386", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "popal on amd64", instruction: "POPAL", want: "requires GOARCH=386", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "vector low destination", instruction: "MOVL X0, $1", want: "MOVL from X reg unsupported dst"},
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
	file, err := Parse(ArchAMD64, `TEXT stack(SB),NOSPLIT,$0-0
	MOVL AX, SP
	SUBL $256, SP
	ADDL AX, SP
	ADDL $32, SP
	ANDL $~15, SP
	LEAL 4(SP), SP
	POPL SP
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs:         map[string]FuncSig{"stack": {Name: "stack", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"%local_stack = alloca [770 x i8]",
		"sub i32",
		"add i32",
		"and i32",
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("386 direct SP lowering missing %q:\n%s", want, ir)
		}
	}
}

func TestTranslate386DestinationForms(t *testing.T) {
	file, err := Parse(ArchAMD64, `
TEXT vectorResult(SB),NOSPLIT,$0-4
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
`)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
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
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"store i32 %",
		"vectorSink",
		"store double",
		"doubleSink",
		"store i16",
		"controlSink",
		"store i64",
		"integerSink",
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("386 destination-form IR missing %q:\n%s", want, ir)
		}
	}
	compile386IR(t, ir, "destination_forms")
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
	MOVQ M0, AX
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
		"mmxload":   {Name: "mmxload", Args: []LLVMType{Ptr}, Ret: I64, ArgRegs: []Reg{SI}},
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
	ir, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		ResolveSym: func(sym string) string {
			return strings.TrimPrefix(sym, "·")
		},
		Goarch: "386",
		Sigs:   sigs,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"cmpxchg ptr",
		"@__plan9asm_rep_stosl",
		"@__plan9asm_repne_scasb",
		"@__plan9asm_movsb",
		"@__plan9asm_movsl",
		`asm sideeffect "fnstcw $0"`,
		`asm sideeffect "fldcw $0"`,
		`asm sideeffect "fnclex"`,
		`asm sideeffect "fldt $3; frndint; fnstsw $2; fstpt $0"`,
		`asm sideeffect "fldt $2; fistpll $0; fnstsw $1"`,
		`asm sideeffect "fldt $3; fsqrt; fnstsw $2; fstpt $0"`,
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
		"sub i64 %",
		", 156",
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("386 IR missing %q:\n%s", want, ir)
		}
	}
	if strings.Contains(ir, "roundeven") {
		t.Fatalf("386 x87 lowering unexpectedly depends on external roundeven:\n%s", ir)
	}
	compile386IR(t, ir, "instruction_families")
}

func TestTranslate386X87Modes(t *testing.T) {
	hardware := translate386RoundingIR(t, X87Auto)
	for _, want := range []string{
		`asm sideeffect "fnstcw $0"`,
		`asm sideeffect "fldcw $0"`,
		`asm sideeffect "fnclex"`,
		`asm sideeffect "fldt $3; frndint; fnstsw $2; fstpt $0"`,
		`asm sideeffect "fldt $2; fistpll $0; fnstsw $1"`,
	} {
		if !strings.Contains(hardware, want) {
			t.Fatalf("hardware x87 IR missing %q:\n%s", want, hardware)
		}
	}
	if strings.Contains(hardware, "call i64 @llvm.ctlz.i64") {
		t.Fatalf("hardware x87 IR unexpectedly contains portable software rounding:\n%s", hardware)
	}

	software := translate386RoundingIR(t, X87Software)
	if !strings.Contains(software, "call i64 @llvm.ctlz.i64") {
		t.Fatalf("software x87 IR missing portable ctlz rounding:\n%s", software)
	}
	if strings.Contains(software, "asm sideeffect") {
		t.Fatalf("software x87 IR unexpectedly contains hardware inline asm:\n%s", software)
	}
	compile386IR(t, software, "software_x87")

	// Software mode without FINIT/FLDCW must reject uninitialized control word.
	uninitFile, err := Parse(ArchAMD64, `TEXT round(SB),NOSPLIT,$0-16
	FMOVD value+0(FP), F0
	FRNDINT
	FMOVVP F0, ret+8(FP)
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(uninitFile, Options{
		Goarch:  "386",
		X87Mode: X87Software,
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
	}); err == nil || !strings.Contains(err.Error(), "instruction probe needs function context: result initialization") {
		t.Fatalf("uninitialized software x87 error = %v", err)
	}

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
		t.Skip("llc not found")
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
	src := `TEXT round(SB),NOSPLIT,$0-16
	FMOVD value+0(FP), F0
	FSTCW -2(SP)
	FLDCW -2(SP)
	FRNDINT
	FMOVVP F0, ret+8(FP)
	RET
`
	if mode == X87Software {
		src = `TEXT round(SB),NOSPLIT,$0-16
	FINIT
	FMOVD value+0(FP), F0
	FSTCW -2(SP)
	FLDCW -2(SP)
	FRNDINT
	FMOVVP F0, ret+8(FP)
	RET
`
	}
	file, err := Parse(ArchAMD64, src)
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
		t.Skip("llc not found")
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
			t.Skipf("llc does not support i386: %s", strings.TrimSpace(string(out)))
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
		t.Skip("llc/clang not found")
	}
	file, err := Parse(ArchAMD64, `
TEXT addCarry(SB),NOSPLIT,$0-12
	MOVL a+0(FP), AX
	MOVL b+4(FP), BX
	CMPL AX, $0
	ADCL BX, AX
	MOVL AX, ret+8(FP)
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

TEXT frameAddress(SB),NOSPLIT,$0-12
	LEAL a+0(FP), SI
	MOVL $41, 4(SI)
	MOVL b+4(FP), AX
	MOVL AX, ret+8(FP)
	RET

TEXT copyForward(SB),NOSPLIT,$0-12
	MOVL dst+0(FP), DI
	MOVL src+4(FP), SI
	MOVL n+8(FP), CX
	CLD
	REP; MOVSB
	RET

TEXT copyBackward(SB),NOSPLIT,$0-12
	MOVL dst+0(FP), DI
	MOVL src+4(FP), SI
	MOVL n+8(FP), CX
	ADDL CX, DI
	ADDL CX, SI
	DECL DI
	DECL SI
	STD
	REP; MOVSB
	CLD
	RET

TEXT copyBackwardRestoredDF(SB),NOSPLIT,$0-12
	MOVL dst+0(FP), DI
	MOVL src+4(FP), SI
	MOVL n+8(FP), CX
	ADDL CX, DI
	ADDL CX, SI
	DECL DI
	DECL SI
	STD
	PUSHFL
	CLD
	POPFL
	REP; MOVSB
	CLD
	RET

TEXT fillWords(SB),NOSPLIT,$0-12
	MOVL dst+0(FP), DI
	MOVL value+4(FP), AX
	MOVL n+8(FP), CX
	CLD
	REP; STOSL
	RET

TEXT findByte(SB),NOSPLIT,$0-16
	MOVL data+0(FP), DI
	MOVL n+4(FP), CX
	MOVL value+8(FP), AX
	CLD
	REPN; SCASB
	MOVL CX, ret+12(FP)
	RET

TEXT zeroLengthScanPreservesZF(SB),NOSPLIT,$0-8
	MOVL data+0(FP), DI
	MOVL $0, CX
	CMPL AX, AX
	REPN; SCASB
	JNE zfLost
	MOVL $1, AX
	MOVL AX, ret+4(FP)
	RET
zfLost:
	MOVL $0, AX
	MOVL AX, ret+4(FP)
	RET

TEXT negateHasCarry(SB),NOSPLIT,$0-8
	MOVL value+0(FP), AX
	NEGL AX
	SETCS BX
	MOVL BX, ret+4(FP)
	RET

TEXT floorValue(SB),NOSPLIT,$0-16
	FMOVD value+0(FP), F0
	FSTCW -2(SP)
	MOVW -2(SP), AX
	ANDW $0xf3ff, AX
	ORW $0x0400, AX
	MOVW AX, -4(SP)
	FLDCW -4(SP)
	FRNDINT
	FLDCW -2(SP)
	FMOVDP F0, ret+8(FP)
	RET

TEXT uint32ToFloat64(SB),NOSPLIT,$0-12
	MOVL value+0(FP), AX
	MOVL AX, 0(SP)
	MOVL $0, 4(SP)
	FMOVV 0(SP), F0
	FMOVDP F0, ret+4(FP)
	RET

TEXT cas64(SB),NOSPLIT,$0-0
	LOCK
	CMPXCHG8B (SI)
	SETEQ AX
	RET

TEXT xadd32(SB),NOSPLIT,$0-12
	MOVL ptr+0(FP), BX
	MOVL delta+4(FP), AX
	MOVL AX, CX
	LOCK
	XADDL AX, 0(BX)
	ADDL CX, AX
	MOVL AX, ret+8(FP)
	RET

TEXT identity64(SB),NOSPLIT,$0-16
	MOVL value_lo+0(FP), AX
	MOVL AX, ret_lo+8(FP)
	MOVL value_hi+4(FP), AX
	MOVL AX, ret_hi+12(FP)
	RET

TEXT identityFloat64(SB),NOSPLIT,$0-16
	MOVL value_lo+0(FP), AX
	MOVL AX, ret_lo+8(FP)
	MOVL value_hi+4(FP), AX
	MOVL AX, ret_hi+12(FP)
	RET

TEXT readFS(SB),NOSPLIT,$0-4
	MOVL 0x18(FS), AX
	MOVL AX, ret+0(FP)
	RET

TEXT roundNearest(SB),NOSPLIT,$0-16
	FMOVD value+0(FP), F0
	FRNDINT
	FMOVDP F0, ret+8(FP)
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	sig := FuncSig{
		Name: "addCarry", Args: []LLVMType{I32, I32}, Ret: I32,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}},
			Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}},
		},
	}
	frameSig := func(name string, args []LLVMType, ret LLVMType, params, results []FrameSlot) FuncSig {
		return FuncSig{
			Name: name, Args: args, Ret: ret,
			Frame: FrameLayout{Params: params, Results: results},
		}
	}
	ir, err := Translate(file, Options{
		TargetTriple: "i686-pc-windows-msvc",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"addCarry":   sig,
			"cpuidProbe": {Name: "cpuidProbe", Ret: I32},
			"frameAddress": frameSig("frameAddress", []LLVMType{I32, I32}, I32,
				[]FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}},
				[]FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}}),
			"copyForward": frameSig("copyForward", []LLVMType{Ptr, Ptr, I32}, Void,
				[]FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 4, Type: Ptr, Index: 1, Field: -1}, {Offset: 8, Type: I32, Index: 2, Field: -1}}, nil),
			"copyBackward": frameSig("copyBackward", []LLVMType{Ptr, Ptr, I32}, Void,
				[]FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 4, Type: Ptr, Index: 1, Field: -1}, {Offset: 8, Type: I32, Index: 2, Field: -1}}, nil),
			"copyBackwardRestoredDF": frameSig("copyBackwardRestoredDF", []LLVMType{Ptr, Ptr, I32}, Void,
				[]FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 4, Type: Ptr, Index: 1, Field: -1}, {Offset: 8, Type: I32, Index: 2, Field: -1}}, nil),
			"fillWords": frameSig("fillWords", []LLVMType{Ptr, I32, I32}, Void,
				[]FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}, {Offset: 8, Type: I32, Index: 2, Field: -1}}, nil),
			"findByte": frameSig("findByte", []LLVMType{Ptr, I32, I32}, I32,
				[]FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}, {Offset: 8, Type: I32, Index: 2, Field: -1}},
				[]FrameSlot{{Offset: 12, Type: I32, Index: 0, Field: -1}}),
			"zeroLengthScanPreservesZF": frameSig("zeroLengthScanPreservesZF", []LLVMType{Ptr}, I32,
				[]FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}},
				[]FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}}),
			"negateHasCarry": frameSig("negateHasCarry", []LLVMType{I32}, I32,
				[]FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
				[]FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}}),
			"floorValue": frameSig("floorValue", []LLVMType{LLVMType("double")}, LLVMType("double"),
				[]FrameSlot{{Offset: 0, Type: LLVMType("double"), Index: 0, Field: -1}},
				[]FrameSlot{{Offset: 8, Type: LLVMType("double"), Index: 0, Field: -1}}),
			"uint32ToFloat64": frameSig("uint32ToFloat64", []LLVMType{I32}, LLVMType("double"),
				[]FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
				[]FrameSlot{{Offset: 4, Type: LLVMType("double"), Index: 0, Field: -1}}),
			"cas64": {
				Name: "cas64", Args: []LLVMType{Ptr, I32, I32, I32, I32}, Ret: I1,
				ArgRegs: []Reg{SI, AX, DX, BX, CX},
			},
			"xadd32": frameSig("xadd32", []LLVMType{Ptr, I32}, I32,
				[]FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}},
				[]FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}}),
			"identity64": frameSig("identity64", []LLVMType{I64}, I64,
				[]FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
				[]FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}}),
			"identityFloat64": frameSig("identityFloat64", []LLVMType{LLVMType("double")}, LLVMType("double"),
				[]FrameSlot{{Offset: 0, Type: LLVMType("double"), Index: 0, Field: -1}},
				[]FrameSlot{{Offset: 8, Type: LLVMType("double"), Index: 0, Field: -1}}),
			"readFS": frameSig("readFS", nil, I32, nil,
				[]FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}}),
			"roundNearest": frameSig("roundNearest", []LLVMType{LLVMType("double")}, LLVMType("double"),
				[]FrameSlot{{Offset: 0, Type: LLVMType("double"), Index: 0, Field: -1}},
				[]FrameSlot{{Offset: 8, Type: LLVMType("double"), Index: 0, Field: -1}}),
		},
	})
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
	const cSource = `
int _fltused;
extern int addCarry(int, int);
extern int cpuidProbe(void);
extern int frameAddress(int, int);
extern void copyForward(unsigned char *, const unsigned char *, unsigned int);
extern void copyBackward(unsigned char *, const unsigned char *, unsigned int);
extern void copyBackwardRestoredDF(unsigned char *, const unsigned char *, unsigned int);
extern void fillWords(unsigned int *, unsigned int, unsigned int);
extern unsigned int findByte(const unsigned char *, unsigned int, unsigned int);
extern unsigned int zeroLengthScanPreservesZF(const unsigned char *);
extern unsigned int negateHasCarry(unsigned int);
extern double floorValue(double);
extern double uint32ToFloat64(unsigned int);
extern _Bool cas64(unsigned long long *, unsigned int, unsigned int, unsigned int, unsigned int);
extern unsigned int xadd32(unsigned int *, unsigned int);
extern unsigned long long identity64(unsigned long long);
extern double identityFloat64(double);
extern unsigned int readFS(void);
extern double roundNearest(double);
int main(void) {
    unsigned int i;
    const unsigned char source[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    unsigned char copied[8] = {0};
    unsigned char overlap[9] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    unsigned char restoredOverlap[9] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    unsigned char forwardOverlap[5] = {1, 2, 3, 4, 5};
    unsigned int words[4] = {0};
    __declspec(align(8)) unsigned long long word = 0x1122334455667788ULL;
    unsigned int atomicWord = 10;
    if (addCarry(20, 22) != 42) return 11;
    if (cpuidProbe() != 1) return 12;
    if (frameAddress(20, 22) != 41) return 13;
    copyForward(copied, source, 8);
    for (i = 0; i < 8; i++) if (copied[i] != source[i]) return 14;
    copyBackward(overlap + 1, overlap, 8);
    for (i = 0; i < 8; i++) if (overlap[i + 1] != i) return 15;
    copyBackwardRestoredDF(restoredOverlap + 1, restoredOverlap, 8);
    for (i = 0; i < 8; i++) if (restoredOverlap[i + 1] != i) return 31;
    fillWords(words, 0x89abcdefU, 4);
    for (i = 0; i < 4; i++) if (words[i] != 0x89abcdefU) return 16;
    if (findByte(source, 8, 4) != 4) return 17;
    if (findByte(source, 8, 9) != 0) return 18;
    if (zeroLengthScanPreservesZF(source) != 1) return 32;
    if (negateHasCarry(0) != 0 || negateHasCarry(7) != 1) return 33;
    if (floorValue(3.75) != 3.0 || floorValue(-3.25) != -4.0) return 19;
    if (uint32ToFloat64(0xffffffffU) != 4294967295.0) return 20;
    if (!cas64(&word, 0x55667788U, 0x11223344U, 0xaabbccddU, 0x99aabbccU)) return 21;
    if (word != 0x99aabbccaabbccddULL) return 22;
    if (cas64(&word, 0, 0, 1, 2) || word != 0x99aabbccaabbccddULL) return 23;
    if (xadd32(&atomicWord, 5) != 15 || atomicWord != 15) return 24;
    if (identity64(0x8877665544332211ULL) != 0x8877665544332211ULL) return 25;
    if (identityFloat64(-123.75) != -123.75) return 26;
    copyForward(forwardOverlap + 1, forwardOverlap, 4);
    for (i = 0; i < 5; i++) if (forwardOverlap[i] != 1) return 27;
    if (readFS() == 0) return 28;
    if (roundNearest(2.5) != 2.0 || roundNearest(3.5) != 4.0 || roundNearest(-1.5) != -2.0) return 29;
    {
        union { double f; unsigned long long u; } rounded;
        rounded.f = roundNearest(-0.5);
        if (rounded.u != 0x8000000000000000ULL) return 30;
    }
    return 0;
}
`
	if err := os.WriteFile(cPath, []byte(cSource), 0o644); err != nil {
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
