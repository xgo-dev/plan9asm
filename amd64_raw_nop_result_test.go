package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86RawNOPResultReadComposition(t *testing.T) {
	x86RawNOPResultReadComposition(t, false)
}

func x86RawNOPResultReadComposition(t *testing.T, align bool) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			mode, word, move := 64, 8, "MOVQ"
			if target.arch == "386" {
				mode, word, move = 32, 4, "MOVL"
			}
			var literals strings.Builder
			if align {
				literals.WriteString("PCALIGN $32\n")
			}
			for _, code := range x86RawNOPWitnesses(mode) {
				literals.WriteString(x86RawDisplacementDirectives(code))
			}
			body := fmt.Sprintf("%s p+0(FP),DX\n%sVMOVDQU (DX),Y1\nPEXTRD $0,X1,AX\nMOVL AX,ret0+%d(FP)\nRET",
				move, literals.String(), word)
			_, file, sig, source := x86ResultInitializationFixture(t, target.arch, "func Value(p *[64]byte) uint32", body)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			normalized, err := decodeX86RawDirectives(file.Funcs[0], target.arch)
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckX86ABI0ResultInitialization(normalized, sig, target.arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("inert raw bytes granted a standalone native read", err)
			}
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *[64]byte) uint32", target.arch, target.triple, api)
				if err != nil {
					t.Fatal("inert NOPs blocked the independently paired native read", api, err)
				}
				compileLLVMToObject(t, llc, target.triple, "nop-result.ll", "nop-result.o", ir)
				compileLLVMToObject(t, llc, target.triple, "nop-result-opt.ll", "nop-result-opt.o", x86MulDivRoundOptimize(t, ir))
			}
		})
	}
}

func TestX86RawNOPResultReadRetainsRawBoundaries(t *testing.T) {
	literal := x86RawDisplacementDirectives([]byte{0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0})
	_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(p *[64]byte) uint32",
		"MOVQ p+0(FP),DX\n"+literal+"VMOVDQU (DX),Y1\nPEXTRD $0,X1,AX\nMOVL AX,ret0+8(FP)\nRET")
	normalized, err := decodeX86RawDirectives(file.Funcs[0], "amd64")
	if err != nil {
		t.Fatal(err)
	}
	nop := -1
	for i, ins := range normalized.Instrs {
		if ins.x86SourceRaw != nil {
			if nop != -1 || ins.Op != "NOP" {
				t.Fatal("fixture did not decode one inert raw instruction")
			}
			nop = i
		}
	}
	if nop == -1 {
		t.Fatal("missing actual raw NOP handoff")
	}
	for _, mutation := range []string{"original opcode", "original operands", "normalized opcode", "normalized operands", "encoded", "address size", "raw return", "raw TEXT", "source stack", "fixed local"} {
		t.Run(mutation, func(t *testing.T) {
			fn := normalized
			fn.Instrs = append([]Instr(nil), fn.Instrs...)
			ins := &fn.Instrs[nop]
			origin := *ins.x86SourceRaw
			ins.x86SourceRaw = &origin
			switch mutation {
			case "original opcode":
				origin.op = "PAUSE"
			case "original operands":
				origin.args = []Operand{{Kind: OpReg, Reg: AX}}
			case "normalized opcode":
				ins.Op = "PAUSE"
			case "normalized operands":
				ins.Args = []Operand{{Kind: OpReg, Reg: AX}}
			case "encoded":
				ins.x86Encoded = true
			case "address size":
				ins.x86AddressBits = 32
			case "raw return":
				ins.x86RawNearReturn = new(x86RawNearReturnForm)
			case "raw TEXT":
				fn.X86RawText = []byte{0x90}
			case "source stack":
				fn.x86SourceStack = new(x86SourceStackProof)
			case "fixed local":
				fn.x86FixedLocal = new(x86FixedLocalProof)
			}
			ctx := &amd64Ctx{fpScalarSource: fn, sig: sig, goarch: "amd64"}
			if err := ctx.checkLoweredScalarFPResultInitialization(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("inert padding granted another raw or entry contract", err)
			}
		})
	}
}
