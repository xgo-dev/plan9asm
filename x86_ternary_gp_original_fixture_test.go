package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

const x86ANDNOriginalRuntimeSource = `TEXT andnsemantics(SB),$0-8
	MOVQ out+0(FP), DI
	MOVQ $0xf0, AX
	MOVQ $0xcc, BX
	ANDNQ AX, BX, CX
	MOVQ CX, 0(DI)
	SETCS 24(DI)
	SETEQ 25(DI)
	SETMI 26(DI)
	SETOS 27(DI)
	MOVQ $0, AX
	MOVQ $0, BX
	ANDNQ AX, BX, CX
	MOVQ CX, 8(DI)
	SETCS 28(DI)
	SETEQ 29(DI)
	SETMI 30(DI)
	SETOS 31(DI)
	MOVL $0x80000000, AX
	MOVL $0, BX
	ANDNL AX, BX, CX
	MOVQ CX, 16(DI)
	SETCS 32(DI)
	SETEQ 33(DI)
	SETMI 34(DI)
	SETOS 35(DI)
	RET
`

func x86ParallelBitsOriginalRuntimeFixture(t *testing.T) (source, decl, checks *strings.Builder, sigs map[string]FuncSig) {
	t.Helper()
	source, decl, checks = &strings.Builder{}, &strings.Builder{}, &strings.Builder{}
	sigs = make(map[string]FuncSig)
	index := 0
	for _, op := range []string{"PDEPL", "PDEPQ", "PEXTL", "PEXTQ"} {
		for _, memory := range []bool{false, true} {
			for dst := 8; dst <= 10; dst++ {
				name := fmt.Sprintf("parallelbits%d", index)
				index++
				fmt.Fprintf(source, "TEXT %s(SB),4,$0-24\n"+
					"MOVQ value+0(FP),R8\nMOVQ mask+8(FP),SI\n"+
					"MOVQ (SI),R9\nMOVQ out+16(FP),DI\nMOVQ $-1,R10\n"+
					"MOVL $2147483647,CX\nADDL $1,CX\n", name)
				mask := "R9"
				if memory {
					mask = "(SI)"
				}
				code := assembleX87ControlBytes(t, "amd64", fmt.Sprintf("TEXT probe(SB),4,$0-0\n%s %s,R8,R%d\nRET\n", op, mask, dst))
				for _, b := range code[:len(code)-1] {
					fmt.Fprintf(source, "BYTE $%#02x\n", b)
				}
				fmt.Fprintf(source, "MOVQ R%d,(DI)\nSETCS 8(DI)\nSETEQ 9(DI)\n"+
					"SETPS 10(DI)\nSETMI 11(DI)\nSETOS 12(DI)\nRET\n", dst)
				sigs[name] = FuncSig{
					Name: name, Args: []LLVMType{I64, Ptr, Ptr}, Ret: Void,
					Frame: FrameLayout{Params: []FrameSlot{
						{Offset: 0, Type: I64, Index: 0, Field: -1},
						{Offset: 8, Type: Ptr, Index: 1, Field: -1},
						{Offset: 16, Type: Ptr, Index: 2, Field: -1},
					}},
				}
				fmt.Fprintf(decl, "extern void %s(uint64_t,const void *,void *);\n", name)
				bits, deposit := 32, 0
				if strings.HasSuffix(op, "Q") {
					bits = 64
				}
				if strings.HasPrefix(op, "PDEP") {
					deposit = 1
				}
				fmt.Fprintf(checks, "if(check(%s,%d,%d)) return %d;\n", name, bits, deposit, index)
			}
		}
	}
	return
}
