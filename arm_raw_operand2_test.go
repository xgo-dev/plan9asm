package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestARMRawOperand2StatusAndFormats(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	// The first word is the literal in the official asm5 corpus:
	// ANDEQ R0,R0,R0 leaves NZCV alone. The matrix then exercises both
	// S-bit settings, conditional execution, and each Operand2 layout.
	var source strings.Builder
	source.WriteString(`TEXT operand2(SB),4,$0-0
 MOVW $0,R0
 CMP $0,R0
 WORD $0
 MOVW.EQ $1,R0
 MOVW $0x80000001,R1
 MOVW $0x60000000,R6
 MOVW $5,R3
`)
	for opcode := uint32(0); opcode < 16; opcode++ {
		test := opcode >= 8 && opcode <= 11
		for _, cond := range []uint32{0, 14} {
			for _, flags := range []uint32{0, 1} {
				if test && flags == 0 {
					continue // miscellaneous instruction encodings
				}
				for _, mode := range []uint32{
					1,               // R1 (LSL #0)
					1 | 1<<5,        // R1, LSR #32
					1 | 2<<5,        // R1, ASR #32
					1 | 3<<5,        // R1, RRX
					1 | 3<<5 | 4<<7, // R1, ROR #4
					1 | 1<<4 | 3<<8, // R1, LSL R3
					1<<25 | 0x104,   // imm8=4, rotation=2, decoded literal 1
				} {
					word := cond<<28 | opcode<<21 | flags<<20 | mode
					if !test {
						word |= 2 << 12 // Rd is R2
					}
					fmt.Fprintf(&source, " MOVW R6,CPSR\n WORD $%#08x\n MOVW CPSR,R4\n", word)
				}
			}
		}
	}
	source.WriteString(" RET\n")
	requireARMGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: map[string]FuncSig{
				"operand2": {Name: "operand2", Ret: Void},
			}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "operand2.ll", "operand2.o", ir)
		})
	}
}

func TestARMRawOperand2RequiresActualStatus(t *testing.T) {
	for _, tt := range []struct {
		word uint32
		want string
	}{
		{0x00000000, "initialized EQ predicate"}, // AND.EQ
		{0xe1a02061, "carry input"},              // MOV R2,R1,RRX
		{0xe0a02001, "carry input"},              // ADC R2,R0,R1
	} {
		t.Run(fmt.Sprintf("%08x", tt.word), func(t *testing.T) {
			source := fmt.Sprintf("TEXT operand2(SB),4,$0-0\n MOVW $1,R0\n MOVW $2,R1\n WORD $%#08x\n RET\n", tt.word)
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{
				"operand2": {Name: "operand2", Ret: Void},
			}})
			if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("WORD status check = %v, want %s", err, tt.want)
			}
		})
	}
}

func testARMRawOperand2ContinuationRuntime(t *testing.T, llc string) {
	t.Helper()
	const source = `TEXT oracle(SB),4,$0-20
 MOVW out+16(FP),R4
 MOVW $0,R0
 CMP $0,R0
 WORD $0
 MOVW.EQ $99,R0
 MOVW R0,0(R4)

 MOVW $0x30000000,R6
 MOVW R6,CPSR
 MOVW $0x80000001,R1
 WORD $0xe1b02061 // MOVS R2, R1, RRX.
 MOVW R2,4(R4)
 MOVW CPSR,R3
 SRL $28,R3
 MOVW R3,8(R4)

 MOVW $0x40000000,R6
 MOVW R6,CPSR
 MOVW $10,R0
 MOVW $10,R1
 WORD $0x00d02001 // SBCS.EQ R2, R0, R1.
 MOVW R2,12(R4)
 MOVW CPSR,R3
 SRL $28,R3
 MOVW R3,16(R4)
 RET
`
	runARMGoSourceOracle(t, source, `package main
import "fmt"

func oracle(value, amount, lhs, status uint32, out *[5]uint32)

func main() {
	var actual [5]uint32
	oracle(0, 0, 0, 0, &actual)
	expected := [5]uint32{99, 0xc0000000, 11, 0xffffffff, 8}
	if actual != expected {
		panic(fmt.Sprintf("raw Operand2 result/flags = %x, want %x", actual, expected))
	}
}
`)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	const triple = "armv7-unknown-linux-gnueabihf"
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: armShifterOracleSignature()})
	if err != nil {
		t.Fatal(err)
	}
	const driver = `#include <stdint.h>
#include <stdio.h>

extern void oracle(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t *);

int main(void) {
    uint32_t actual[5] = {0};
    const uint32_t expected[5] = {99, 0xc0000000u, 11, 0xffffffffu, 8};
    oracle(0, 0, 0, 0, actual);
    for (unsigned i = 0; i < 5; i++) {
        if (actual[i] != expected[i]) {
            fprintf(stderr, "raw Operand2 result/flags [%u] = %x, want %x\n",
                    i, actual[i], expected[i]);
            return 1;
        }
    }
    return 0;
}
`
	for _, level := range []int{0, 2} {
		t.Run(fmt.Sprintf("O%d", level), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"},
				"raw_operand2_continuation", triple, ir, driver, []string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, level)
		})
	}
}
