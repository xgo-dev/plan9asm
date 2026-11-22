package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalCRC32OriginalObjects(t *testing.T) {
	rows := []string{
		"CRC32W (BX), DX", "CRC32W DX, DX",
		"CRC32L (BX), DX", "CRC32L DX, DX",
		"CRC32B (BX), DX", "CRC32B DL, DX", "CRC32B R11, DX",
		"CRC32Q (BX), DX", "CRC32Q DX, DX",
	}
	var assembly, declarations strings.Builder
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$128-16\nMOVQ a+0(FP),AX\n", name)
		assembly.WriteString("MOVQ AX,64(SP)\nNOTQ AX\nMOVQ AX,DX\nROLQ $13,AX\nMOVQ AX,R11\nLEAQ 64(SP),BX\n")
		fmt.Fprintf(&assembly, "%s\nMOVQ DX,ret+8(FP)\nRET\n", row)
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}

func TestGoAMD64FixedLocalMXCSROriginalObjects(t *testing.T) {
	rows := []string{"LDMXCSR", "VLDMXCSR", "STMXCSR", "VSTMXCSR"}
	var assembly, declarations strings.Builder
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$128-16\n", name)
		assembly.WriteString("STMXCSR 32(SP)\nMOVL $0x3f80,64(SP)\n")
		if strings.Contains(row, "LDMXCSR") {
			fmt.Fprintf(&assembly, "LEAQ 64(SP),BX\n%s (BX)\nSTMXCSR 80(SP)\n", row)
		} else {
			fmt.Fprintf(&assembly, "LDMXCSR 64(SP)\nLEAQ 80(SP),BX\n%s (BX)\n", row)
		}
		assembly.WriteString("LDMXCSR 32(SP)\nMOVL 80(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n")
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}

func TestGoAMD64FixedLocalCRC32AndMXCSRExactMemory(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name, body string
		accept     bool
	}{
		{"byte", "MOVB $7,127(SP)\nMOVL AX,DX\nCRC32B 127(SP),DX", true},
		{"word", "MOVW $7,126(SP)\nMOVL AX,DX\nCRC32W 126(SP),DX", true},
		{"dword", "MOVL $7,124(SP)\nMOVL AX,DX\nCRC32L 124(SP),DX", true},
		{"qword", "MOVQ $7,120(SP)\nMOVL AX,DX\nCRC32Q 120(SP),DX", true},
		{"undefined source byte", "MOVB $7,126(SP)\nMOVL AX,DX\nCRC32W 126(SP),DX", false},
		{"undefined accumulator byte", "MOVB $7,127(SP)\nMOVW AX,DX\nCRC32B 127(SP),DX", false},
		{"overrun source", "MOVL $7,124(SP)\nMOVL AX,DX\nCRC32L 125(SP),DX", false},
		{"mxcsr last dword", "STMXCSR 124(SP)\nVLDMXCSR 124(SP)\nMOVL 124(SP),DX", true},
		{"mxcsr unaligned dword", "VSTMXCSR 1(SP)\nLDMXCSR 1(SP)\nMOVL 1(SP),DX", true},
		{"mxcsr overrun", "MOVL AX,DX\nVSTMXCSR 125(SP)", false},
		{"mxcsr undefined read", "MOVL AX,DX\nMOVW $0,124(SP)\nVLDMXCSR 124(SP)", false},
		{"mxcsr unwritten neighbor", "VSTMXCSR 1(SP)\nMOVQ 1(SP),DX", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := "TEXT ·Value(SB),4,$128-16\nMOVQ a+0(FP),AX\n" +
				row.body + "\nMOVQ DX,ret+8(FP)\nRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.accept && err != nil || !row.accept && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("private instruction inputs or memory extent, accept=%t: %v", row.accept, err)
			}
		})
	}
}

func TestX86VEXMXCSRCompleteGoEncodings(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		addresses := []string{"(BX)", "8(SI)(CX*4)", "-129(AX)"}
		mode := 32
		if arch == "amd64" {
			mode = 64
			addresses = append(addresses, "(R11)(R13*2)")
		}
		for _, op := range []Op{"VLDMXCSR", "VSTMXCSR"} {
			var assembly strings.Builder
			for _, address := range addresses {
				fmt.Fprintf(&assembly, "%s %s\n", op, address)
			}
			assembly.WriteString("RET")
			code, pcs := x86NumericalBoundaryGoBytes(t, arch, assembly.String())
			if len(pcs) != len(addresses)+1 {
				t.Fatal("Go changed the complete MXCSR source inventory", len(pcs))
			}
			for index, address := range addresses {
				body := code[pcs[index]:pcs[index+1]]
				instruction, length, known, err := decodedX86VEXMXCSRInstructionWithMemory(body, mode, x86RawMemoryDecoder{})
				if err != nil || !known || length != len(body) || instruction.Op != op ||
					len(instruction.Args) != 1 || instruction.Args[0].Kind != OpMem {
					t.Fatalf("%s %s %s: failed decoding actual Go bytes %x: %v", arch, op, address, body, err)
				}
				if observed, err := x86NumericalVectorBoundary(body, mode); err != nil || observed != length {
					t.Fatalf("%s %s %s: native instruction boundary differs: %v", arch, op, address, err)
				}
			}
		}
	}
	for _, code := range [][]byte{
		{0xc5, 0xf8, 0xae},       // Missing ModRM.
		{0xc5, 0xf8, 0xae, 0xd0}, // Register operand.
		{0xc5, 0xfc, 0xae, 0x13}, // Reserved vector length.
		{0xc5, 0xf0, 0xae, 0x13}, // Reserved vvvv operand.
	} {
		if _, _, known, err := decodedX86VEXMXCSRInstructionWithMemory(code, 64, x86RawMemoryDecoder{}); !known || err == nil {
			t.Fatalf("accepted a malformed MXCSR encoding %x: %v", code, err)
		}
	}
}
