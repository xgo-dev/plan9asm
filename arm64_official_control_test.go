package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARM64OfficialControl(t *testing.T) {
	var source strings.Builder
	var instructions []string
	for _, instruction := range arm64OfficialSourceRows(t) {
		fields := strings.Fields(instruction)
		switch fields[0] {
		case "ADR", "ADRP", "BEQ", "BL", "BLT", "CALL", "CBNZ", "CBNZW", "CBZ", "CBZW", "JMP", "TBNZ", "TBZ":
		default:
			continue
		}
		if strings.HasSuffix(instruction, "(SB)") {
			continue
		}
		body, known := arm64OfficialControlBody(strings.Join(fields, " "))
		if !known {
			t.Fatalf("missing execution fixture for Go instruction %q", instruction)
		}
		name := arm64OfficialRuntimeSymbol(len(instructions))
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVD data+0(FP),R8\nMOVD 0(R8),R0\nMOVD 8(R8),R1\n", name)
		source.WriteString(strings.ReplaceAll(body, "INSTRUCTION", instruction))
		source.WriteString("\nMOVD R0,ret+8(FP)\nRET\n")
		instructions = append(instructions, instruction)
	}
	// The older SDK corpus lacks the eight numeric ADR/ADRP rows.
	if found := len(instructions); found != 17 && found != 25 {
		t.Fatalf("found %d context-bound control operations, want 17 or 25 for the selected Go corpus", found)
	}
	for _, fixture := range []struct{ flags, prefix string }{
		{"516", ""},
		{"4", "PCALIGN $64\n"},
	} {
		source.WriteString(arm64RawAlignedBranchSource(
			arm64OfficialRuntimeSymbol(len(instructions)), fixture.flags, fixture.prefix, "PCALIGN $32", 20,
		))
		instructions = append(instructions, "WORD $0xb40000a0 across PCALIGN $32")
	}
	fmt.Fprintf(&source, `TEXT %s(SB),516,$0-16
MOVD data+0(FP),R8
MOVD 0(R8),R0
WORD $0xd2800042 // MOVZ #2,X2
again:
WORD $0x91000400 // ADD X0,X0,#1
WORD $0xd1000442 // SUB X2,X2,#1
PCALIGN $32
WORD $0xb5ffff62 // CBNZ X2,-20
MOVD R0,ret+8(FP)
RET
`, arm64OfficialRuntimeSymbol(len(instructions)))
	instructions = append(instructions, "WORD $0xb5ffff62 across PCALIGN $32")
	edges := []uint64{
		0, 1, 2, 3, 4, 5, 6, 7, 0x7fffffff, 0x80000000, 0xffffffff,
		0x7fffffffffffffff, 0x8000000000000000, ^uint64(0), 0x100000000, 0xffffffff00000000,
	}
	inputs := make([][4]uint64, 0, len(edges)*len(edges))
	for _, high := range edges {
		for _, low := range edges {
			inputs = append(inputs, [4]uint64{low, high})
		}
	}
	runARM64OfficialResultRuntime(t, "official_arm64_control", source.String(), instructions, inputs)
}

func arm64OfficialControlBody(instruction string) (string, bool) {
	switch instruction {
	case "BEQ 1(PC)":
		return "CMP R0,R1\nINSTRUCTION\nCSET EQ,R0", true
	case "BEQ 2(PC)":
		return "CMP R0,R1\nINSTRUCTION\nADD $7,R0\nADD $2,R0", true
	case "BL 1(PC)":
		return "MOVD R30,R19\nINSTRUCTION\nADD $31,R0\nMOVD R19,R30", true
	case "BLT -1(PC)":
		return `AND $1,R0,R4
SUB $2,R4
ADDS $1,R4
INSTRUCTION
MOVD R4,R0`, true
	case "CBNZ R7, -1(PC)":
		return `AND $7,R0,R7
ADD $1,R7
SUB $1,R7
INSTRUCTION
MOVD R7,R0`, true
	case "CBNZW R2, -1(PC)":
		return `AND $7,R0,R2
ADD $1,R2
MOVD $0xa700000000,R5
ORR R5,R2
SUB $1,R2
INSTRUCTION
MOVD R2,R0`, true
	case "CBZ R1, again":
		return "INSTRUCTION\nADD $3,R0\nagain:\nADD $2,R0", true
	case "CBZ R1, -1(PC)":
		return "AND $1,R1\nSUB $1,R1\nADD $1,R1\nINSTRUCTION\nMOVD R1,R0", true
	case "CBZW R15, -1(PC)":
		return `AND $1,R1,R15
MOVD $0xa7ffffffff,R5
ADD R5,R15
ADD $1,R15
INSTRUCTION
MOVD R15,R0`, true
	case "TBNZ $2, R2, 2(PC)":
		return "MOVD R0,R2\nINSTRUCTION\nADD $32,R0\nADD $1,R0", true
	case "TBZ $1, R1, 2(PC)":
		return "INSTRUCTION\nADD $32,R0\nADD $1,R0", true
	case "ADR next, R11":
		return "INSTRUCTION\nJMP (R11)\nADD $16,R0\nnext:\nADD $2,R0", true
	case "BL (R2)", "CALL (R15)":
		_, operand, _ := strings.Cut(instruction, " ")
		return fmt.Sprintf(`MOVD R30,R19
ADR callee,%s
INSTRUCTION
ADD $2,R0
MOVD R19,R30
B done
callee:
EOR $9,R0
B (R30)
done:`, strings.Trim(operand, "()")), true
	case "CALL -1(PC)":
		return `MOVD R30,R19
B invoke
trampoline:
B callee
invoke:
INSTRUCTION
ADD $2,R0
MOVD R19,R30
B done
callee:
EOR $9,R0
B (R30)
done:`, true
	case "JMP (R29)":
		return `MOVD R29,R19
ADR target,R29
INSTRUCTION
ADD $16,R0
target:
MOVD R19,R29
ADD $2,R0`, true
	case "JMP -1(PC)":
		return "B entry\ntarget:\nB done\nentry:\nINSTRUCTION\nADD $16,R0\ndone:\nADD $2,R0", true
	}
	fields := strings.Fields(instruction)
	if len(fields) != 3 || !strings.HasSuffix(fields[1], "(PC),") {
		return "", false
	}
	switch fields[0] {
	case "ADR":
		return fmt.Sprintf("ADR self,R9\nADD $2,R0\nself:\nINSTRUCTION\nCMP R9,%s\nCSET EQ,R0", fields[2]), true
	case "ADRP":
		return fmt.Sprintf("ADD $2,R0\nself:\nINSTRUCTION\nADR self,R9\nAND $-4096,R9\nCMP R9,%s\nCSET EQ,R0", fields[2]), true
	}
	return "", false
}
