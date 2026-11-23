package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64OfficialConditionalSource(t *testing.T) (string, []string) {
	t.Helper()
	var source strings.Builder
	var instructions []string
	for _, instruction := range arm64OfficialSourceRows(t) {
		op, operands, _ := strings.Cut(strings.ReplaceAll(instruction, "\t", " "), " ")
		switch op {
		case "CCMN", "CCMNW", "CCMP", "CCMPW", "CINC", "CINCW", "CINV", "CINVW",
			"CNEG", "CNEGW", "CSEL", "CSELW", "CSET", "CSETW", "CSETM", "CSETMW",
			"CSINC", "CSINCW", "CSINV", "CSINVW", "CSNEG", "CSNEGW",
			"FCCMPS", "FCCMPD", "FCCMPES", "FCCMPED", "FCSELS", "FCSELD":
		default:
			continue
		}
		args := strings.Split(operands, ",")
		for index := range args {
			args[index] = strings.TrimSpace(args[index])
		}
		if args[0] == "AL" || args[0] == "NV" {
			continue
		}
		name := arm64OfficialRuntimeSymbol(len(instructions))
		writeARM64OfficialConditionalBody(&source, name, op, instruction, args[1:])
		instructions = append(instructions, instruction)
	}
	if len(instructions) != 56 {
		t.Fatalf("found %d original conditional operations requiring NZCV, want 56", len(instructions))
	}
	return source.String(), instructions
}

func writeARM64OfficialConditionalBody(source *strings.Builder, name, op, instruction string, args []string) {
	var registers []string
	used := make(map[string]bool)
	for _, operand := range args {
		if (strings.HasPrefix(operand, "R") || strings.HasPrefix(operand, "F")) && !used[operand] {
			registers = append(registers, operand)
			used[operand] = true
		}
	}
	var scratch []string
	for index := 9; len(scratch) < 4; index++ {
		register := fmt.Sprintf("R%d", index)
		if index != 18 && !used[register] {
			scratch = append(scratch, register)
		}
	}
	base, value := scratch[0], scratch[1]
	saved := []struct {
		register string
		scratch  string
	}{{"R29", scratch[2]}, {"R30", scratch[3]}}

	fmt.Fprintf(source, "TEXT %s(SB),516,$0-16\nMOVD data+0(FP),%s\n", name, base)
	for _, save := range saved {
		if used[save.register] {
			fmt.Fprintf(source, "MOVD %s,%s\n", save.register, save.scratch)
		}
	}
	floatMove := "FMOVD"
	if strings.HasSuffix(op, "S") {
		floatMove = "FMOVS"
	}
	for index, register := range registers {
		move := "MOVD"
		if strings.HasPrefix(register, "F") {
			move = floatMove
		}
		fmt.Fprintf(source, "%s %d(%s),%s\n", move, 8*index, base, register)
	}
	fmt.Fprintf(source, "MOVD 24(%s),%s\nMSR %s,NZCV\n%s\n", base, value, value, instruction)
	result := args[len(args)-1]
	switch {
	case strings.HasPrefix(op, "CC"), strings.HasPrefix(op, "FCC"):
		fmt.Fprintf(source, "MRS NZCV,%s\n", value)
	case strings.HasPrefix(result, "F"):
		fmt.Fprintf(source, "%s %s,%s\n", floatMove, result, value)
	default:
		fmt.Fprintf(source, "MOVD %s,%s\n", result, value)
	}
	for _, save := range saved {
		if used[save.register] {
			fmt.Fprintf(source, "MOVD %s,%s\n", save.scratch, save.register)
		}
	}
	fmt.Fprintf(source, "MOVD %s,ret+8(FP)\nRET\n", value)
}

func TestCrossLinuxRuntimeMatrixARM64OfficialConditions(t *testing.T) {
	source, instructions := arm64OfficialConditionalSource(t)
	var inputs [][4]uint64
	for _, tuple := range [][3]uint64{
		{0x3ff000003f800000, 0xc0000000c0000000, 0x4010000040800000},
		{0x8000000000000000, 0x7f8000007f800000, 0xfff80000ffc00000},
		{^uint64(0), 0, 0x8000000000000001},
	} {
		for flags := uint64(0); flags < 16; flags++ {
			inputs = append(inputs, [4]uint64{tuple[0], tuple[1], tuple[2], flags << 28})
		}
	}
	runARM64OfficialResultRuntime(t, "official_arm64_conditions", source, instructions, inputs)
}
