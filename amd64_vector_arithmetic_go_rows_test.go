package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86VectorArithmeticCompleteGoEncoderRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`(?s)\{as: A(VPADD\w+|VPSUB\w+),.*?\n\t\}\},`).FindAllStringSubmatch(string(data), -1)
	if len(rows) != len(x86ResultVectorArithmeticNames) {
		t.Fatal("complete Go add/subtract inventory changed", len(rows))
	}
	encodings := map[string]byte{
		"VPADDB": 0xfc, "VPADDW": 0xfd, "VPADDD": 0xfe, "VPADDQ": 0xd4,
		"VPADDSB": 0xec, "VPADDSW": 0xed, "VPADDUSB": 0xdc, "VPADDUSW": 0xdd,
		"VPSUBB": 0xf8, "VPSUBW": 0xf9, "VPSUBD": 0xfa, "VPSUBQ": 0xfb,
		"VPSUBSB": 0xe8, "VPSUBSW": 0xe9, "VPSUBUSB": 0xd8, "VPSUBUSW": 0xd9,
	}
	for _, row := range rows {
		opcode, known := encodings[row[1]]
		if !known {
			t.Fatal("unregistered official arithmetic row", row[1])
		}
		delete(encodings, row[1])
		var expected strings.Builder
		fmt.Fprintf(&expected, "{as: A%s, ytab: _yvandnpd, prefix: Pavx, op: opBytes{\n", row[1])
		for _, width := range []int{128, 256} {
			fmt.Fprintf(&expected, "avxEscape | vex%d | vex66 | vex0F | vexW0, 0x%X,\n", width, opcode)
		}
		w, broadcast := 0, ""
		if row[1] == "VPADDD" || row[1] == "VPSUBD" {
			broadcast = " | evexBcstN4"
		}
		if row[1] == "VPADDQ" || row[1] == "VPSUBQ" {
			w, broadcast = 1, " | evexBcstN8"
		}
		for _, width := range []int{128, 256, 512} {
			fmt.Fprintf(&expected, "avxEscape | evex%d | evex66 | evex0F | evexW%d, evexN%d%s | evexZeroingEnabled, 0x%X,\n", width, w, width/8, broadcast, opcode)
		}
		expected.WriteString("}},")
		if strings.Join(strings.Fields(row[0]), "") != strings.Join(strings.Fields(expected.String()), "") {
			t.Fatal("complete encoder prefix/opcode/tuple/zeroing attributes changed", row[0])
		}
	}
	if len(encodings) != 0 {
		t.Fatal("missing official operations", encodings)
	}
	start := strings.Index(string(data), "var _yvandnpd =")
	if start < 0 {
		t.Fatal("missing original selector table")
	}
	table := strings.SplitN(string(data)[start:], "\n}", 2)[0] + "\n}"
	if err := x86AverageValidateGoYtab(table); err != nil {
		t.Fatal(err)
	}
}

func TestX86VectorArithmeticRejectsUnknownFormsAndBanks(t *testing.T) {
	for _, op := range x86ResultVectorArithmeticNames {
		for _, operands := range []string{"$1,X1,X2", "X0,Y1,Y2", "X0,X1,K0,X2", "X0,X1,(AX)", "X0,X1", "(AX),(BX),X1", "unknown,X1,X2"} {
			row := op.name + " " + operands
			goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
			state := x86ResultState{masks: [8]bool{true, true}}
			for index := 0; index < 32; index++ {
				state.writeVector(index, 64, ^uint64(0), false)
			}
			if x86ResultTransfer(x86ScalarLaneInstruction(t, row), &state, nil, 0, "amd64") {
				t.Fatal("unknown Go form acquired numerical effects", row)
			}
		}
		for _, row := range []string{
			op.name + " X8,X0,X1", op.name + " Y0,Y8,Y1", op.name + " Z0,Z1,Z8",
		} {
			// Go admits unbound high X/Y names, but rejects high Z names
			// in mode32. Neither category supplies a physical register.
			goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", !strings.Contains(row, "Z8"))
			state := x86ResultState{}
			for index := 0; index < 32; index++ {
				state.writeVector(index, 64, ^uint64(0), false)
			}
			if x86ResultTransfer(x86ScalarLaneInstruction(t, row), &state, nil, 0, "386") {
				t.Fatal("Go syntax acquired an unproved physical bank", row)
			}
		}
	}
}
