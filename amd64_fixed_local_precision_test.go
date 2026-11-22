package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestGoAMD64FixedLocalPrecisionOriginalObjects(t *testing.T) {
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86PrecisionHalfScalarConversionRows(legacy, avx)
	if err != nil {
		t.Fatal(err)
	}
	type testCase struct{ operation, setup string }
	operations := []testCase{
		{"CVTSS2SD 124(SP),X2", ""},
		{"CVTSD2SS 120(SP),X2", ""},
		{"CVTPS2PD 113(SP),X2", ""},
		// Use the same aligned pointer for both initialization and conversion.
		{"CVTPD2PS (CX),X2", "LEAQ 192(SP),CX\nANDQ $-16,CX\nMOVQ AX,(CX)\nMOVQ AX,8(CX)\n"},
		// Preserve the complete original operands from the official corpus.
		{"VCVTPH2PS (SP), K2, Y12", ""},
		{"VCVTPH2PS 17(SP)(BP*8), K1, Z1", ""},
		{"VCVTPS2PD 17(SP), K1, Y9", ""},
		{"VCVTPS2PD -17(BP)(SI*4), K1, Y9", "LEAQ 48(SP),BP\nMOVQ $1,SI\n"},
		{"VCVTPS2PH $126, X7, K5, 17(SP)(BP*1)", ""},
		{"VCVTSS2SD -17(BP)(SI*1), X22, K2, X6", "LEAQ 48(SP),BP\nMOVQ $1,SI\n"},
	}
	seen, names := make(map[string]bool), make(map[string]bool)
	matrixRows := 0
	for _, row := range rows {
		switch row.Opcode {
		case "VCVTPD2PS", "VCVTPD2PSX", "VCVTPD2PSY", "VCVTPS2PD",
			"VCVTPH2PS", "VCVTPS2PH", "VCVTSD2SS", "VCVTSS2SD":
		default:
			continue
		}
		names[row.Opcode] = true
		matrixRows++
		for _, witness := range row.Witnesses {
			if !witness.Memory || row.Opcode == "VCVTPS2PH" && witness.Zeroing {
				continue // EVEX.z memory stores have a separate original #UD test.
			}
			operation := strings.Replace(witness.Instruction, "(AX)", "17(SP)(BP*2)", 1)
			if operation == witness.Instruction {
				t.Fatalf("%s has no replaceable memory operand: %s", row.ID, operation)
			}
			if !seen[operation] {
				seen[operation] = true
				operations = append(operations, testCase{operation: operation})
			}
		}
	}
	t.Logf("%d AVX opcodes, %d table rows, %d distinct memory witnesses", len(names), matrixRows, len(seen))
	if len(names) != 8 || matrixRows != 40 || len(seen) != 59 {
		t.Fatal("incomplete official precision-memory matrix")
	}
	var assembly, declarations strings.Builder
	for index, row := range operations {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalVectorStackAssembly(t, name, row.operation, row.setup, ""))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(operations))
}

func TestGoAMD64FixedLocalPrecisionSelectedVectorBytes(t *testing.T) {
	for _, row := range []struct {
		instruction string
		x1, x2, x3  uint64
		out         uint64
	}{
		{"CVTSS2SD X1,X3", 0xf, 0, 0xff00, 0xffff},
		{"CVTSD2SS X1,X3", 0xff, 0, 0xfff0, 0xffff},
		{"VCVTSS2SD X1,X2,K1,X3", 0xf, 0xff00, 0xff, ^uint64(0)},
		{"VCVTSD2SS.Z X1,X2,K1,X3", 0xff, 0xfff0, 0, ^uint64(0)},
		{"VCVTPD2PSX X1,K1,X3", 0xffff, 0, 0xff, ^uint64(0)},
		{"VCVTPH2PS X1,K1,X3", 0xff, 0, 0xffff, ^uint64(0)},
		{"VCVTPS2PH $1,X1,K1,X3", 0xffff, 0, 0xff, ^uint64(0)},
	} {
		t.Run(row.instruction, func(t *testing.T) {
			instruction := x86ScalarLaneInstruction(t, row.instruction)
			inputs := []uint64{row.x1, row.x2, row.x3}
			registers := []Reg{"Z1", "Z2", "Z3"}
			for index, required := range inputs {
				for missing := -1; missing < 16; missing++ {
					state := &x86FixedLocalState{
						vectors: map[Reg]uint64{"Z1": row.x1, "Z2": row.x2, "Z3": row.x3},
						masks:   map[Reg]bool{"K1": true},
						flags:   x86ByteFlagsAll,
					}
					valid := true
					if missing >= 0 {
						bit := uint64(1) << uint(missing)
						state.vectors[registers[index]] &^= bit
						valid = required&bit == 0
					}
					err := fixedLocalVectorStep(&instruction, state, nil, 0)
					if valid && (err != nil || state.vectors["Z3"] != row.out || state.flags != x86ByteFlagsAll) ||
						!valid && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("register %s byte %d, valid=%t: output=%x flags=%x error=%v",
							registers[index], missing, valid, state.vectors["Z3"], state.flags, err)
					}
				}
			}
		})
	}
}

func TestGoAMD64FixedLocalPrecisionMemoryDependencies(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		instruction string
		omit        Reg
		valid       bool
	}{
		{"VCVTSS2SD.Z 124(SP),X4,K1,X5", "Z5", true},
		{"VCVTSS2SD 124(SP),X4,K1,X5", "Z5", false},
		{"VCVTSS2SD.Z 124(SP),X4,K1,X5", "Z4", false},
		{"VCVTSD2SS.Z 124(SP),X4,K1,X5", "", false},
		{"VCVTPS2PD.BCST.Z 124(SP),K1,Z5", "Z5", true},
		{"VCVTPS2PD.Z 124(SP),K1,Z5", "", false},
		{"VCVTPD2PSX.BCST 120(SP),X5", "", true},
		{"CVTPD2PS 1(SP),X5", "", false},
		{"VCVTPH2PS 120(SP),X5", "", true},
		{"VCVTPH2PS 120(SP),Y5", "", false},
		{"VCVTPS2PH $1,X5,128(SP)", "", true},
		{"VCVTPS2PH $1,X5,K1,128(SP)", "", false},
		{"VCVTPS2PH $1,X5,K1,120(SP)", "", true},
		{"VCVTPS2PH $1,X5,K1,252(SP)", "", false},
		{"VCVTPS2PH.Z $1,X5,K1,120(SP)", "", false},
	} {
		t.Run(row.instruction+"/"+string(row.omit), func(t *testing.T) {
			source := fixedLocalVectorStackAssembly(t, "Value", row.instruction, "", row.omit)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.valid && err != nil || !row.valid && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("valid=%t: %v", row.valid, err)
			}
		})
	}
}
