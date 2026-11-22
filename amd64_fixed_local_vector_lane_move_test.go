package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestGoAMD64FixedLocalVectorLaneMoveOriginalObjects(t *testing.T) {
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	halves, err := goasmrules.X86MoveRemainderRows(legacy, avx)
	if err != nil {
		t.Fatal(err)
	}
	duplicates, err := goasmrules.X86PackedDuplicateRows(legacy, avx)
	if err != nil {
		t.Fatal(err)
	}
	type testCase struct{ operation, setup string }
	index := "MOVQ $4,AX\n"
	operations := []testCase{
		{"MOVLPS 120(SP),X2", ""}, {"MOVHPS X2,120(SP)", ""},
		{"MOVHPD 120(SP),X2", ""}, {"MOVLPD X2,120(SP)", ""},
		{"MOVHLPS X1,X2", ""}, {"MOVLHPS X1,X2", ""},
		{"VMOVHLPS X17,X1,X3", ""}, {"VMOVLHPS X1,X17,X3", ""},
		{"VMOVHPD (SP)(AX*2), X5, X5", index},
		{"VMOVHPD X20, (SP)(AX*2)", index},
		{"VMOVLPD (SP)(AX*2), X20, X5", index},
		{"VMOVLPD X20, (SP)(AX*2)", index},
		{"VMOVDDUP 17(SP)(BP*1), K3, Z21", ""},
		{"VMOVSLDUP 17(SP), K1, Z13", ""},
		{"VMOVSLDUP -17(BP)(SI*4), K1, Z13", "LEAQ 48(SP),BP\nMOVQ $1,SI\n"},
	}
	var rows []goasmrules.X86PackedBinaryRow
	for _, row := range halves {
		switch row.Opcode {
		case "VMOVLPS", "VMOVHPS", "VMOVLPD", "VMOVHPD":
			rows = append(rows, row)
		}
	}
	if len(rows) != 16 || len(duplicates) != 27 {
		t.Fatalf("incomplete official lane-move rows: half=%d duplicate=%d", len(rows), len(duplicates))
	}
	rows = append(rows, duplicates...)
	seen := make(map[string]bool)
	for _, row := range rows {
		for _, witness := range row.Witnesses {
			if !witness.Memory {
				continue
			}
			memory, setup := "17(SP)(BP*2)", ""
			if row.Opcode == "MOVSLDUP" || row.Opcode == "MOVSHDUP" {
				memory = "(CX)"
				setup = "LEAQ 192(SP),CX\nANDQ $-16,CX\nMOVQ AX,(CX)\nMOVQ AX,8(CX)\n"
			}
			operation := strings.Replace(witness.Instruction, "(AX)", memory, 1)
			if operation == witness.Instruction {
				t.Fatalf("%s lacks an original memory role: %s", row.ID, operation)
			}
			if !seen[operation] {
				seen[operation] = true
				operations = append(operations, testCase{operation: operation, setup: setup})
			}
		}
	}
	t.Logf("%d encoder rows and %d distinct memory witnesses", len(rows), len(seen))
	if len(seen) != 44 {
		t.Fatal("incomplete official lane-move memory matrix", len(seen))
	}
	var assembly, declarations strings.Builder
	for index, row := range operations {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalVectorStackAssembly(t, name, row.operation, row.setup, ""))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(operations))
}

func TestGoAMD64FixedLocalVectorLaneMoveSelectedBytes(t *testing.T) {
	for _, row := range []struct {
		operation string
		inputs    [3]uint64
		result    uint64
	}{
		{"MOVHLPS X1,X3", [3]uint64{0xff00, 0, 0xff00}, 0xffff},
		{"MOVLHPS X1,X3", [3]uint64{0xff, 0, 0xff}, 0xffff},
		{"VMOVHLPS X1,X2,X3", [3]uint64{0xff00, 0xff00}, ^uint64(0)},
		{"VMOVLHPS X1,X2,X3", [3]uint64{0xff, 0xff}, ^uint64(0)},
		{"MOVDDUP X1,X3", [3]uint64{0xff}, 0xffff},
		{"VMOVSLDUP Y1,Y3", [3]uint64{0x0f0f0f0f}, ^uint64(0)},
		{"VMOVSHDUP.Z Z1,K2,Z3", [3]uint64{0xf0f0f0f0f0f0f0f0}, ^uint64(0)},
		{"VMOVDDUP Y1,K2,Y3", [3]uint64{0x00ff00ff, 0, 0xffffffff}, ^uint64(0)},
	} {
		t.Run(row.operation, func(t *testing.T) {
			instruction := x86ScalarLaneInstruction(t, row.operation)
			registers := [...]Reg{"Z1", "Z2", "Z3"}
			for index, required := range row.inputs {
				for missing := -1; missing < 64; missing++ {
					state := x86FixedLocalState{
						vectors: map[Reg]uint64{"Z1": row.inputs[0], "Z2": row.inputs[1], "Z3": row.inputs[2]},
						masks:   map[Reg]bool{"K2": true},
						flags:   x86ByteFlagsAll,
					}
					valid := true
					if missing >= 0 {
						bit := uint64(1) << uint(missing)
						state.vectors[registers[index]] &^= bit
						valid = required&bit == 0
					}
					err := fixedLocalVectorStep(&instruction, &state, nil, 0)
					if valid && (err != nil || state.vectors["Z3"] != row.result || state.flags != x86ByteFlagsAll) ||
						!valid && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("register %s byte %d, valid=%t: result=%x error=%v",
							registers[index], missing, valid, state.vectors["Z3"], err)
					}
				}
			}
		})
	}
}

func TestGoAMD64FixedLocalVectorLaneMoveDependencies(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		operation string
		omit      Reg
		valid     bool
	}{
		{"VMOVHPD 120(SP),X4,X5", "Z5", true},
		{"VMOVLPD 121(SP),X4,X5", "", false},
		{"VMOVLPD 120(SP),X4,X5", "Z4", false},
		{"VMOVHPD X4,128(SP)", "", true},
		{"VMOVHPD X4,128(SP)", "Z4", false},
		{"VMOVLPD X4,249(SP)", "", false},
		{"MOVHPD X4,X5", "", false},
		{"VMOVDDUP 120(SP),X5", "", true},
		{"VMOVDDUP 120(SP),Y5", "", false},
		{"VMOVSHDUP 113(SP),X5", "", false},
		{"MOVSHDUP 1(SP),X5", "", false},
		{"VMOVSLDUP.Z 64(SP),K2,Z5", "Z5", true},
		{"VMOVSLDUP 64(SP),K2,Z5", "Z5", false},
		{"VMOVSLDUP.Z 64(SP),K2,Z5", "K2", false},
	} {
		t.Run(row.operation+"/"+string(row.omit), func(t *testing.T) {
			source := fixedLocalVectorStackAssembly(t, "Value", row.operation, "", row.omit)
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
