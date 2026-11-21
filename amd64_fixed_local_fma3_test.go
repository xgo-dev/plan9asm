package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestGoAMD64FixedLocalFMA3OriginalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	operations := []string{
		"VFMADD132SS 124(SP),X2,X3",
		"VFMSUB213PD 17(SP)(BP*2),Y2,Y3",
		"VFNMSUB231SD.Z 120(SP),X19,K3,X22",
		"VFMSUBADD213PD.BCST.Z -8(BP),Z19,K2,Z22",
		"VFMADDSUB231PS 17(SP)(BP*2),Z27,K5,Z29",
		"VFNMADD132SS.RD_SAE.Z X19,X21,K1,X23",
	}
	for index, operation := range operations {
		name := fmt.Sprintf("Value%d", index)
		setup := ""
		if strings.Contains(operation, "-8(BP)") {
			setup = "LEAQ 48(SP),BP\n"
		}
		assembly.WriteString(fixedLocalVectorStackAssembly(t, name, operation, setup, ""))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(operations))
}

func TestGoAMD64FixedLocalFMA3OfficialMemoryRows(t *testing.T) {
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86FMA3Rows(legacy, avx)
	if err != nil {
		t.Fatal(err)
	}
	var assembly strings.Builder
	var operations []string
	seen := make(map[string]bool)
	count := 0
	for _, row := range rows {
		count += len(row.Witnesses)
		for _, witness := range row.Witnesses {
			if !witness.Memory {
				continue
			}
			operation := strings.Replace(witness.Instruction, "(AX)", "17(SP)(BP*2)", 1)
			if operation == witness.Instruction {
				t.Fatalf("row %s lacks a memory operand: %s", row.ID, operation)
			}
			if seen[operation] {
				continue
			}
			name := fmt.Sprintf("Value%d", len(operations))
			assembly.WriteString(fixedLocalVectorStackAssembly(t, name, operation, "", ""))
			operations = append(operations, operation)
			seen[operation] = true
		}
	}
	if len(rows) != 360 || count != 2028 || len(operations) != 816 {
		t.Fatal("incomplete FMA3 table inventory", len(rows), count, len(operations))
	}
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != len(operations) {
		t.Fatal("missing parsed FMA3 functions", len(file.Funcs), len(operations))
	}
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for index, fn := range file.Funcs {
		if _, err := proveX86FixedLocal(fn, sig); err != nil {
			t.Fatalf("%s: initialized frame did not bind: %v", operations[index], err)
		}
	}
	t.Logf("checked %d original Go rows and %d initialized stack forms", len(rows), len(operations))
}

func TestGoAMD64FixedLocalFMA3TupleAndInputs(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name, operation string
		omit            Reg
		valid           bool
	}{
		{"m32 reads four bytes", "VFMADD132SS 124(SP),X2,X3", "", true},
		{"m64 requires eight bytes", "VFMADD132SD 124(SP),X2,X3", "", false},
		{"broadcast reads one element", "VFNMADD213PD.BCST 120(SP),Y2,K3,Y4", "", true},
		{"packed reads all lanes", "VFNMADD213PD 120(SP),Y2,K3,Y4", "", false},
		{"zeroing still reads old destination", "VFMSUB231SS.Z 124(SP),X2,K3,X4", "Z4", false},
		{"merging still reads its mask", "VFMSUB231SD 120(SP),X2,K3,X4", "K3", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			assembly := fixedLocalVectorStackAssembly(t, "Value", row.operation, "", row.omit)
			file, err := Parse(ArchAMD64, assembly)
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

func TestGoAMD64FixedLocalFMA3ScalarDestinationDefinedBytes(t *testing.T) {
	for _, row := range []struct {
		operation string
		low       uint64
	}{
		{"VFMADD132SS X2,X3,X4", 0xf},
		{"VFMSUB213SD.RZ_SAE.Z X2,X3,K1,X4", 0xff},
	} {
		t.Run(row.operation, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, row.operation)
			const preservedInX = 1 << 12
			state := x86FixedLocalState{
				vectors: map[Reg]uint64{
					"Z2": row.low,
					"Z3": 0xffff,
					"Z4": row.low | preservedInX | 1<<30,
				},
				masks: map[Reg]bool{"K1": true},
				flags: x86ByteFlagsAll,
			}
			if err := fixedLocalVectorStep(&ins, &state, nil, 0); err != nil {
				t.Fatal(err)
			}
			want := ^uint64(0xffff) | preservedInX | row.low
			if got := state.vectors["Z4"]; got != want || state.flags != x86ByteFlagsAll {
				t.Fatalf("destination bytes=%#x, want %#x; FLAGS=%#x", got, want, state.flags)
			}
		})
	}
}
