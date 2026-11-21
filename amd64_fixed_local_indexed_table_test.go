package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestGoAMD64FixedLocalIndexedTableOriginalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	operations := []string{
		"VPERMB.Z 17(SP), Y24, K7, Y18",
		"VPERMI2PS.BCST.Z 17(SP)(BP*2), Z19, K1, Z3",
		"VPERMT2D.Z 17(SP), Z24, K3, Z2",
		"VPMULTISHIFTQB.BCST.Z 17(SP), Z19, K2, Z9",
		"VPSHUFBITQMB 17(SP)(BP*2), Z31, K1, K6",
		"VPSHUFBITQMB 17(SP), Y17, K6, K6",
		"VPMADD52HUQ.BCST.Z 17(SP), Z26, K3, Z8",
	}
	for index, operation := range operations {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalVectorStackAssembly(t, name, operation, "", ""))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(operations))
}

func TestGoAMD64FixedLocalIndexedTableOfficialRows(t *testing.T) {
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var assembly strings.Builder
	var operations []string
	seen := make(map[string]bool)
	opcodes := make(map[string]bool)
	for _, family := range []func(goasmrules.X86LegacyCatalog, []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error){
		goasmrules.X86PackedEVEXBinaryRemainderRows,
		goasmrules.X86QwordLookupRows,
	} {
		rows, err := family(legacy, avx)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			switch {
			case row.Opcode == "VPERMB", row.Opcode == "VPERMW",
				strings.HasPrefix(row.Opcode, "VPERMI2"), strings.HasPrefix(row.Opcode, "VPERMT2"),
				strings.HasPrefix(row.Opcode, "VPMADD52"),
				row.Opcode == "VPMULTISHIFTQB", row.Opcode == "VPSHUFBITQMB":
			default:
				continue
			}
			opcodes[row.Opcode] = true
			for _, witness := range row.Witnesses {
				operation := strings.Replace(witness.Instruction, "(AX)", "17(SP)(BP*2)", 1)
				if seen[operation] {
					continue
				}
				assembly.WriteString(fixedLocalVectorStackAssembly(t, fmt.Sprintf("Value%d", len(operations)), operation, "", ""))
				operations = append(operations, operation)
				seen[operation] = true
			}
		}
	}
	if len(opcodes) != 18 || len(operations) != 429 {
		t.Fatal("unexpected official opcode or witness inventory", len(opcodes), len(operations))
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(operations, "\n")+"\nRET")
	if len(pcs) != len(operations)+1 {
		t.Fatal("missing original Go indexed-table boundaries", len(pcs))
	}
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for index, operation := range operations {
		encoding := code[pcs[index]:pcs[index+1]]
		length, err := x86NumericalVectorBoundary(encoding, 64)
		if err != nil || length != len(encoding) {
			t.Errorf("%s: original bytes %x failed to bind: %d, %v", operation, encoding, length, err)
		}
		if _, err := proveX86FixedLocal(file.Funcs[index], sig); err != nil {
			t.Errorf("%s: initialized frame did not bind: %v", operation, err)
		}
	}
	t.Logf("checked %d original Go witnesses across %d opcodes", len(operations), len(opcodes))
}

func TestGoAMD64FixedLocalIndexedTableProofBoundaries(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	const zeroMask = "MOVQ $0,CX\nKMOVQ CX,K1\n"
	for _, row := range []struct {
		name, operation, setup string
		omit                   Reg
		valid                  bool
	}{
		{"single table zeroing needs no old result", "VPERMB.Z 17(SP),Y4,K1,Y3", "", "Z3", true},
		{"single table merging needs the old result", "VPERMW 17(SP),Y4,K1,Y3", "", "Z3", false},
		{"I2 zeroing still needs old indices", "VPERMI2B.Z 17(SP),Y4,K1,Y3", "", "Z3", false},
		{"T2 zeroing still needs the old table", "VPERMT2W.Z 17(SP),Y4,K1,Y3", "", "Z3", false},
		{"IFMA zeroing still needs the accumulator", "VPMADD52HUQ.Z 17(SP),Y4,K1,Y3", "", "Z3", false},
		{"zero mask retains full table read", "VPERMB.Z 112(SP),Y4,K1,Y3", zeroMask, "K1", false},
		{"lookup broadcast reads its qword", "VPMULTISHIFTQB.BCST.Z 120(SP),Y4,K1,Y3", "", "Z3", true},
		{"lookup broadcast needs its final byte", "VPMULTISHIFTQB.BCST.Z 121(SP),Y4,K1,Y3", "", "Z3", false},
		{"a distinct K result needs no prior value", "VPSHUFBITQMB 17(SP),Y4,K1,K3", "", "K3", true},
		{"K input and output can alias", "VPSHUFBITQMB 17(SP),Y4,K3,K3", "", "", true},
		{"an aliased K result still needs its input", "VPSHUFBITQMB 17(SP),Y4,K3,K3", "", "K3", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			assembly := fixedLocalVectorStackAssembly(t, "Value", row.operation, row.setup, row.omit)
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

func TestGoAMD64FixedLocalIndexedTableRIPBoundaryOnly(t *testing.T) {
	var source strings.Builder
	rows := []struct {
		operation string
		decode    func([]byte, int) (Instr, int, bool, error)
	}{
		{"VPERMT2D.BCST table<>(SB),Y18,K1,Y3", decodedX86IndexedPermuteInstruction},
		{"VPMULTISHIFTQB.BCST table<>(SB),Z17,K1,Z18", decodedX86QwordLookupInstruction},
		{"VPSHUFBITQMB table<>(SB),Y17,K1,K6", decodedX86QwordLookupInstruction},
		{"VPMADD52LUQ.BCST table<>(SB),Z18,K2,Z19", decodedX86IFMAInstruction},
	}
	for _, row := range rows {
		fmt.Fprintln(&source, row.operation)
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", source.String()+"RET")
	if len(pcs) != len(rows)+1 {
		t.Fatal("missing original RIP-relative boundaries", pcs)
	}
	for index, row := range rows {
		encoding := code[pcs[index]:pcs[index+1]]
		size, err := x86NumericalVectorBoundary(encoding, 64)
		if err != nil || size != len(encoding) {
			t.Errorf("%s: original RIP bytes %x failed to bind: %d, %v", row.operation, encoding, size, err)
		}
		if _, _, known, err := row.decode(encoding, 64); !known || err == nil {
			t.Errorf("%s: original RIP bytes %x acquired a raw source address", row.operation, encoding)
		}
	}
}
