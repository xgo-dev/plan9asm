package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestGoAMD64FixedLocalConflictFunnelOriginalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	operations := []string{
		"VPCONFLICTD.Z 17(SP)(BP*2), K7, Y18",
		"VPSHLDVW.Z 17(SP), Y20, K1, Y3",
		"VPSHRDQ.BCST $51, 17(SP), Z24, K3, Z2",
		"VALIGNQ.Z $51, 17(SP), Z19, K2, Z9",
		"VPALIGNR.Z $31, 17(SP)(BP*2), X12, K5, X19",
		"VPOPCNTQ.BCST 17(SP), K4, Z18",
	}
	for index, operation := range operations {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalVectorStackAssembly(t, name, operation, "", ""))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(operations))
}

func TestGoAMD64FixedLocalConflictFunnelOfficialRows(t *testing.T) {
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
		goasmrules.X86LeadingImmediateVectorRows,
		goasmrules.X86PackedEVEXBinaryRemainderRows,
		goasmrules.X86PackedBitCountConflictRows,
		goasmrules.X86TwoSourceImmediateShuffleRows,
	} {
		rows, err := family(legacy, avx)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			switch {
			case strings.HasPrefix(row.Opcode, "VPSHLD"), strings.HasPrefix(row.Opcode, "VPSHRD"),
				strings.HasPrefix(row.Opcode, "VALIGN"), row.Opcode == "VPALIGNR",
				strings.HasPrefix(row.Opcode, "VPCONFLICT"), strings.HasPrefix(row.Opcode, "VPOPCNT"),
				strings.HasPrefix(row.Opcode, "VPLZCNT"):
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
	if len(opcodes) != 23 || len(operations) != 562 {
		t.Fatal("unexpected official opcode or instruction witness inventory", len(opcodes), len(operations))
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(operations, "\n")+"\nRET")
	if len(pcs) != len(operations)+1 {
		t.Fatal("missing original Go conflict/funnel boundaries", len(pcs))
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
	t.Logf("checked %d distinct original encodings across %d opcodes", len(operations), len(opcodes))
}

func TestGoAMD64FixedLocalConflictFunnelProofBoundaries(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	const zeroMask = "MOVQ $0,CX\nKMOVQ CX,K1\n"
	for _, row := range []struct {
		name, operation, setup string
		omit                   Reg
		valid                  bool
	}{
		{"variable old is an input even with zeroing", "VPSHLDVW.Z 17(SP),Y4,K1,Y3", "", "Z3", false},
		{"immediate zeroing needs no old result", "VPSHLDW.Z $7,17(SP),Y4,K1,Y3", "", "Z3", true},
		{"immediate merge needs the old result", "VALIGNQ $7,17(SP),Y4,K1,Y3", "", "Z3", false},
		{"zeroing requires an initialized mask", "VPCONFLICTD.Z 17(SP),K1,Y3", "", "K1", false},
		{"broadcast reads only its scalar", "VPCONFLICTD.BCST.Z 124(SP),K1,Y3", "", "Z3", true},
		{"broadcast still needs its final byte", "VPCONFLICTD.BCST.Z 125(SP),K1,Y3", "", "Z3", false},
		{"conflict zero mask still reads full tuple", "VPCONFLICTD.Z 112(SP),K1,Y3", zeroMask, "K1", false},
		{"align zero mask still reads full tuple", "VALIGNQ.Z $0,112(SP),Y4,K1,Y3", zeroMask, "K1", false},
		{"large byte align retains its memory read", "VPALIGNR $32,112(SP),Y4,Y3", "", "Z3", false},
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

func TestGoAMD64FixedLocalConflictFunnelRIPBoundaryOnly(t *testing.T) {
	var source strings.Builder
	rows := []struct {
		operation string
		decode    func([]byte, int) (Instr, int, bool, error)
	}{
		{"VPSHRDQ $7,table<>(SB),Z17,K1,Z18", decodedX86FunnelShiftInstruction},
		{"VALIGND $7,table<>(SB),X17,K1,X18", decodedX86VectorAlignInstruction},
		{"VPOPCNTD table<>(SB),K1,Y18", decodedX86RawVectorBitCountInstruction},
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
