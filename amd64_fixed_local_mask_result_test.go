package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestGoAMD64FixedLocalMaskResultOriginalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	for index, operation := range []string{
		"VPCMPEQD.BCST 17(SP)(BP*2),Z24,K1,K7",
		"VPCMPGTB 17(SP),Y21,K2",
		"VPCMPUB $1,17(SP),Z19,K2,K2",
		"VPCMPQ.BCST $6,17(SP),Y23,K1,K4",
		"VPTESTNMB 17(SP)(BP*2),Z28,K5,K5",
		"VPTESTMQ.BCST 17(SP),X30,K1,K0",
	} {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalVectorStackAssembly(t, name, operation, "", ""))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), 6)
}

func TestGoAMD64FixedLocalMaskResultOfficialRows(t *testing.T) {
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
	seen, opcodes := make(map[string]bool), make(map[string]bool)
	for _, family := range []func(goasmrules.X86LegacyCatalog, []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error){
		goasmrules.X86PackedIntegerCompareRows,
		goasmrules.X86ImmediateIntegerCompareRows,
		goasmrules.X86IntegerTestMaskRows,
	} {
		rows, err := family(legacy, avx)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			for _, witness := range row.Witnesses {
				if !strings.HasPrefix(witness.Destination, "K") {
					continue
				}
				opcodes[row.Opcode] = true
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
	if len(opcodes) != 24 || len(operations) != 600 {
		t.Fatal("unexpected Go mask-result inventory", len(opcodes), len(operations))
	}
	bytes, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(operations, "\n")+"\nRET")
	if len(pcs) != len(operations)+1 {
		t.Fatal("missing original Go mask-result boundaries", len(pcs))
	}
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for index, operation := range operations {
		encoding := bytes[pcs[index]:pcs[index+1]]
		length, err := x86NumericalVectorBoundary(encoding, 64)
		if err != nil || length != len(encoding) {
			t.Errorf("%s: original bytes %x failed to bind: %d, %v", operation, encoding, length, err)
		}
		if _, err := proveX86FixedLocal(file.Funcs[index], sig); err != nil {
			t.Errorf("%s: initialized frame did not bind: %v", operation, err)
		}
	}
	t.Logf("checked %d original Go witnesses across %d mask-result opcodes", len(operations), len(opcodes))
}

func TestGoAMD64FixedLocalMaskResultProofBoundaries(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name, operation string
		omit            Reg
		valid           bool
	}{
		{"compare defines a distinct K destination", "VPCMPEQD 17(SP),Y4,K1,K3", "K3", true},
		{"aliased compare mask still needs its input", "VPCMPUD $1,17(SP),Y4,K1,K1", "K1", false},
		{"aliased bit test stores a fully defined result", "VPTESTMB 17(SP),Y4,K1,K1", "", true},
		{"aliased bit test still needs its mask", "VPTESTNMB 17(SP),Y4,K1,K1", "K1", false},
		{"integer self comparison is independent of input bytes", "VPCMPQ $0,Y4,Y4,K3", "Z4", true},
		{"self bit test needs actual input bytes", "VPTESTMQ Y4,Y4,K3", "Z4", false},
		{"broadcast reads just eight initialized bytes", "VPTESTNMQ.BCST 120(SP),Y4,K1,K3", "K3", true},
		{"broadcast requires its final byte", "VPTESTNMQ.BCST 121(SP),Y4,K1,K3", "K3", false},
		{"the vector tuple requires every possible active byte", "VPCMPEQQ 112(SP),Y4,K1,K3", "K3", false},
	} {
		t.Run(row.name, func(t *testing.T) {
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

func TestGoAMD64FixedLocalMaskResultRIPBoundaryOnly(t *testing.T) {
	var source strings.Builder
	rows := []struct {
		operation string
		decode    func([]byte, int) (Instr, int, bool, error)
	}{
		{"VPCMPEQD.BCST table<>(SB),X17,K1,K7", decodedX86PackedIntegerCompareInstruction},
		{"VPCMPQ.BCST $6,table<>(SB),Y23,K7,K3", decodedX86RawMaskCompareInstruction},
		{"VPTESTNMQ.BCST table<>(SB),Z28,K3,K3", decodedX86RawPackedTestMaskInstruction},
	}
	for _, row := range rows {
		fmt.Fprintln(&source, row.operation)
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", source.String()+"RET")
	if len(pcs) != len(rows)+1 {
		t.Fatal("missing original RIP-relative mask-result boundaries", pcs)
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
