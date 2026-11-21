package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestGoAMD64FixedLocalFloatMaskOriginalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	for index, operation := range []string{
		"VCMPSS $31,17(SP)(BP*2),X19,K1,K7",
		"VCMPSD $15,17(SP),X21,K5,K5",
		"VCMPPD.BCST $13,17(SP),Y19,K2,K2",
		"VCMPPS $3,17(SP)(BP*2),Z29,K5,K6",
		"VCMPPS.SAE $19,Z20,Z21,K1,K0",
	} {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalVectorStackAssembly(t, name, operation, "", ""))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), 5)
}

func TestGoAMD64FixedLocalFloatMaskOfficialRows(t *testing.T) {
	legacy, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := goasmrules.X86FloatingCompareRows(legacy, avx)
	if err != nil {
		t.Fatal(err)
	}
	var assembly strings.Builder
	var operations []string
	var maskResults []bool
	seen := make(map[string]bool)
	count := 0
	for _, row := range rows {
		for _, witness := range row.Witnesses {
			operation := strings.Replace(witness.Instruction, "(AX)", "17(SP)(BP*2)", 1)
			if seen[operation] {
				continue
			}
			maskResult := strings.HasPrefix(witness.Destination, "K")
			if maskResult {
				assembly.WriteString(fixedLocalVectorStackAssembly(t, fmt.Sprintf("Value%d", count), operation, "", ""))
				count++
			}
			operations = append(operations, operation)
			maskResults = append(maskResults, maskResult)
			seen[operation] = true
		}
	}
	if len(rows) != 22 || len(operations) != 116 || count != 104 {
		t.Fatal("incomplete VEX and EVEX comparison inventory", len(rows), len(operations), count)
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(operations, "\n")+"\nRET")
	if len(pcs) != len(operations)+1 {
		t.Fatal("missing original Go floating compare boundaries", pcs)
	}
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	fn := 0
	for index, operation := range operations {
		encoding := code[pcs[index]:pcs[index+1]]
		length, err := x86NumericalVectorBoundary(encoding, 64)
		if err != nil || length != len(encoding) {
			t.Errorf("%s: original bytes %x failed to bind: %d, %v", operation, encoding, length, err)
		}
		if maskResults[index] {
			if _, err := proveX86FixedLocal(file.Funcs[fn], sig); err != nil {
				t.Errorf("%s: initialized frame did not bind: %v", operation, err)
			}
			fn++
		}
	}
	t.Logf("checked %d rows, %d VEX/EVEX witnesses and %d K-result frames", len(rows), len(operations), count)
}

func TestGoAMD64FixedLocalFloatMaskProofBoundaries(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name, operation string
		omit            Reg
		valid           bool
	}{
		{"scalar single reads four bytes", "VCMPSS $31,124(SP),X3,K1,K2", "K2", true},
		{"scalar double requires all eight bytes", "VCMPSD $31,121(SP),X3,K1,K2", "K2", false},
		{"packed broadcast reads only the scalar tuple", "VCMPPD.BCST $31,120(SP),Y3,K1,K2", "K2", true},
		{"packed compare needs the entire possible source", "VCMPPD $31,120(SP),Y3,K1,K2", "K2", false},
		{"aliased mask input must already be defined", "VCMPSS $0,17(SP),X3,K1,K1", "K1", false},
		{"floating self compare still reads its input", "VCMPSD $0,X4,X4,K3", "Z4", false},
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

func TestGoAMD64FixedLocalFloatMaskScalarRegisterBytes(t *testing.T) {
	for _, row := range []struct {
		operation string
		bytes     uint64
	}{
		{"VCMPSS $31,X20,X21,K3,K3", 0xf},
		{"VCMPSD.SAE $31,X20,X21,K3,K3", 0xff},
	} {
		for _, available := range []uint64{row.bytes, row.bytes >> 1} {
			ins := x86ScalarLaneInstruction(t, row.operation)
			state := x86FixedLocalState{
				vectors: map[Reg]uint64{"Z20": row.bytes, "Z21": available},
				masks:   map[Reg]bool{"K3": true},
				flags:   x86ByteFlagsAll,
			}
			err := fixedLocalVectorStep(&ins, &state, nil, 0)
			valid := available == row.bytes
			if valid && err != nil || !valid && !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("%s with low defined bytes %#x: %v", row.operation, available, err)
			}
			if state.vectors["Z21"] != available || state.flags != x86ByteFlagsAll {
				t.Errorf("%s changed its source vector or FLAGS: %+v", row.operation, state)
			}
		}
	}
}
