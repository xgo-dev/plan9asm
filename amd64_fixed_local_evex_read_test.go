package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func fixedLocalEVEXReadAssembly(name, operation string, destination Reg) string {
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$128-16\nMOVQ a+0(FP),AX\n", name)
	for offset := 0; offset < 128; offset += 8 {
		fmt.Fprintf(&source, "MOVQ AX,%d(SP)\n", offset)
	}
	source.WriteString("VMOVUPS (SP),Z0\n")
	for _, reg := range []int{1, 2, 3, 9, 14, 16, 17, 18, 19} {
		fmt.Fprintf(&source, "VMOVUPS Z0,Z%d\n", reg)
	}
	source.WriteString("KMOVQ AX,K1\nKMOVQ AX,K2\nKMOVQ AX,K4\nKMOVQ AX,K7\nMOVQ $1,BP\n")
	fmt.Fprintf(&source, "%s\nVMOVUPS %s,64(SP)\nMOVQ 64(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n", operation, destination)
	return source.String()
}

func TestGoAMD64FixedLocalEVEXReadOriginalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	rows := []struct {
		operation   string
		destination Reg
	}{
		{"VPADDQ 17(SP),Y0,K1,Y9", "Y9"},
		{"VPMINUD 17(SP)(BP*8),Y17,K2,Y14", "Y14"},
		{"VPSRAW 17(SP)(BP*1),X19,K7,X1", "X1"},
		{"VANDNPS 17(SP)(BP*1),X18,K7,X18", "X18"},
		{"VPANDQ 17(SP)(BP*4),Z19,K4,Z3", "Z3"},
	}
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalEVEXReadAssembly(name, row.operation, row.destination))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}

func TestGoAMD64FixedLocalEVEXReadOfficialRows(t *testing.T) {
	root := runtime.GOROOT()
	legacy, err := goasmrules.LoadX86LegacyRules(root)
	if err != nil {
		t.Fatal(err)
	}
	avx, err := goasmrules.LoadX86AVXRules(root)
	if err != nil {
		t.Fatal(err)
	}
	var assembly strings.Builder
	seen := make(map[string]bool)
	var operations []string
	for _, family := range []func(goasmrules.X86LegacyCatalog, []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error){
		goasmrules.X86PackedBinaryPilotRows,
		goasmrules.X86PackedIntegerMinMaxRows,
		goasmrules.X86PackedAverageMultiplyRows,
		goasmrules.X86PackedUniformByteShiftRows,
		goasmrules.X86PackedPerLaneShiftRows,
		goasmrules.X86PackedLogicalRows,
	} {
		rows, err := family(legacy, avx)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			for _, witness := range row.Witnesses {
				if witness.Generation != "evex" || !witness.Memory {
					continue
				}
				operation := strings.Replace(witness.Instruction, "(AX)", "17(SP)(BP*2)", 1)
				if operation == witness.Instruction {
					t.Fatalf("row %s lacks its memory spelling: %s", row.ID, operation)
				}
				if seen[operation] {
					continue
				}
				name := fmt.Sprintf("Value%d", len(seen))
				assembly.WriteString(fixedLocalEVEXReadAssembly(name, operation, Reg(witness.Destination)))
				seen[operation] = true
				operations = append(operations, operation)
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("empty original Go EVEX memory inventory")
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(operations, "\n")+"\nRET")
	if len(pcs) != len(operations)+1 {
		t.Fatal("original Go EVEX memory instruction count changed", len(pcs), len(operations))
	}
	for index, operation := range operations {
		encoding := code[pcs[index]:pcs[index+1]]
		size, err := x86NumericalVectorBoundary(encoding, 64)
		if encoding[0] != 0x62 || err != nil || size != len(encoding) {
			t.Errorf("%s: cannot bind the exact Go EVEX bytes %x: length=%d err=%v", operation, encoding, size, err)
		}
	}
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, fn := range file.Funcs {
		if _, err := proveX86FixedLocal(fn, sig); err != nil {
			t.Errorf("%s: %v", fn.Sym, err)
		}
	}
	t.Logf("checked %d distinct original Go EVEX memory witnesses", len(seen))
}

func TestGoAMD64FixedLocalEVEXReadBoundaries(t *testing.T) {
	const operation = "VPADDQ 17(SP)(BP*2),Y0,K1,Y9"
	base := fixedLocalEVEXReadAssembly("Value", operation, "Y9")
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		old, replacement string
		valid            bool
	}{
		{"KMOVQ AX,K1\n", "", false},
		{"VMOVUPS Z0,Z9\n", "", false},
		{"MOVQ $1,BP", "MOVQ a+0(FP),BP", false},
		{"MOVQ AX,24(SP)\n", "", false},
		{"17(SP)", "110(SP)", false},
		{operation, "VPADDQ.Z 17(SP)(BP*2),Y0,K1,Y9", true},
		{"", "", true},
	} {
		assembly := strings.Replace(base, row.old, row.replacement, 1)
		if row.valid && row.replacement != "" {
			assembly = strings.Replace(assembly, "VMOVUPS Z0,Z9\n", "", 1)
		}
		file, err := Parse(ArchAMD64, assembly)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := proveX86FixedLocal(file.Funcs[0], sig); row.valid && err != nil || !row.valid && !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%q -> %q valid=%t: %v", row.old, row.replacement, row.valid, err)
		}
	}
}

func TestGoAMD64FixedLocalEVEXReadBroadcastTuple(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		operation string
		index     int
		width     int64
	}{
		{"VPMINUD.BCST 84(SP),Y17,K2,Y14", 0, 4},
		{"VPSRAVD.BCST 84(SP),Y17,K2,Y14", 0, 4},
		{"VPSRAD.BCST $3,84(SP),K2,Y14", 1, 4},
		{"VANDPD.BCST 80(SP),Y17,K2,Y14", 0, 8},
		{"VPXORD.BCST 84(SP),Y17,K2,Y14", 0, 4},
	} {
		t.Run(row.operation, func(t *testing.T) {
			assembly := fixedLocalEVEXReadAssembly("Value", row.operation, "Y14")
			assembly = strings.Replace(assembly, "MOVQ AX,88(SP)\n", "", 1)
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			proved, err := proveX86FixedLocal(file.Funcs[0], sig)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, ins := range proved.Instrs {
				if ins.Raw != row.operation {
					continue
				}
				access := ins.x86FixedLocalMemory[row.index]
				found = access.width == row.width && !access.write && !access.nativeInput
			}
			if !found {
				t.Fatal("broadcast lost its exact private scalar tuple")
			}
			file, err = Parse(ArchAMD64, strings.Replace(assembly, ".BCST", "", 1))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := proveX86FixedLocal(file.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("full memory tuple borrowed undefined bytes", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalEVEXLogicalDependencies(t *testing.T) {
	const source = "TEXT ·Value(SB),4,$0-0\n"
	for _, row := range []struct {
		name, operation  string
		first, second    uint64
		old              uint64
		mask, shouldPass bool
	}{
		{name: "zero idiom uses independent mask", operation: "VPXORD.Z Z9,Z9,K2,Z7", mask: true, shouldPass: true},
		{name: "zero idiom requires mask", operation: "VPXORD.Z Z9,Z9,K2,Z7"},
		{name: "merge requires old destination", operation: "VPANDQ Z9,Z18,K2,Z7", first: ^uint64(0), second: ^uint64(0), mask: true},
		{name: "zeroing ignores old destination", operation: "VPANDQ.Z Z9,Z18,K2,Z7", first: ^uint64(0), second: ^uint64(0), mask: true, shouldPass: true},
		{name: "merge retains initialized destination", operation: "VPANDQ Z9,Z18,K2,Z7", first: ^uint64(0), second: ^uint64(0), old: ^uint64(0), mask: true, shouldPass: true},
		{name: "zeroing requires all source bytes", operation: "VPANDQ.Z Z9,Z18,K2,Z7", first: 0xffff, second: ^uint64(0), mask: true},
	} {
		t.Run(row.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, source+row.operation+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			state := x86FixedLocalState{
				vectors: map[Reg]uint64{"Z9": row.first, "Z18": row.second, "Z7": row.old},
				masks:   map[Reg]bool{"K2": row.mask},
				flags:   x86ByteFlagsAll,
			}
			err = fixedLocalVectorStep(&file.Funcs[0].Instrs[1], &state, nil, 0)
			if !row.shouldPass {
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("unproved input acquired a vector effect", err)
				}
				return
			}
			if err != nil || state.vectors["Z7"] != ^uint64(0) || state.flags != x86ByteFlagsAll {
				t.Fatalf("complete logical operation did not define the vector and preserve FLAGS: %v", err)
			}
		})
	}
}
