package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func fixedLocalVectorStackAssembly(t *testing.T, name, operation, setup string, omit Reg) string {
	t.Helper()
	ins := x86ScalarLaneInstruction(t, operation)
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$256-16\nMOVQ a+0(FP),AX\n", name)
	for offset := 0; offset < 128; offset += 8 {
		fmt.Fprintf(&source, "MOVQ AX,%d(SP)\n", offset)
	}
	source.WriteString("VMOVUPS (SP),Z0\nMOVQ $1,BP\n")
	source.WriteString(setup)
	seeded := map[Reg]bool{"Z0": true, omit: true}
	for index, arg := range ins.Args {
		if arg.Kind != OpReg {
			continue
		}
		if amd64IsKOperand(arg) && !seeded[arg.Reg] {
			if index == len(ins.Args)-1 {
				continue // A mask result must define its own value.
			}
			fmt.Fprintf(&source, "KMOVQ AX,%s\n", arg.Reg)
			seeded[arg.Reg] = true
		} else if amd64VectorByteWidth(arg.Reg) != 0 {
			reg := x86CallerVectorRoot(arg.Reg)
			if !seeded[reg] {
				fmt.Fprintf(&source, "VMOVUPS Z0,%s\n", reg)
				seeded[reg] = true
			}
		}
	}
	destination := ins.Args[len(ins.Args)-1]
	fmt.Fprintln(&source, operation)
	switch {
	case amd64IsKOperand(destination):
		fmt.Fprintf(&source, "KMOVQ %s,AX\n", destination.Reg)
	case destination.Kind == OpReg:
		fmt.Fprintf(&source, "VMOVUPS %s,128(SP)\nMOVQ 128(SP),AX\n", destination.Reg)
	default:
		fmt.Fprintf(&source, "MOVB %s,AL\n", destination.String())
	}
	source.WriteString("MOVQ AX,ret+8(FP)\nRET\n")
	return source.String()
}

func TestGoAMD64FixedLocalLaneFamiliesOriginalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	rows := []struct{ operation, setup string }{
		{"VPROLD $13, 17(SP), K1, Y11", ""},
		{"VPERMILPS $67, 17(SP)(BP*2), K1, Y7", ""},
		{"VSHUFF32X4 $97, (BP), Y19, K1, Y3", "LEAQ 48(SP),BP\n"},
		{"VPBLENDMD -17(BP)(SI*4), X12, K4, X0", "LEAQ 48(SP),BP\nMOVQ $1,SI\n"},
		{"VPUNPCKLBW 17(SP)(BP*2), X11, K7, X1", ""},
	}
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalVectorStackAssembly(t, name, row.operation, row.setup, ""))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}

func TestGoAMD64FixedLocalLaneFamiliesOfficialRows(t *testing.T) {
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
	for _, family := range []func(goasmrules.X86LegacyCatalog, []goasmrules.X86AVXRule) ([]goasmrules.X86PackedBinaryRow, error){
		goasmrules.X86PackedRotateRows,
		goasmrules.X86PermutationShuffleRows,
		goasmrules.X86PackedMaskBlendRows,
		goasmrules.X86PackedUnpackRows,
	} {
		rows, err := family(legacy, avx)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			for _, witness := range row.Witnesses {
				if witness.Generation == "legacy" || !witness.Memory {
					continue
				}
				operation := strings.Replace(witness.Instruction, "(AX)", "17(SP)(BP*2)", 1)
				if operation == witness.Instruction {
					t.Fatalf("row %s lacks its memory spelling: %s", row.ID, operation)
				}
				if seen[operation] {
					continue
				}
				assembly.WriteString(fixedLocalVectorStackAssembly(t, fmt.Sprintf("Value%d", len(operations)), operation, "", ""))
				operations = append(operations, operation)
				seen[operation] = true
			}
		}
	}
	if len(operations) != 650 {
		t.Fatal("original Go lane-family memory inventory changed", len(operations))
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", strings.Join(operations, "\n")+"\nRET")
	if len(pcs) != len(operations)+1 {
		t.Fatal("original Go lane-family memory instruction count changed", len(pcs), len(operations))
	}
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for index, operation := range operations {
		encoding := code[pcs[index]:pcs[index+1]]
		size, err := x86NumericalVectorBoundary(encoding, 64)
		if err != nil || size != len(encoding) {
			t.Errorf("%s: original encoding %x failed to bind: length=%d err=%v", operation, encoding, size, err)
		}
		if _, err := proveX86FixedLocal(file.Funcs[index], sig); err != nil {
			t.Errorf("%s: initialized frame did not bind: %v", operation, err)
		}
	}
	t.Logf("checked %d distinct original Go lane-family memory witnesses", len(operations))
}

func TestGoAMD64FixedLocalLaneFamiliesInputs(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		operation string
		omit      Reg
		valid     bool
	}{
		{"VPROLD $13,17(SP),K1,Y11", "K1", false},
		{"VPROLD $13,17(SP),K1,Y11", "Z11", false},
		{"VPROLD.Z $13,17(SP),K1,Y11", "Z11", true},
		{"VPROLQ.BCST.Z $7,120(SP),K1,Z11", "", true},
		{"VPROLQ.Z $7,120(SP),K1,Z11", "", false},
		{"VPBLENDMD 17(SP),X12,K4,X18", "Z18", true},
		{"VPBLENDMD 17(SP),X12,K4,X18", "Z12", false},
		{"VPBLENDMD.Z 17(SP),X12,K4,X18", "Z12", true},
		{"VPUNPCKLBW.Z 112(SP),X11,K7,X1", "", true},
		{"VPUNPCKLBW.Z 113(SP),X11,K7,X1", "", false},
	} {
		t.Run(row.operation+"/"+string(row.omit), func(t *testing.T) {
			file, err := Parse(ArchAMD64, fixedLocalVectorStackAssembly(t, "Value", row.operation, "", row.omit))
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

func TestGoAMD64FixedLocalLaneFamiliesRIPBoundaryOnly(t *testing.T) {
	var source strings.Builder
	rows := []struct {
		operation string
		decode    func([]byte, int) (Instr, int, bool, error)
	}{
		{"VPROLD $13,table<>(SB),K1,Y11", decodedX86PackedImmediateRotateInstruction},
		{"VPERMILPS $67,table<>(SB),K1,Y7", decodedX86InLaneFloatingPermuteInstruction},
		{"VSHUFF32X4 $97,table<>(SB),Y19,K1,Y3", decodedX86Shuffle128BitBlocksInstruction},
		{"VPBLENDMD table<>(SB),X12,K4,X0", decodedX86RawMaskBlendInstruction},
		{"VPUNPCKLBW table<>(SB),X11,K7,X1", decodedX86EVEXPackedUnpackInstruction},
	}
	for _, row := range rows {
		fmt.Fprintln(&source, row.operation)
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", source.String()+"RET")
	if len(pcs) != len(rows)+1 {
		t.Fatal("missing original RIP-relative lane-family boundaries", pcs)
	}
	for index, row := range rows {
		encoding := code[pcs[index]:pcs[index+1]]
		size, err := x86NumericalVectorBoundary(encoding, 64)
		if err != nil || size != len(encoding) {
			t.Errorf("%s: original RIP bytes %x failed to bind: %d, %v", row.operation, encoding, size, err)
		}
		if _, _, known, err := row.decode(encoding, 64); !known || err == nil {
			t.Errorf("%s: original RIP bytes acquired a raw source address", row.operation)
		}
	}
}
