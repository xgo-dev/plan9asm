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
	for _, reg := range []int{1, 2, 9, 14, 16, 17, 18, 19} {
		fmt.Fprintf(&source, "VMOVUPS Z0,Z%d\n", reg)
	}
	source.WriteString("KMOVQ AX,K1\nKMOVQ AX,K2\nKMOVQ AX,K7\nMOVQ $1,BP\n")
	fmt.Fprintf(&source, "%s\nVMOVUPS %s,64(SP)\nMOVQ 64(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n", operation, destination)
	return source.String()
}

func TestGoAMD64FixedLocalEVEXReadOriginalObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	var assembly, declarations strings.Builder
	rows := []struct {
		operation   string
		destination Reg
	}{
		{"VPADDQ 17(SP),Y0,K1,Y9", "Y9"},
		{"VPMINUD 17(SP)(BP*8),Y17,K2,Y14", "Y14"},
		{"VPSRAW 17(SP)(BP*1),X19,K7,X1", "X1"},
	}
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalEVEXReadAssembly(name, row.operation, row.destination))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	for _, target := range []struct{ goos, triple string }{
		{"linux", "x86_64-unknown-linux-gnu"},
		{"darwin", "x86_64-apple-darwin"},
		{"windows", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.goos, func(t *testing.T) {
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly.String(), declarations.String(),
				target.goos+"/amd64", target.triple)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal(err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir,
						[]string{pkg.Path + ".Value0", pkg.Path + ".Value1", pkg.Path + ".Value2"})
					compileLLVMToObject(t, llc, target.triple, "evex-frame.ll", "evex-frame.o", ir)
					compileLLVMToObject(t, llc, target.triple, "evex-frame-opt.ll", "evex-frame-opt.o", x86MulDivRoundOptimize(t, ir))
				})
		})
	}
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
