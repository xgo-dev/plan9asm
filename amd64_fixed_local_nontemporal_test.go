package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalNonTemporalOperation(name, bank string, vector, load bool) string {
	if load {
		return name + " 64(BP)," + bank + "0\nMOVOU X0,128(BP)"
	}
	initialize := "MOVOU 64(BP),X0\n"
	if vector {
		initialize = "VMOVUPS 64(BP)," + bank + "0\n"
	}
	return initialize + name + " " + bank + "0,128(BP)\nSFENCE"
}

func TestGoAMD64FixedLocalNonTemporalCompleteFamilyProof(t *testing.T) {
	var original strings.Builder
	count := 0
	for _, row := range x86NonTemporalNativeOracle {
		banks := []string{"X"}
		if row.vector {
			banks = []string{"X", "Y", "Z"}
		}
		for _, bank := range banks {
			t.Run(row.name+"/"+bank, func(t *testing.T) {
				operation := fixedLocalNonTemporalOperation(row.name, bank, row.vector, row.load)
				pkg, _, file, options := fixedLocalPackedFixture(t, operation)
				original.WriteString(strings.Replace(fixedLocalPackedAssembly(operation), "·Value", fmt.Sprint("·Value", count), 1))
				count++
				if !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") {
					t.Error("native non-temporal access omitted its actual fixed-frame binding")
				}
				sig := options.Sigs[pkg.Path+".Value"]
				if _, err := proveX86FixedLocal(file.Funcs[0], sig); err != nil {
					t.Fatalf("complete initialized non-temporal frame: %v", err)
				}
				memory, misaligned := "128(BP)", "129(BP)"
				if row.load {
					memory, misaligned = "64(BP)", "65(BP)"
				}
				for _, displacement := range []string{misaligned, "320(BP)"} {
					changedOperation := strings.Replace(operation, memory, displacement, 1)
					changed := fixedLocalPackedAssembly(changedOperation)
					parsed, err := Parse(ArchAMD64, changed)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := proveX86FixedLocal(parsed.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("misaligned or out-of-frame bytes acquired native backing", displacement, err)
					}
				}
			})
		}
	}
	if count != 17 {
		t.Fatal("independent fixed-frame non-temporal family is incomplete", count)
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}

func fixedLocalNonTemporalActualObjects(t *testing.T, target, triple string) {
	t.Helper()
	t.Setenv("GOCACHE", t.TempDir())
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	var assembly, declarations strings.Builder
	var names []string
	for _, row := range x86NonTemporalNativeOracle {
		banks := []string{"X"}
		if row.vector {
			banks = []string{"X", "Y", "Z"}
		}
		for _, bank := range banks {
			name := fmt.Sprint("Stream", len(names))
			names = append(names, "example.invalid/framefixture."+name)
			operation := fixedLocalNonTemporalOperation(row.name, bank, row.vector, row.load)
			assembly.WriteString(strings.Replace(fixedLocalPackedAssembly(operation), "·Value", "·"+name, 1))
			fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
		}
	}
	if len(names) != 17 {
		t.Fatal("complete independent fixed-frame non-temporal inventory changed", len(names))
	}
	pkg, request, _, options := x86CMOVFixedLocalFixture(t, assembly.String(), declarations.String(), target, triple)
	fixedLocalConversionPrepareToolCache(t, request)
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
		if err != nil || strings.Count(ir, "%fixed_local_native = alloca") != len(names) {
			t.Fatal("original non-temporal frame inventory lost its actual binding", err)
		}
		for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
			x86CompactExpandRequireAllDefinitions(t, text, names)
			for _, level := range []string{"-O0", "-O2"} {
				x86PackedStringCompileObject(t, llc, triple, text, level)
			}
		}
	})
}

func TestGoAMD64FixedLocalNonTemporalActualObjectsLinux(t *testing.T) {
	fixedLocalNonTemporalActualObjects(t, "linux/amd64", "x86_64-unknown-linux-gnu")
}

func TestGoAMD64FixedLocalNonTemporalActualObjectsDarwin(t *testing.T) {
	fixedLocalNonTemporalActualObjects(t, "darwin/amd64", "x86_64-apple-darwin")
}

func TestGoAMD64FixedLocalNonTemporalActualObjectsWindows(t *testing.T) {
	fixedLocalNonTemporalActualObjects(t, "windows/amd64", "x86_64-pc-windows-msvc")
}
