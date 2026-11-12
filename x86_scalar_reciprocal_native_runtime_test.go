package plan9asm

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// This is an independent finite alias basis, not a list obtained from the
// production grammar: five set partitions of three VEX operands, both memory
// base/destination relations, and both legacy register relations plus m32.
type x86ScalarReciprocalNativeRow struct {
	name, op          string
	source, base, dst int
	kind              int
	memory, vector    bool
}

func x86ScalarReciprocalNativeRows() []x86ScalarReciprocalNativeRow {
	var rows []x86ScalarReciprocalNativeRow
	for kind, op := range []string{"RCPSS", "RSQRTSS", "VRCPSS", "VRSQRTSS"} {
		aliases := [][3]int{{0, 2, 2}, {2, 2, 2}, {-1, 2, 2}}
		if kind >= 2 {
			aliases = [][3]int{{0, 1, 2}, {2, 1, 2}, {0, 2, 2}, {1, 1, 2}, {2, 2, 2}, {-1, 1, 2}, {-1, 2, 2}}
		}
		for _, alias := range aliases {
			rows = append(rows, x86ScalarReciprocalNativeRow{
				name: fmt.Sprint("Estimate", len(rows)), op: op,
				source: alias[0], base: alias[1], dst: alias[2],
				kind: kind, memory: alias[0] < 0, vector: kind >= 2,
			})
		}
	}
	return rows
}

func x86ScalarReciprocalNativeAssembly(row x86ScalarReciprocalNativeRow, arch string, dead bool) string {
	word, move, push, pop := 8, "MOVQ", "PUSHFQ", "POPQ"
	if arch == "386" {
		word, move, push, pop = 4, "MOVL", "PUSHFL", "POPL"
	}
	input := fmt.Sprintf("X%d", row.source)
	if row.memory {
		input = "(AX)"
	}
	operation := fmt.Sprintf("%s %s,X%d", row.op, input, row.dst)
	if row.vector {
		operation = fmt.Sprintf("%s %s,X%d,X%d", row.op, input, row.base, row.dst)
	}
	if dead {
		return fmt.Sprintf("TEXT ·Dead%d(SB),4,$0-%d\n%s input+0(FP),AX\n%s\nRET\n", row.kind, word, move, operation)
	}
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s input+%d(FP),AX\n%s upper+%d(FP),BX\n%s old+%d(FP),CX\n",
		row.name, 4*word+4, move, move, word, move, 2*word, move, 3*word)
	source.WriteString("VMOVUPS (AX),Y0\nVMOVUPS (BX),Y1\nVMOVUPS (CX),Y2\n")
	if !row.memory {
		fmt.Fprintf(&source, "MOVSS (AX),X%d\n", row.source)
	}
	// Set the complete requested environment only after preparing transport.
	// The estimate must not signal or change any MXCSR bit, including unmasked
	// SNaN/denormal inputs. Restore before returning to either C or Go.
	fmt.Fprintf(&source, "STMXCSR 40(DI)\nLDMXCSR csr+%d(FP)\nMOVL $0x7fffffff,DX\nADDL $1,DX\nSTC\nSTD\n%s\n", 4*word, operation)
	fmt.Fprintf(&source, "%s\n%s DX\nANDL $0xcd5,DX\nCLD\nVMOVUPS Y%d,8(DI)\nMOVL DX,44(DI)\nSTMXCSR 48(DI)\nLDMXCSR 40(DI)\nVZEROUPPER\nRET\n", push, pop, row.dst)
	return source.String()
}

func x86ScalarReciprocalNativeProgram(arch string) (source, declarations, prototypes, metadata string) {
	var assembly, decl, c, rows strings.Builder
	dead := make(map[int]bool)
	for _, row := range x86ScalarReciprocalNativeRows() {
		assembly.WriteString(x86ScalarReciprocalNativeAssembly(row, arch, false))
		fmt.Fprintf(&decl, "func %s(out *[64]byte,input,upper,old *[32]byte,csr uint32)\n", row.name)
		fmt.Fprintf(&c, "extern void %s(uint8_t *,const uint8_t *,const uint8_t *,const uint8_t *,uint32_t);\n", row.name)
		fmt.Fprintf(&rows, "{%s,%d,%d,%d,%d},\n", row.name, row.kind, row.source, row.base, row.dst)
		if row.memory && !dead[row.kind] {
			dead[row.kind] = true
			assembly.WriteString(x86ScalarReciprocalNativeAssembly(row, arch, true))
			fmt.Fprintf(&decl, "func Dead%d(input *uint32)\n", row.kind)
			fmt.Fprintf(&c, "extern void Dead%d(const uint8_t *);\n", row.kind)
		}
	}
	return assembly.String(), decl.String(), c.String(), rows.String()
}

func x86ScalarReciprocalOriginalReferences(arch string) (string, string) {
	var source, declarations strings.Builder
	result := goWordSize(arch)
	for kind, op := range []string{"RCPSS", "RSQRTSS", "VRCPSS", "VRSQRTSS"} {
		fmt.Fprintf(&declarations, "func Reference%d(bits uint32) uint32\n", kind)
		fmt.Fprintf(&source, "TEXT ·Reference%d(SB),4,$0-%d\nMOVSS bits+0(FP),X0\n%s X0,X0", kind, result+4, op)
		if kind >= 2 {
			source.WriteString(",X0")
		}
		fmt.Fprintf(&source, "\nMOVSS X0,ret+%d(FP)\nRET\n", result)
	}
	declarations.WriteString("func MXCSR(value uint32) uint32\n")
	source.WriteString(x86OriginalNativeMXCSRSource(arch))
	return source.String(), declarations.String()
}

func TestX86ScalarReciprocalNativeDirectoryAndOriginalGoSource(t *testing.T) {
	rows := x86ScalarReciprocalNativeRows()
	var kinds [4]int
	seen := make(map[string]bool)
	for _, row := range rows {
		if row.kind < 0 || row.kind >= len(kinds) || seen[row.name] || row.vector != (row.kind >= 2) || row.memory != (row.source < 0) {
			t.Fatal("invalid independent native alias row", row)
		}
		seen[row.name] = true
		kinds[row.kind]++
	}
	if len(rows) != 20 || kinds != [4]int{3, 3, 7, 7} {
		t.Fatal("complete four-name native alias basis changed", len(rows), kinds)
	}
	for _, arch := range []string{"amd64", "386"} {
		refs, refDecl := x86ScalarReciprocalOriginalReferences(arch)
		source, declarations, _, metadata := x86ScalarReciprocalNativeProgram(arch)
		if strings.Count(source, "TEXT ·Estimate") != 20 || strings.Count(source, "TEXT ·Dead") != 4 ||
			strings.Contains(source+refs, "Z0") || strings.Contains(source+refs, "VMOVDQU64") {
			t.Fatal("native source lost complete live/dead SSE/AVX-only inventory", arch)
		}
		for name, text := range map[string]string{
			"value.go":      "package oracle\n" + declarations + refDecl,
			"api.go":        "package bitview\n" + declarations,
			"value_test.go": fmt.Sprintf(x86ScalarReciprocalNativeOriginalGo, metadata),
		} {
			file, err := parser.ParseFile(token.NewFileSet(), name, text, parser.AllErrors)
			want := "oracle"
			if name == "api.go" {
				want = "bitview"
			}
			if err != nil || file.Name.Name != want {
				t.Fatal("complete actual original Go source is not parseable", arch, name, err)
			}
			if name == "api.go" {
				if _, err := parser.ParseFile(token.NewFileSet(), name, "package bitview\npackage oracle\n"+declarations, parser.AllErrors); err == nil {
					t.Fatal("API source control accepted the old duplicate package clause")
				}
			}
		}
	}
}

// STD/CLD are deliberately retained: this root validates native x86 source,
// not a portable replacement that silently drops the DF observation. The
// independent typed family already has its separate five-target object gate.
func TestX86ScalarReciprocalNativeSourcePhysicalX86Targets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		if !strings.HasPrefix(target.triple, "x86_64-") && !strings.HasPrefix(target.triple, "i386-") {
			continue
		}
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, _, _ := x86ScalarReciprocalNativeProgram(target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil {
						t.Fatal("complete initialized estimate/FLAGS/DF/MXCSR source rejected", err)
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						compileLLVMToObject(t, llc, target.triple, "scalar-reciprocal-native.ll", "scalar-reciprocal-native.o", body)
					}
				})
			}
		})
	}
}

func x86RunScalarReciprocalNative(t *testing.T, execution x86FloatCompareExecution, arch string) {
	t.Helper()
	if len(execution.prefix) != 0 || arch != "amd64" && arch != "386" {
		t.Fatal("estimate native qualification requires direct x86 host execution", arch, execution.prefix)
	}
	source, declarations, prototypes, metadata := x86ScalarReciprocalNativeProgram(arch)
	goAssemblerOracleOutput(t, arch, source, "", true)
	ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, execution.triple, "Go")
	if err != nil {
		t.Fatal("complete native four-name estimate program rejected", err)
	}
	for _, pipeline := range []struct{ name, level, ir string }{
		{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir}, {"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			executable := execution.compileLLVM(t, "scalar-reciprocal-values", pipeline.ir,
				fmt.Sprintf(x86ScalarReciprocalNativeValuesC, prototypes, metadata), pipeline.level)
			var output []byte
			if arch == "386" {
				output = x87IA32RunDirect(t, x86NativeOracleIA32Executable(t, execution, executable), nil, os.Environ())
			} else {
				output = execution.run(t, executable)
			}
			if string(output) != "scalar estimates whole32/FLAGS/DF/MXCSR/canary outcomes 30720 failures 0\n" {
				t.Fatal("independent native scalar estimate model mismatch", string(output))
			}
			faultExecutable := execution.compileLLVM(t, "scalar-reciprocal-faults", pipeline.ir,
				x86MemoryFaultSupportC+prototypes+x86ScalarReciprocalNativeFaultsC, pipeline.level)
			var ia32 *x87IA32Executable
			if arch == "386" {
				program := x86NativeOracleIA32Executable(t, execution, faultExecutable)
				ia32 = &program
			}
			for row := 0; row < 4; row++ {
				for probe := 0; probe < 5; probe++ {
					observe := func(original int) string {
						if ia32 != nil {
							if err := ia32.verify(); err != nil {
								t.Fatal(err)
							}
						}
						result := x86ObserveMemoryFault(t, execution, faultExecutable, row, probe, original)
						if ia32 != nil {
							if err := ia32.verify(); err != nil {
								t.Fatal(err)
							}
						}
						return result
					}
					want := observe(1)
					if probe < 2 && want != "segv" && want != "bus" || probe >= 2 && want != "return" {
						t.Fatal("actual scalar opcode has unexpected exact m32 access", row, probe, want)
					}
					if got := observe(0); got != want {
						t.Fatal("dead scalar estimate lost actual m32 fault", row, probe, got, want)
					}
				}
			}
			t.Logf("scalar estimates native arch=%s live=20 dead=4 whole32-outcomes=30720 fault-processes=40; SSE/AVX actual scalar opcodes, no AVX512/Z transport", arch)
		})
	}
	t.Run("OriginalGo", func(t *testing.T) {
		references, refDecl := x86ScalarReciprocalOriginalReferences(arch)
		x86RunOriginalGoNativeSource(t, execution, arch, "package oracle\n"+declarations+refDecl, source+references,
			fmt.Sprintf(x86ScalarReciprocalNativeOriginalGo, metadata))
		t.Log("actual original Go scalar estimates: 20 aliases × 24 bit patterns × 64 MXCSR profiles = 30720 whole32/FLAGS/DF/MXCSR/canary outcomes; independent scalar references, no AVX512/Z execution claim")
	})
}
