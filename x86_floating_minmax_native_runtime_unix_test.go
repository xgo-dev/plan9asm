//go:build unix

package plan9asm

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/nativeoracle"
)

// Legacy and VEX are independent of the still-pending EVEX hardware owner.
// The five register partitions and two memory/base aliases cover operand
// identity without multiplying the implementation by concrete registers.
type x86MinMaxNativeCase struct {
	op                   string
	bits, width          int
	source, second, dest int
	legacy, scalar, dead bool
}

func x86MinMaxNativeCases() []x86MinMaxNativeCase {
	var rows []x86MinMaxNativeCase
	for _, member := range x86FloatingMinMaxCases {
		widths := []int{16}
		aliases := [][3]int{{1, 2, 2}, {2, 2, 2}, {-1, 2, 2}}
		if !member.legacy {
			aliases = [][3]int{{0, 1, 2}, {2, 1, 2}, {0, 2, 2}, {1, 1, 2}, {2, 2, 2}, {-1, 0, 2}, {-1, 2, 2}}
			if !member.scalar {
				widths = append(widths, 32)
			}
		}
		for _, width := range widths {
			for index := 0; index <= len(aliases); index++ {
				alias := aliases[len(aliases)-1]
				if index < len(aliases) {
					alias = aliases[index]
				}
				rows = append(rows, x86MinMaxNativeCase{
					op: member.op, bits: member.bits, width: width,
					source: alias[0], second: alias[1], dest: alias[2],
					legacy: member.legacy, scalar: member.scalar, dead: index == len(aliases),
				})
			}
		}
	}
	return rows
}

func (row x86MinMaxNativeCase) operation(memory string) string {
	bank := "X"
	if row.width == 32 {
		bank = "Y"
	}
	first := memory
	if row.source >= 0 {
		first = fmt.Sprintf("%s%d", bank, row.source)
	}
	if row.legacy {
		return fmt.Sprintf("%s %s,%s%d", row.op, first, bank, row.dest)
	}
	return fmt.Sprintf("%s %s,%s%d,%s%d", row.op, first, bank, row.second, bank, row.dest)
}

func (row x86MinMaxNativeCase) body(original bool) string {
	first, memory, old, control := "AX", "BX", "CX", "MOVL csr+32(FP),DX\nMOVL DX,44(DI)\n"
	if original {
		// SysV C arguments: out=DI, a=SI, b=DX, old=CX, csr=R8.
		first, memory = "SI", "R9"
		control = "MOVQ DX,R9\nMOVL R8,44(DI)\n"
	}
	second := memory
	if row.source < 0 {
		// A scalar memory operand must not acquire a preparatory m256 load.
		second = first
	}
	load, bank := "VMOVUPS", "Y"
	if row.legacy {
		// Keep the complete SSE/SSE2 owner runnable without AVX state.
		// Its output observes X aliases, not uninitialized physical Y bytes.
		load, bank = "MOVUPS", "X"
	}
	var source strings.Builder
	source.WriteString(control)
	fmt.Fprintf(&source, "%s (%s),%s0\n%s (%s),%s1\n%s (%s),%s2\n", load, first, bank, load, second, bank, load, old, bank)
	// Seed AF explicitly rather than infer it from an emulator's ADD result.
	// OF still comes from ADD; SAHF sets SF/ZF/AF/PF/CF and preserves OF.
	source.WriteString("STMXCSR 32(DI)\nLDMXCSR 44(DI)\nMOVL $0x7fffffff,DX\nADDL $1,DX\nMOVB $0x95,AH\nSAHF\nSTD\n")
	if original {
		// The independent native observer can retain reserved hardware FLAGS.
		// Do not turn those unmodeled bits into translator numerical inputs.
		source.WriteString("PUSHFQ\nPOPQ R10\nMOVL R10,48(DI)\n")
	}
	fmt.Fprintln(&source, row.operation("("+memory+")"))
	source.WriteString("PUSHFQ\nPOPQ DX\nANDL $0xcd5,DX\nCLD\n")
	if row.dead {
		fmt.Fprintf(&source, "%s (%s),%s%d\n", load, old, bank, row.dest)
	}
	fmt.Fprintf(&source, "%s %s%d,(DI)\nMOVL DX,40(DI)\nSTMXCSR 36(DI)\nLDMXCSR 32(DI)\n", load, bank, row.dest)
	if !row.legacy {
		source.WriteString("VZEROUPPER\n")
	}
	source.WriteString("RET\n")
	return source.String()
}

func x86MinMaxNativeProgram(rows []x86MinMaxNativeCase) (source, declarations, prototypes, kernels string) {
	var assembly, decl, c, metadata strings.Builder
	for index, row := range rows {
		name, original := fmt.Sprintf("MinMax%d", index), fmt.Sprintf("OriginalMinMax%d", index)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-36\nMOVQ out+0(FP),DI\nMOVQ a+8(FP),AX\nMOVQ b+16(FP),BX\nMOVQ old+24(FP),CX\n%s", name, row.body(false))
		fmt.Fprintf(&decl, "func %s(out *[64]byte,a,b,old *[32]byte,csr uint32)\n", name)
		fmt.Fprintf(&c, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,uint32_t);\n", name)
		fmt.Fprintf(&c, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,uint32_t);\n", original)
		minimum := strings.Contains(row.op, "MIN")
		fmt.Fprintf(&metadata, "{%s,%s,%d,%d,%d,%d,%d,%t,%t,%t,%t},\n", name, original,
			row.bits, row.width, row.source, row.second, row.dest, row.legacy, row.scalar, row.dead, minimum)
	}
	return assembly.String(), decl.String(), c.String(), metadata.String()
}

func x86MinMaxNativeDriver(t *testing.T, rows []x86MinMaxNativeCase, triple string) (source, declarations, driver string) {
	t.Helper()
	source, declarations, prototypes, kernels := x86MinMaxNativeProgram(rows)
	var originals strings.Builder
	for index, row := range rows {
		original := fmt.Sprintf("OriginalMinMax%d", index)
		code := x86OrderingHintGoBytes(t, "amd64", "TEXT original(SB),4,$0-0\n"+row.body(true))
		var bytes []string
		for _, value := range code {
			bytes = append(bytes, fmt.Sprintf("0x%02x", value))
		}
		symbol := original
		if strings.Contains(triple, "apple") {
			symbol = "_" + symbol
		}
		fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(bytes, ",")+"\n")
	}
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	fixture, err := os.ReadFile("testdata/x86_floating_minmax_native.c")
	if err != nil {
		t.Fatal(err)
	}
	driver = strings.NewReplacer("@PROTOTYPES@", prototypes, "@ORIGINALS@", originals.String(), "@KERNELS@", kernels).Replace(string(fixture))
	return source, declarations, driver
}

func x86MinMaxNativeRuntime(t *testing.T, legacy bool) {
	x86MinMaxNativeRuntimeEncoding(t, legacy, false)
}

// Preserve the same independent hardware/IEEE oracle for named and raw inputs.
// Only the public translator's spelling of the instruction changes.
func x86MinMaxNativeRawSource(t *testing.T, source string, rows []x86MinMaxNativeCase) string {
	t.Helper()
	encodings := make(map[string]string)
	for _, row := range rows {
		operation := row.operation("(BX)")
		if _, exists := encodings[operation]; exists {
			continue
		}
		// NOSPLIT|NOFRAME leaves exactly this operation and its explicit RET.
		// The x/arch decoder does not supply an independent VEX length oracle.
		code := x86OrderingHintGoBytes(t, "amd64", "TEXT original(SB),516,$0-0\n"+operation+"\nRET\n")
		if len(code) < 2 || len(code) > 16 || code[len(code)-1] != 0xc3 {
			t.Fatal("original MIN/MAX encoding lacks its final RET", operation, code)
		}
		encodings[operation] = x86RawDisplacementDirectives(code[:len(code)-1])
	}
	for operation, encoded := range encodings {
		source = strings.ReplaceAll(source, "\n"+operation+"\n", "\n"+encoded)
	}
	if strings.Contains(source, "MIN") || strings.Contains(source, "MAX") {
		t.Fatal("raw MIN/MAX source retained a named instruction")
	}
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	return source
}

func x86MinMaxNativeRuntimeEncoding(t *testing.T, legacy, raw bool) {
	t.Helper()
	execution := x86FloatCompareExecutionTools(t)
	if runtime.GOOS == "darwin" {
		ctx, cancel := runtimeOracleStageContext(t)
		flags, err := nativeoracle.DarwinClangFlags(ctx, os.Environ())
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		execution.compiler = append(execution.compiler, flags...)
	}
	if !legacy {
		execution.requireAVX(t)
	}
	all := x86MinMaxNativeCases()
	if len(all) != 128 {
		t.Fatal("complete eight legacy/eight VEX alias basis changed", len(all))
	}
	var rows []x86MinMaxNativeCase
	for _, row := range all {
		if row.legacy == legacy {
			rows = append(rows, row)
		}
	}
	wantCount, numerical, faults, exceptions := 96, 393216, 360, 768
	if legacy {
		wantCount, numerical, faults, exceptions = 32, 131072, 160, 256
	}
	if len(rows) != wantCount {
		t.Fatal("complete native alias owner lost rows", legacy, len(rows))
	}
	source, declarations, driver := x86MinMaxNativeDriver(t, rows, execution.triple)
	if raw {
		source = x86MinMaxNativeRawSource(t, source, rows)
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
					input, level := ir, "-O0"
					if optimized {
						input, level = x86MulDivRoundOptimize(t, ir), "-O2"
					}
					output := execution.compileAndRunLLVM(t, "minmax-native", input, driver, level)
					want := fmt.Sprintf("%d MIN/MAX kernels: numerical %d, faults %d, exceptions %d, tripwires 2; failures 0\n", wantCount, numerical, faults, exceptions)
					if string(output) != want {
						t.Fatal("original-byte/LLVM MIN/MAX values, MXCSR, FLAGS or reads differ:", string(output))
					}
					t.Log(strings.TrimSpace(string(output)))
				})
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixX86FloatingMinMaxLegacy(t *testing.T) {
	x86MinMaxNativeRuntime(t, true)
}

func TestCrossLinuxRuntimeMatrixX86FloatingMinMaxVEX(t *testing.T) {
	x86MinMaxNativeRuntime(t, false)
}

func TestCrossLinuxRuntimeMatrixX86FloatingMinMaxRawLegacy(t *testing.T) {
	x86MinMaxNativeRuntimeEncoding(t, true, true)
}

func TestCrossLinuxRuntimeMatrixX86FloatingMinMaxRawVEX(t *testing.T) {
	x86MinMaxNativeRuntimeEncoding(t, false, true)
}

func TestX86FloatingMinMaxNativeAliasObjects(t *testing.T) {
	x86MinMaxNativeAliasObjects(t, false)
}

func TestX86FloatingMinMaxRawNativeAliasObjects(t *testing.T) {
	x86MinMaxNativeAliasObjects(t, true)
}

func x86MinMaxNativeAliasObjects(t *testing.T, raw bool) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	rows := x86MinMaxNativeCases()
	if len(rows) != 128 {
		t.Fatal("complete native source alias inventory changed", len(rows))
	}
	source, declarations, _, _ := x86MinMaxNativeProgram(rows)
	if raw {
		source = x86MinMaxNativeRawSource(t, source, rows)
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
					if err != nil {
						t.Fatal(err)
					}
					x86PackedStringCompileObject(t, llc, triple, ir, "-O0")
					x86PackedStringCompileObject(t, llc, triple, x86MulDivRoundOptimize(t, ir), "-O2")
				})
			}
		})
	}
}
