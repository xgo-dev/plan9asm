package plan9asm

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

type x86DuplicateNativeRow struct {
	name, op, bank      string
	width, laneBytes    int
	odd, legacy, memory bool
	masked, zeroing     bool
}

func x86DuplicateNativeRows() []x86DuplicateNativeRow {
	var rows []x86DuplicateNativeRow
	for _, spec := range x86DuplicateMoveOracle {
		for _, bank := range []string{"X", "Y", "Z"} {
			if !spec.vector && bank != "X" {
				continue
			}
			for _, mode := range []string{"plain", "merge", "zero"} {
				if !spec.vector && mode != "plain" {
					continue
				}
				for _, memory := range []bool{false, true} {
					rows = append(rows, x86DuplicateNativeRow{
						name: fmt.Sprint("Copy", len(rows)), op: spec.name, bank: bank,
						width: map[string]int{"X": 16, "Y": 32, "Z": 64}[bank], laneBytes: spec.bytes,
						odd: spec.odd, legacy: !spec.vector, memory: memory,
						masked: mode != "plain", zeroing: mode == "zero",
					})
				}
			}
		}
	}
	return rows
}

func x86DuplicateNativeAssembly(row x86DuplicateNativeRow, arch string, originalGo, dead bool) string {
	word, move, push, pop := 8, "MOVQ", "PUSHFQ", "POPQ"
	if arch == "386" {
		word, move, push, pop = 4, "MOVL", "PUSHFL", "POPL"
	}
	name, wide, input, operation, mask := row.name, "Z", row.bank+"0", row.op, ""
	if originalGo {
		wide = "Y" // The actual Go runtime subset is legacy + VEX, never unexecuted EVEX.
	}
	if dead {
		name = "Dead" + name
	}
	if row.memory {
		input = "(BX)"
	}
	if row.masked {
		mask = "K1,"
	}
	if row.zeroing {
		operation += ".Z"
	}
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),AX\n%s input+%d(FP),BX\n%s old+%d(FP),CX\n",
		name, 3*word+8, move, move, word, move, 2*word)
	if row.masked {
		fmt.Fprintf(&source, "KMOVD mask+%d(FP),K1\n", 3*word)
	}
	load, store := "VMOVDQU64", "VMOVDQU64"
	if originalGo {
		load, store = "VMOVUPS", "VMOVUPS"
	}
	if !row.memory {
		fmt.Fprintf(&source, "%s (BX),%s0\n", load, wide)
	}
	fmt.Fprintf(&source, "%s (CX),%s2\nMOVL $3,DX\nCMPL DX,$3\nSTD\n%s %s,%s%s2\n",
		load, wide, operation, input, mask, row.bank)
	if dead {
		source.WriteString("CLD\nRET\n")
		return source.String()
	}
	// ID and unrelated FLAGS bits are intentionally unknown. Project the
	// declared status/DF bits immediately after POP, while its precise bit
	// witness is live, then clear DF before any whole-vector memory transport.
	fmt.Fprintf(&source, "%s\n%s DX\nANDL $0xcd5,DX\nCLD\n%s %s2,(AX)\nMOVL DX,64(AX)\nSTMXCSR 68(AX)\nRET\n",
		push, pop, store, wide)
	return source.String()
}

func TestX86DuplicateMoveIndependentNativeDirectory(t *testing.T) {
	rows, memory, originalGo := x86DuplicateNativeRows(), 0, 0
	for _, row := range rows {
		if row.memory {
			memory++
		}
		if row.legacy || !row.masked && row.width < 64 {
			originalGo++
		}
		if row.width%row.laneBytes != 0 || row.laneBytes != 4 && row.laneBytes != 8 {
			t.Fatal("invalid independent lane/width directory", row)
		}
	}
	if len(rows) != 60 || memory != 30 || len(rows)+memory > 96 || originalGo != 18 {
		t.Fatal("complete native/actual-Go matrix changed", len(rows), memory, originalGo)
	}
}

func TestX86DuplicateMoveNativeSourceFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			program := x86BuildDuplicateNativeProgram(target.arch)
			if strings.Count(program.source, "TEXT ·") != 90 {
				t.Fatal("complete initialized live/dead native source changed")
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, program.source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, program.source, program.declarations, target.arch, target.triple, api)
					if err != nil {
						t.Fatal("complete native runtime source lost initialized data/FLAGS/MXCSR/storage", err)
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						compileLLVMToObject(t, llc, target.triple, "duplicate-runtime.ll", "duplicate-runtime.o", body)
					}
				})
			}
		})
	}
}

type x86DuplicateNativeProgram struct {
	source, declarations, prototypes, cRows, faultRows string
	originalSource, originalDeclarations, originalRows string
	faultAligned                                       []bool
}

// Keep the exact native fixture available to host-independent source checks.
// Building it must not require an x86 execution host or hide a failed oracle.
func x86BuildDuplicateNativeProgram(arch string) x86DuplicateNativeProgram {
	rows := x86DuplicateNativeRows()
	var source, declarations, prototypes, cRows, faultRows strings.Builder
	var originalSource, originalDeclarations, originalRows strings.Builder
	var faultAligned []bool
	originalDeclarations.WriteString("package oracle\n")
	flag := func(value bool) int {
		if value {
			return 1
		}
		return 0
	}
	for _, row := range rows {
		declaration := fmt.Sprintf("func %s(out *[96]byte,input,old *[64]byte,mask uint64)\n", row.name)
		declarations.WriteString(declaration)
		source.WriteString(x86DuplicateNativeAssembly(row, arch, false, false))
		fmt.Fprintf(&prototypes, "extern void %s(uint8_t *,const uint8_t *,const uint8_t *,uint64_t);\n", row.name)
		fields := fmt.Sprintf("%d,%d,%d,%d,%d,%d", row.width, row.laneBytes,
			flag(row.odd), flag(row.legacy), flag(row.masked), flag(row.zeroing))
		fmt.Fprintf(&cRows, "{%s,%s},\n", row.name, fields)
		if row.memory {
			fmt.Fprintf(&declarations, "func Dead%s(out *[96]byte,input,old *[64]byte,mask uint64)\n", row.name)
			source.WriteString(x86DuplicateNativeAssembly(row, arch, false, true))
			fmt.Fprintf(&prototypes, "extern void Dead%s(uint8_t *,const uint8_t *,const uint8_t *,uint64_t);\n", row.name)
			bytes, aligned := row.width, row.legacy && row.laneBytes == 4
			if row.laneBytes == 8 && row.width == 16 {
				bytes = 8
			}
			faultAligned = append(faultAligned, aligned)
			kind := 0
			if aligned && row.odd {
				kind = 1
			} else if aligned {
				kind = 2
			}
			fmt.Fprintf(&faultRows, "{Dead%s,%d,%d},\n", row.name, bytes, kind)
		}
		if row.legacy || !row.masked && row.width < 64 {
			originalSource.WriteString(x86DuplicateNativeAssembly(row, arch, true, false))
			originalDeclarations.WriteString(declaration)
			fmt.Fprintf(&originalRows, "{%s,%s},\n", row.name, fields)
		}
	}
	return x86DuplicateNativeProgram{
		source: source.String(), declarations: declarations.String(),
		prototypes: prototypes.String(), cRows: cRows.String(), faultRows: faultRows.String(),
		originalSource: originalSource.String(), originalDeclarations: originalDeclarations.String(),
		originalRows: originalRows.String(), faultAligned: faultAligned,
	}
}

func x86RunDuplicateMoveNative(t *testing.T, execution x86FloatCompareExecution, arch string) {
	t.Helper()
	program := x86BuildDuplicateNativeProgram(arch)
	// All 90 complete source kernels are compiled by Go, including the EVEX
	// rows. Only the separate 18-row AVX/SSE3 source is claimed as Go execution.
	goAssemblerOracleOutput(t, arch, program.source, "", true)
	ir, err := x86ScalarFPBitViewAPI(t, program.source, program.declarations, arch, execution.triple, "Go")
	if err != nil {
		t.Fatal("complete original duplicate runtime source rejected", err)
	}
	valueDriver := x86DuplicateNativeValuesC(program.prototypes, program.cRows)
	faultDriver := x86DuplicateNativeFaultsC(program.prototypes, program.faultRows)
	for _, pipeline := range []struct{ name, level, ir string }{
		{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir}, {"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			valueExecutable := execution.compileLLVM(t, "duplicate-values", pipeline.ir, valueDriver, pipeline.level)
			var output []byte
			if arch == "386" {
				output = x87IA32RunDirect(t, x86NativeOracleIA32Executable(t, execution, valueExecutable), nil, os.Environ())
			} else {
				output = execution.run(t, valueExecutable)
			}
			if string(output) != "duplicate whole64/FLAGS/DF/MXCSR/canary outcomes 5760 failures 0\n" {
				t.Fatal("independent complete byte model mismatch", string(output))
			}
			executable := execution.compileLLVM(t, "duplicate-faults", pipeline.ir, faultDriver, pipeline.level)
			var ia32 *x87IA32Executable
			if arch == "386" {
				program := x86NativeOracleIA32Executable(t, execution, executable)
				ia32 = &program
			}
			for row, aligned := range program.faultAligned {
				for mask := 0; mask < 2; mask++ {
					probes := 5
					if aligned {
						probes = 19 // Every misaligned residue modulo 16, not just +1.
					}
					for probe := 0; probe < probes; probe++ {
						index := row*2 + mask
						observe := func(original int) string {
							if ia32 != nil {
								if err := ia32.verify(); err != nil {
									t.Fatal(err)
								}
							}
							result := x86ObserveMemoryFault(t, execution, executable, index, probe, original)
							if ia32 != nil {
								if err := ia32.verify(); err != nil {
									t.Fatal(err)
								}
							}
							return result
						}
						want := observe(1)
						faults := probe < 2 || aligned && probe >= 4
						if faults && want != "segv" && want != "bus" || !faults && want != "return" {
							t.Fatal("independent native access had an unexpected result", row, mask, probe, want)
						}
						if got := observe(0); got != want {
							t.Fatal("dead duplicate lost NF tuple or original alignment fault", row, mask, probe, got, want)
						}
					}
				}
			}
			t.Logf("duplicate native arch=%s live=60 dead=30 whole64-outcomes=5760 fault-processes=712; legacy original opcode/all mod16, E4NF/E5NF independent full-span references", arch)
		})
	}
	t.Run("OriginalGo", func(t *testing.T) {
		declarations := program.originalDeclarations + "func MXCSR(value uint32) uint32\n"
		source := program.originalSource + x86OriginalNativeMXCSRSource(arch)
		x86RunOriginalGoNativeSource(t, execution, arch, declarations, source,
			fmt.Sprintf(x86DuplicateOriginalGo, program.originalRows))
		t.Log("actual original Go legacy/VEX: 18 rows × 16 IEEE/bit patterns × 6 masks = 1728 whole32/FLAGS/DF/MXCSR/canary outcomes; no EVEX execution claim")
	})
}
