package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// The finite execution directory is independent of the production grammar.
// Canonical shapes come first; aliases and dynamic-environment controls do not
// change the official 132-shape denominator.
type x86Reciprocal14NativeRow struct {
	id, member, width, source, mode, low, upper int
	dynamic                                     bool
}

func x86Reciprocal14NativeRows() []x86Reciprocal14NativeRow {
	var rows []x86Reciprocal14NativeRow
	for member, op := range x86Reciprocal14TestMembers {
		for _, width := range []int{16, 32, 64} {
			if op.scalar && width != 16 {
				continue
			}
			for source := 0; source < 3; source++ {
				if op.scalar && source == 2 {
					continue
				}
				for mode := 0; mode < 3; mode++ {
					rows = append(rows, x86Reciprocal14NativeRow{
						member: member, width: width, source: source,
						mode: mode, low: 16, upper: 17,
					})
				}
			}
		}
	}
	canonical := append([]x86Reciprocal14NativeRow(nil), rows...)
	for _, row := range canonical {
		if row.source == 0 {
			aliases := [][2]int{{18, 17}}
			if x86Reciprocal14TestMembers[row.member].scalar {
				aliases = [][2]int{{18, 17}, {16, 18}, {17, 17}, {18, 18}}
			}
			for _, alias := range aliases {
				copy := row
				copy.low, copy.upper = alias[0], alias[1]
				rows = append(rows, copy)
			}
		} else if x86Reciprocal14TestMembers[row.member].scalar {
			row.upper = 18
			rows = append(rows, row)
		}
	}
	for member, op := range x86Reciprocal14TestMembers {
		width := 64
		if op.scalar {
			width = 16
		}
		rows = append(rows, x86Reciprocal14NativeRow{
			member: member, width: width, low: 16, upper: 17, dynamic: true,
		})
	}
	for index := range rows {
		rows[index].id = index
	}
	return rows
}

func (row x86Reciprocal14NativeRow) profile() int {
	if !x86Reciprocal14TestMembers[row.member].scalar && row.width != 64 {
		return 6
	}
	return 5
}

func (row x86Reciprocal14NativeRow) name() string { return fmt.Sprintf("R14%d", row.id) }

func (row x86Reciprocal14NativeRow) instruction() string {
	member := x86Reciprocal14TestMembers[row.member]
	op, input := member.op, "(AX)"
	bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[row.width]
	if row.source == 0 {
		input = fmt.Sprintf("%s%d", bank, row.low)
	} else if row.source == 2 {
		op += ".BCST"
	}
	if row.mode == 2 {
		op += ".Z"
	}
	operands := input + ","
	if member.scalar {
		operands += fmt.Sprintf("X%d,", row.upper)
	}
	if row.mode != 0 {
		operands += "K1,"
	}
	return op + " " + operands + bank + "18"
}

func x86Reciprocal14NativeSource(rows []x86Reciprocal14NativeRow, dead bool) (string, string, string) {
	var source, declarations, prototypes strings.Builder
	for _, row := range rows {
		name := row.name()
		fmt.Fprintf(&declarations, "func %s(out *[160]byte,input,upper,old *[64]byte,mask uint64,first,second uint32)\n", name)
		fmt.Fprintf(&prototypes, "extern void %s(uint8_t *,const uint8_t *,const uint8_t *,const uint8_t *,uint64_t,uint32_t,uint32_t);\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-48\nMOVQ out+0(FP),DI\nMOVQ input+8(FP),AX\n"+
			"MOVQ upper+16(FP),BX\nMOVQ old+24(FP),CX\nVMOVUPS (BX),Z17\nVMOVUPS (CX),Z18\n", name)
		if row.source == 0 {
			fmt.Fprintf(&source, "VMOVUPS (AX),Z%d\n", row.low)
		}
		// Z-width moves and KMOVW are deliberate: original Go execution must
		// not acquire narrow-VL or KMOVQ/BW requirements from its transport.
		source.WriteString("MOVQ mask+32(FP),DX\nKMOVW DX,K1\nSTMXCSR 128(DI)\nLDMXCSR first+40(FP)\n" +
			"MOVL $0x7fffffff,DX\nADDL $1,DX\nSTC\nSTD\n")
		source.WriteString(row.instruction() + "\nPUSHFQ\nPOPQ DX\nANDL $0xcd5,DX\nCLD\nMOVL DX,132(DI)\nSTMXCSR 136(DI)\n")
		if !dead {
			source.WriteString("VMOVUPS Z18,(DI)\n")
		}
		if row.dynamic {
			// Reloading inputs would hide same-input CSE across LDMXCSR.
			source.WriteString("LDMXCSR second+44(FP)\nMOVL $0x7fffffff,DX\nADDL $1,DX\nSTC\nSTD\n" +
				row.instruction() + "\nPUSHFQ\nPOPQ DX\nANDL $0xcd5,DX\nCLD\n" +
				"MOVL DX,144(DI)\nSTMXCSR 140(DI)\nVMOVUPS Z18,64(DI)\n")
		}
		source.WriteString("LDMXCSR 128(DI)\nVZEROUPPER\nRET\n")
	}
	return source.String(), declarations.String(), prototypes.String()
}

type x86Reciprocal14NativeCase struct {
	row, sample   int
	mask          uint64
	first, second uint32
}

func x86Reciprocal14NativeCases(rows []x86Reciprocal14NativeRow) []x86Reciprocal14NativeCase {
	var cases []x86Reciprocal14NativeCase
	environments := make(map[int]bool)
	for _, row := range rows {
		member := x86Reciprocal14TestMembers[row.member]
		lanes := row.width * 8 / member.bits
		if member.scalar {
			lanes = 1
		}
		if row.dynamic {
			cases = append(cases, x86Reciprocal14NativeCase{row.id, 6, 0xffff, 0x1f80, 0x1fc0})
			if row.member < 4 {
				cases = append(cases, x86Reciprocal14NativeCase{row.id, 16, 0xffff, 0x1f80, 0x9f80})
			}
			continue
		}
		for _, sample := range []int{0, 6, 10, 22} {
			for _, mask := range []uint64{0, 0xffff, 0x5555, 1, 1 << (lanes - 1), 1 << lanes} {
				cases = append(cases, x86Reciprocal14NativeCase{row.id, sample, mask, 0x1f80, 0x1f80})
			}
		}
		if row.source != 0 || row.mode != 0 || row.low != 16 || row.upper != 17 ||
			!member.scalar && row.width == 32 || environments[row.member] {
			continue
		}
		environments[row.member] = true
		for sample := 0; sample < 24; sample++ {
			for control := uint32(0); control < 64; control++ {
				csr := (control&3)<<13 | (control&4)<<4 | (control&8)<<12
				if control&16 != 0 {
					csr |= 0x3f
				}
				if control&32 != 0 {
					csr |= 0x1f80
				}
				cases = append(cases, x86Reciprocal14NativeCase{row.id, sample, 0xffff, csr, csr})
			}
		}
	}
	return cases
}

func x86Reciprocal14NativeTrace(data []byte, cases []x86Reciprocal14NativeCase) error {
	const header, record = 16, 184
	if len(data) != header+record*len(cases) || len(data) < header || !bytes.Equal(data[:8], []byte("R14TRACE")) {
		return fmt.Errorf("incomplete or foreign original-Go trace")
	}
	if binary.LittleEndian.Uint32(data[8:]) != 1 || int(binary.LittleEndian.Uint32(data[12:])) != len(cases) {
		return fmt.Errorf("original-Go trace protocol/count differs")
	}
	for index, c := range cases {
		r := data[header+index*record : header+(index+1)*record]
		if int(binary.LittleEndian.Uint32(r)) != c.row || int(binary.LittleEndian.Uint32(r[4:])) != c.sample ||
			binary.LittleEndian.Uint64(r[8:]) != c.mask || binary.LittleEndian.Uint32(r[16:]) != c.first ||
			binary.LittleEndian.Uint32(r[20:]) != c.second {
			return fmt.Errorf("original-Go trace case %d has foreign identity/order", index)
		}
	}
	return nil
}

func x86Reciprocal14NativeMetadata(rows []x86Reciprocal14NativeRow, goSyntax bool) string {
	var b strings.Builder
	for _, row := range rows {
		member := x86Reciprocal14TestMembers[row.member]
		dynamic := 0
		if row.dynamic {
			dynamic = 1
		}
		if goSyntax {
			fmt.Fprintf(&b, "{%d,%d,%d,%d,%d,%d,%d,%d,%d,%s},\n", row.id, row.member, member.bits,
				row.width, row.source, row.mode, row.low, row.upper, dynamic, row.name())
		} else {
			fmt.Fprintf(&b, "{%d,%s,%d},\n", row.id, row.name(), member.bits)
		}
	}
	return b.String()
}

// This is the one existing native process/LLVM driver, not a new runner.
// Only explicitly tagged roots call it; default owners below validate source,
// trace controls and actual objects without claiming native execution.
func x86RunReciprocal14Native(t *testing.T, profile int) {
	t.Helper()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || profile != 5 && profile != 6 {
		t.Fatal("RCP14 native qualification requires direct Linux/AMD64 and its exact profile")
	}
	if os.Getenv("PLAN9ASM_AVX512_RUNTIME") == "auto" {
		t.Fatal("explicit RCP14 native qualification is required; auto cannot skip hardware acceptance")
	}
	execution := x86FloatCompareExecutionTools(t)
	if execution.triple != "x86_64-unknown-linux-gnu" || len(execution.prefix) != 0 || execution.preserveArgv0 {
		t.Fatal("RCP14 native qualification cannot use foreign or emulated execution")
	}
	x86FloatCompareVerifyArguments(t, execution)
	preflight := map[int]string{5: "estimate14-F", 6: "estimate14-FVL"}[profile]
	x86OriginalFloatingRuntimeRequireCPU(t, preflight, execution.compiler[0], execution.triple, nil)
	var selected []x86Reciprocal14NativeRow
	for _, row := range x86Reciprocal14NativeRows() {
		if row.profile() == profile {
			selected = append(selected, row)
		}
	}
	for start := 0; start < len(selected); start += 32 {
		end := start + 32
		if end > len(selected) {
			end = len(selected)
		}
		rows := selected[start:end]
		t.Run(fmt.Sprintf("batch%d", start/32), func(t *testing.T) {
			source, declarations, prototypes := x86Reciprocal14NativeSource(rows, false)
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			x86NativeFixtureASMDecl(t, "amd64", declarations, source, "")
			cases := x86Reciprocal14NativeCases(rows)
			trace := filepath.Join(t.TempDir(), "original.trace")
			var caseSource strings.Builder
			for _, c := range cases {
				fmt.Fprintf(&caseSource, "{%d,%d,%d,%d,%d},\n", c.row, c.sample, c.mask, c.first, c.second)
			}
			original := strings.NewReplacer("@ROWS@", x86Reciprocal14NativeMetadata(rows, true),
				"@CASES@", caseSource.String(), "@TRACE@", strconv.Quote(trace)).Replace(x86Reciprocal14NativeOriginalGo)
			t.Run("OriginalGo", func(t *testing.T) {
				x86RunOriginalGoNativeSource(t, execution, "amd64", "package oracle\n"+declarations+
					"func MXCSR(value uint32) uint32\n", source+x86OriginalNativeMXCSRSource("amd64"), original)
			})
			data, err := os.ReadFile(trace)
			if err != nil {
				t.Fatal(err)
			}
			if err := x86Reciprocal14NativeTrace(data, cases); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(trace, 0400); err != nil {
				t.Fatal(err)
			}
			identity := sha256.Sum256(data)
			t.Logf("actual original-Go RCP14 sourceSHA=%x traceSHA=%x rows=%d cases=%d profile=%d",
				sha256.Sum256([]byte(source)), identity, len(rows), len(cases), profile)
			mainC := strings.NewReplacer("@PROTOTYPES@", prototypes, "@ROWS@", x86Reciprocal14NativeMetadata(rows, false),
				"@TRACE@", strconv.Quote(trace), "@COUNT@", strconv.Itoa(len(cases))).Replace(x86Reciprocal14NativeValuesC)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", execution.triple, api)
					if err != nil {
						t.Fatal("complete original native source rejected", err)
					}
					for _, pipeline := range []struct{ name, body, level string }{
						{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"},
						{"IR_O2/backend_O2", x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						t.Run(pipeline.name, func(t *testing.T) {
							executable := x86Reciprocal14NativeObject(t, execution, profile, "rcp14-native-values",
								source, declarations, pipeline.body, mainC, pipeline.level)
							output := execution.run(t, executable)
							if string(output) != fmt.Sprintf("RCP14 native original-Go bits cases=%d failures=0\n", len(cases)) {
								t.Fatal("native original-Go bit comparison lacks its complete terminal", string(output))
							}
							current, err := os.ReadFile(trace)
							if err != nil || sha256.Sum256(current) != identity {
								t.Fatal("original trace changed", err)
							}
						})
					}
				})
			}
		})
	}
	x86Reciprocal14NativeFaults(t, execution, profile)
}

func x86Reciprocal14NativeFaults(t *testing.T, execution x86FloatCompareExecution, profile int) {
	t.Helper()
	var rows []x86Reciprocal14NativeRow
	for _, row := range x86Reciprocal14NativeRows() {
		if row.id < 132 && row.source != 0 && row.profile() == profile {
			rows = append(rows, row)
		}
	}
	for start := 0; start < len(rows); start += 32 {
		end := start + 32
		if end > len(rows) {
			end = len(rows)
		}
		batch := rows[start:end]
		t.Run(fmt.Sprintf("faultBatch%d", start/32), func(t *testing.T) {
			source, declarations, mainC := x86Reciprocal14NativeFaultProgram(t, batch, profile)
			original := make(map[[2]int]string)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", execution.triple, api)
					if err != nil {
						t.Fatal("dead native RCP14 fault source rejected", err)
					}
					for _, pipeline := range []struct{ name, body, level string }{
						{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"},
						{"IR_O2/backend_O2", x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						t.Run(pipeline.name, func(t *testing.T) {
							executable := x86Reciprocal14NativeObject(t, execution, profile, "rcp14-native-faults",
								source, declarations, pipeline.body, mainC, pipeline.level)
							for rowIndex, row := range batch {
								for probe := 0; probe < 10; probe++ {
									key := [2]int{rowIndex, probe}
									want, seen := original[key]
									if !seen {
										want = x86ObserveMemoryFault(t, execution, executable, rowIndex, probe, 1)
										original[key] = want
									}
									member := x86Reciprocal14TestMembers[row.member]
									fullSpan := !member.scalar && row.source != 2 && row.width > member.bits/8
									fault := probe == 2 || probe == 4 || probe == 6 || probe == 7 ||
										row.mode == 0 && (probe < 2 || probe == 5 && fullSpan)
									if fault && want != "segv" && want != "bus" || !fault && want != "return" {
										t.Fatal("original RCP14 fault semantics differ", row.id, probe, want)
									}
									if got := x86ObserveMemoryFault(t, execution, executable, rowIndex, probe, 0); got != want {
										t.Fatal("RCP14 dead native memory fault mismatch", row.id, probe, got, want)
									}
								}
							}
						})
					}
				})
			}
		})
	}
}

func x86Reciprocal14NativeFaultProgram(t *testing.T, batch []x86Reciprocal14NativeRow, profile int) (string, string, string) {
	t.Helper()
	source, declarations, prototypes := x86Reciprocal14NativeSource(batch, true)
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	x86NativeFixtureASMDecl(t, "amd64", declarations, source, "")
	listing, err := x86ScalarLiteralGoListing(t, "amd64", source)
	if err != nil {
		t.Fatal(err)
	}
	operationLines := make(map[int]x86Reciprocal14NativeRow)
	for _, row := range batch {
		found := 0
		for line, instruction := range strings.Split(source, "\n") {
			if instruction == row.instruction() {
				operationLines[line+1] = row
				found++
			}
		}
		if found != 1 {
			t.Fatal("original fault instruction lost unique source ownership", row.id, found)
		}
	}
	originalBytes := make(map[int][]byte)
	x86Reciprocal14NativeGoBytesIR(t, listing, batch, func(owner string, line int, code []byte) {
		if row, exists := operationLines[line]; exists {
			if owner != row.name() || len(originalBytes[row.id]) != 0 {
				t.Fatal("original fault bytes have foreign/duplicate owner", owner, line)
			}
			originalBytes[row.id] = code
		}
	})
	var directory, nativeAsm strings.Builder
	for _, row := range batch {
		member := x86Reciprocal14TestMembers[row.member]
		lane, lanes, extent := member.bits/8, row.width*8/member.bits, row.width
		if member.scalar {
			lanes, extent = 1, lane
		}
		if row.source == 2 {
			extent = lane
		}
		fmt.Fprintf(&directory, "{%d,%s,%d,%d,%d,%d},\n", row.id, row.name(), extent, lane, lanes, row.mode)
		code := originalBytes[row.id]
		if len(code) == 0 {
			t.Fatal("actual original Go fault bytes absent", row.id)
		}
		var encoded strings.Builder
		for index, b := range code {
			if index != 0 {
				encoded.WriteByte(',')
			}
			fmt.Fprintf(&encoded, "0x%02x", b)
		}
		asm := "kmovw %1,%%k1; vpxord %%zmm17,%%zmm17,%%zmm17; vpxord %%zmm18,%%zmm18,%%zmm18; .byte " + encoded.String()
		// Go's selected original r/m operand is exactly (AX). The
		// fixed a constraint supplies that machine address; it grants
		// no new numerical pointer/array capability to translation.
		fmt.Fprintf(&nativeAsm, "case %d: __asm__ volatile(%s::\"a\"(input),\"r\"(mask):\"zmm17\",\"zmm18\",\"k1\",\"memory\");break;\n", row.id, strconv.Quote(asm))
	}
	features := "avx512f"
	if profile == 6 {
		features += ",avx512vl"
	}
	mainC := x86MemoryFaultSupportC + prototypes + strings.NewReplacer("@ROWS@", directory.String(),
		"@ORIGINAL@", nativeAsm.String(), "@FEATURES@", features).Replace(x86Reciprocal14NativeFaultsC)
	return source, declarations, mainC
}

func x86Reciprocal14NativeObject(t *testing.T, execution x86FloatCompareExecution, profile int,
	name, source, declarations, ir, mainC, level string) string {
	t.Helper()
	executable := execution.compileLLVM(t, name, ir, mainC, level)
	object := filepath.Join(filepath.Dir(executable), name+".o")
	objdump := findLLVM22Tool("llvm-objdump")
	if objdump == "" {
		t.Fatal("LLVM22 llvm-objdump required for actual native ISA acceptance")
	}
	listing := x86FloatCompareCaptureCommand(t, exec.Command(objdump, "-d", object))
	x86OriginalFloatingAuditListing(t, map[int]string{5: "estimate14-F", 6: "estimate14-FVL"}[profile],
		execution.triple, level, strings.ToLower(string(listing)), false, 0)
	x86Reciprocal14RetainObject(t, source, declarations, ir, object, listing)
	return executable
}
