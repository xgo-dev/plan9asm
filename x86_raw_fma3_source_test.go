package plan9asm

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

type x86RawFMA3SourceCase struct {
	op, bank, control string
	opcode            byte
	evex, memory      bool
	mask              int
	zero, high        bool
}

// Independent Go _yvaddpd/_yvaddsd and FMA opcode axes. Physical low-bank
// unmasked EVEX is intentionally distinct from the named spelling's VEX choice.
// Do not derive this inventory from the production decoder or FMA registry.
func x86RawFMA3SourceCases() []x86RawFMA3SourceCase {
	var rows []x86RawFMA3SourceCase
	for _, family := range []struct {
		stem   string
		opcode byte
		scalar bool
	}{
		{"VFMADD", 0x98, true}, {"VFMSUB", 0x9a, true},
		{"VFNMADD", 0x9c, true}, {"VFNMSUB", 0x9e, true},
		{"VFMADDSUB", 0x96, false}, {"VFMSUBADD", 0x97, false},
	} {
		for orderIndex, order := range []string{"132", "213", "231"} {
			for _, suffix := range []string{"PS", "PD", "SS", "SD"} {
				scalar := strings.HasPrefix(suffix, "S")
				if scalar && !family.scalar {
					continue
				}
				row := x86RawFMA3SourceCase{
					op: family.stem + order + suffix, bank: "X",
					opcode: family.opcode + byte(orderIndex*16),
				}
				if scalar {
					row.opcode++
				}
				rows = append(rows, row)
				row.evex = true
				rows = append(rows, row)
				row.high = true
				rows = append(rows, row)
				row.high = false
				if !scalar {
					row.evex, row.bank, row.memory = false, "Y", true
					rows = append(rows, row)
					row.evex, row.memory, row.mask = true, false, 1
					rows = append(rows, row)
					row.bank, row.memory, row.control, row.zero = "Z", true, "BCST", true
					rows = append(rows, row)
				}
				row.evex, row.memory, row.mask, row.zero = true, false, 1, true
				for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
					row.control = rounding
					rows = append(rows, row)
				}
			}
		}
	}
	return rows
}

func (row x86RawFMA3SourceCase) scalar() bool {
	return strings.HasSuffix(row.op, "SS") || strings.HasSuffix(row.op, "SD")
}

func (row x86RawFMA3SourceCase) registers() (int, int, int) {
	if row.high {
		return 20, 21, 22
	}
	return 0, 1, 2
}

func (row x86RawFMA3SourceCase) instruction() string {
	first, second, destination := row.registers()
	name, source := row.op, fmt.Sprint(row.bank, first)
	if row.memory {
		source = "(AX)"
	}
	if row.control != "" {
		name += "." + row.control
	}
	if row.zero {
		name += ".Z"
	}
	mask := ""
	if row.mask != 0 {
		mask = fmt.Sprintf("K%d,", row.mask)
	}
	return fmt.Sprintf("%s %s,%s%d,%s%s%d", name, source, row.bank, second, mask, row.bank, destination)
}

func (row x86RawFMA3SourceCase) code() []byte {
	first, second, destination := row.registers()
	width64 := strings.HasSuffix(row.op, "D")
	length := byte(map[string]int{"X": 0, "Y": 1, "Z": 2}[row.bank])
	var code []byte
	if row.evex {
		if row.control != "" && row.control != "BCST" {
			length = byte(map[string]int{"RN_SAE": 0, "RD_SAE": 1, "RU_SAE": 2, "RZ_SAE": 3}[row.control])
		}
		code = encodeX86EVEXFMA3(row.opcode, width64, length,
			row.control != "", row.zero, row.mask, destination, second, first)
	} else {
		code = encodeX86VEXFMA3(row.opcode, width64, row.bank == "Y", destination, second, first)
	}
	if row.memory {
		code[1] |= 0x60 // AX base has neither B nor X extension.
		code[len(code)-1] = byte(destination&7) << 3
	}
	return code
}

func TestX86RawFMA3OriginalGoBytesAndCompleteDirectory(t *testing.T) {
	x86FMA3CheckCompleteEncoderAttributes(t)
	rows := x86RawFMA3SourceCases()
	if len(rows) != 528 {
		t.Fatal("incomplete independent 60-name physical FMA directory", len(rows))
	}
	names, seen := make(map[string]bool), make(map[string]bool)
	var source strings.Builder
	var expected []byte
	count := 0
	for _, row := range rows {
		key := fmt.Sprintf("%s/EVEX=%t", row.instruction(), row.evex)
		if seen[key] {
			t.Fatal("duplicate independent physical case", key)
		}
		seen[key], names[row.op] = true, true
		if row.evex && !row.high && row.bank == "X" && row.mask == 0 {
			continue // Named low-bank unmasked X necessarily selects VEX.
		}
		source.WriteString(row.instruction() + "\n")
		expected = append(expected, row.code()...)
		count++
	}
	actual, pcs := x86NumericalBoundaryGoBytes(t, "amd64", source.String()+"RET")
	expected = append(expected, 0xc3)
	if len(names) != 60 || count != 468 || len(pcs) != count+1 || !bytes.Equal(actual, expected) {
		t.Fatal("actual original Go FMA encodings differ from complete independent physical bytes", len(names), count, len(pcs))
	}
}

func TestX86RawFMA3PhysicalBytesIndependentLLVM22(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc required")
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			expected := make(map[string]int)
			for _, row := range x86RawFMA3SourceCases() {
				if row.high && arch == "386" {
					continue // Physical mode32 has only banks 0..7.
				}
				for _, value := range row.code() {
					fmt.Fprintf(&source, "0x%02x ", value)
				}
				source.WriteByte('\n')
				expected[strings.ToLower(row.op)]++
			}
			stage, cancel := runtimeOracleStageContext(t)
			defer cancel()
			command := exec.CommandContext(stage, mc, "--disassemble",
				"--triple="+x86AddressMemoryTargets(arch)[0], "--mattr=+avx,+fma,+avx512f,+avx512vl")
			command.Stdin = strings.NewReader(source.String())
			output, err := runtimeOracleCombinedOutput(stage, command)
			if err != nil || strings.Contains(string(output), "warning") || strings.Contains(string(output), "invalid") {
				t.Fatalf("independent physical FMA prior failed: %v\n%s", err, output)
			}
			for name, want := range expected {
				if count := len(regexp.MustCompile(`\b`+name+`[ \t]+`).FindAll(output, -1)); count != want {
					t.Fatal("independent LLVM22 physical FMA directory is incomplete", name, count, want)
				}
			}
		})
	}
}

func TestX86RawFMA3PhysicalGenerationAndIsolatedISA(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86RawFMA3SourceCases() {
			if row.high && arch == "386" {
				continue
			}
			t.Run(fmt.Sprintf("%s/%s/EVEX=%t", arch, row.instruction(), row.evex), func(t *testing.T) {
				ins := x86RawMoveObservedInstruction(t, arch, row.code())
				form, known, err := amd64FMA3Properties(ins, arch)
				if !known || err != nil || string(ins.Op) != strings.Fields(row.instruction())[0] {
					t.Fatal("physical FMA lost its independent complete typed grammar", err)
				}
				if x86FMA3NativeEVEX(ins, form) != row.evex {
					t.Error("physical low-bank generation was inferred from a named spelling")
				}
				features := "," + inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{ins}}) + ","
				if strings.Contains(features, ",+avx512f,") != row.evex ||
					strings.Contains(features, ",+avx512vl,") != (row.evex && !row.scalar() && row.bank != "Z") ||
					!row.evex && (!strings.Contains(features, ",+avx,") || !strings.Contains(features, ",+fma,")) {
					t.Error("isolated original physical FMA acquired a foreign ISA profile", features)
				}
			})
		}
	}
}
