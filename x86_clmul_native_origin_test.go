package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

type x86CLMULNativeOriginCase struct {
	encoding  string
	width     int
	w, memory bool
	immediate byte
}

// Go has six rows: legacy X, VEX X/Y and EVEX X/Y/Z. Intel SDM
// 325383-093US Vol. 2B 4-242..244 additionally binds both vector WIG values
// and their actual mode32 encodings, independently of Go's named arity cap.
func x86CLMULNativeOriginCases() []x86CLMULNativeOriginCase {
	var rows []x86CLMULNativeOriginCase
	for _, encoding := range []string{"legacy", "vex", "evex"} {
		widths := []int{16}
		if encoding != "legacy" {
			widths = append(widths, 32)
		}
		if encoding == "evex" {
			widths = append(widths, 64)
		}
		for _, width := range widths {
			for _, w := range []bool{false, true} {
				if encoding == "legacy" && w {
					continue
				}
				for _, memory := range []bool{false, true} {
					for _, immediate := range []byte{0, 1, 16, 17, 238, 239, 254, 255} {
						rows = append(rows, x86CLMULNativeOriginCase{encoding, width, w, memory, immediate})
					}
				}
			}
		}
	}
	return rows
}

func (row x86CLMULNativeOriginCase) name() string {
	return fmt.Sprintf("%s/%d/W%t/memory%t/selector%d", row.encoding, row.width, row.w, row.memory, row.immediate)
}

func (row x86CLMULNativeOriginCase) sourceInstruction(highDestination bool) string {
	bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[row.width]
	source, destination := bank+"0", bank+"2"
	if row.memory {
		source = "(BX)"
	}
	if highDestination {
		destination = bank + "18" // Force Go's otherwise indistinguishable EVEX X/Y row.
	}
	if row.encoding == "legacy" {
		return fmt.Sprintf("PCLMULQDQ $%d,%s,X1", row.immediate, source)
	}
	return fmt.Sprintf("VPCLMULQDQ $%d,%s,%s1,%s", row.immediate, source, bank, destination)
}

func (row x86CLMULNativeOriginCase) code() []byte {
	destination := 2
	if row.encoding == "legacy" {
		destination = 1
	}
	code := x86RawCLMULCode(row.encoding, row.width, 0, 1, destination, row.immediate)
	if row.memory {
		index := len(code) - 2
		code[index] = code[index]&0x38 | 3 // Original (BX), not a selected-qword load.
	}
	if row.w {
		code[2] |= 0x80
	}
	return code
}

func x86CLMULNativeOriginRequireGoBytes(t *testing.T, rows []x86CLMULNativeOriginCase) {
	t.Helper()
	var source strings.Builder
	for _, row := range rows {
		source.WriteString(row.sourceInstruction(row.encoding == "evex" && row.width != 64) + "\n")
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", source.String()+"RET")
	if len(pcs) != len(rows)+1 || len(code) == 0 || code[len(code)-1] != 0xc3 {
		t.Fatal("original Go CLMUL row bytes/PCs incomplete")
	}
	for index, row := range rows {
		expected := row.code()
		if row.encoding != "legacy" {
			expected[2] &^= 0x80 // Go chooses W0; the independent LLVM22 oracle binds WIG.
		}
		if row.encoding == "evex" && row.width != 64 {
			expected[1] ^= 0x10 // The only difference in Go's forced high-bank witness is R'.
		}
		if !bytes.Equal(code[pcs[index]:pcs[index+1]], expected) {
			t.Fatal("independent original Go complete physical row changed", row.name(), code[pcs[index]:pcs[index+1]], expected)
		}
	}
}

func TestX86CLMULNativeCompletePhysicalGoDirectory(t *testing.T) {
	rows := x86CLMULNativeOriginCases()
	if len(rows) != 176 {
		t.Fatal("complete physical WIG/source/selector directory changed", len(rows))
	}
	x86CLMULNativeOriginRequireGoBytes(t, rows)
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range rows {
			t.Run(arch+"/"+row.name(), func(t *testing.T) {
				ins := x86RawMoveObservedInstruction(t, arch, row.code())
				form, known, err := x86CLMULProperties(ins.Op, ins, arch)
				if !known || err != nil || form.legacy != (row.encoding == "legacy") || form.byteWidth != row.width ||
					form.immediate != row.immediate || (form.memory >= 0) != row.memory || form.source != 1 {
					t.Fatal("valid physical CLMUL lost typed selected-qword and whole-memory roles", err)
				}
			})
		}
	}
}

func TestX86CLMULNativePhysicalBytesIndependentLLVM22(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc required")
	}
	var input strings.Builder
	rows := x86CLMULNativeOriginCases()
	for _, row := range rows {
		for _, value := range row.code() {
			fmt.Fprintf(&input, "0x%02x ", value)
		}
		input.WriteByte('\n')
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "x86_64-unknown-linux-gnu"} {
		t.Run(triple, func(t *testing.T) {
			stage, cancel := runtimeOracleStageContext(t)
			defer cancel()
			command := exec.CommandContext(stage, mc, "--disassemble", "--triple="+triple,
				"--mattr=+pclmul,+avx,+avx512f,+avx512vl,+vpclmulqdq")
			command.Stdin = strings.NewReader(input.String())
			output, err := runtimeOracleCombinedOutput(stage, command)
			if err != nil || strings.Contains(string(output), "warning") || strings.Contains(string(output), "invalid") {
				t.Fatalf("independent complete physical CLMUL decoding failed: %v\n%s", err, output)
			}
			// LLVM may print one of Intel's four immediate aliases.
			if count := len(regexp.MustCompile(`\bv?pclmul[a-z]*dq[ \t]+`).FindAll(output, -1)); count != len(rows) {
				t.Fatalf("independent LLVM22 decoding lost physical CLMUL forms: %d\n%s", count, output)
			}
		})
	}
}

func x86CLMULNativeOriginSource(row x86CLMULNativeOriginCase, arch, control string, raw, dead, unused bool) (string, string) {
	word, move, suffix := goWordSize(arch), "MOVQ", "Q"
	if arch == "386" {
		move, suffix = "MOVL", "L"
	}
	extent, declaration := 3*word, "func Carryless(a,b,out *[144]byte)\n"
	if unused {
		extent++
		declaration = "func Carryless(a,b,out *[144]byte,unused bool)\n"
	}
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·Carryless(SB),4,$0-%d\n", extent)
	if control == "numeric address" {
		source.WriteString("MOVL $42,BX\n")
	} else if control != "address" {
		fmt.Fprintf(&source, "%s a+0(FP),BX\n", move)
	}
	fmt.Fprintf(&source, "%s b+%d(FP),AX\n%s out+%d(FP),DI\n", move, word, move, 2*word)
	if !row.memory && control != "first" {
		source.WriteString("VMOVUPS (BX),Z0\n")
	}
	if control != "second" {
		source.WriteString("VMOVUPS (AX),Z1\n")
	}
	source.WriteString("MOVL $3,CX\nCMPL CX,$3\nSTD\n")
	if raw {
		for _, value := range row.code() {
			fmt.Fprintf(&source, "BYTE $%d\n", value)
		}
	} else {
		source.WriteString(row.sourceInstruction(false) + "\n")
	}
	if !dead {
		destination := "Z2"
		if row.encoding == "legacy" {
			destination = "Z1"
		}
		fmt.Fprintf(&source, "VMOVUPS %s,(DI)\n", destination)
	}
	fmt.Fprintf(&source, "PUSHF%s\nPOP%s CX\nANDL $0xcd5,CX\nMOVL CX,128(DI)\nCLD\nRET\n", suffix, suffix)
	return source.String(), declaration
}

const x86CLMULNativeOriginBatchSize = 32

func TestX86CLMULNativeInitializedFiveTargetsBatch00(t *testing.T) {
	x86CLMULNativeOriginObjectBatch(t, 0)
}
func TestX86CLMULNativeInitializedFiveTargetsBatch01(t *testing.T) {
	x86CLMULNativeOriginObjectBatch(t, 1)
}
func TestX86CLMULNativeInitializedFiveTargetsBatch02(t *testing.T) {
	x86CLMULNativeOriginObjectBatch(t, 2)
}
func TestX86CLMULNativeInitializedFiveTargetsBatch03(t *testing.T) {
	x86CLMULNativeOriginObjectBatch(t, 3)
}
func TestX86CLMULNativeInitializedFiveTargetsBatch04(t *testing.T) {
	x86CLMULNativeOriginObjectBatch(t, 4)
}
func TestX86CLMULNativeInitializedFiveTargetsBatch05(t *testing.T) {
	x86CLMULNativeOriginObjectBatch(t, 5)
}

func x86CLMULNativeOriginObjectBatch(t *testing.T, batch int) {
	t.Helper()
	rows := x86CLMULNativeOriginCases()
	start, end := batch*x86CLMULNativeOriginBatchSize, (batch+1)*x86CLMULNativeOriginBatchSize
	if start < 0 || start >= len(rows) {
		t.Fatal("invalid complete CLMUL object batch", batch)
	}
	if end > len(rows) {
		end = len(rows)
	}
	rows = rows[start:end]
	x86CLMULNativeOriginRequireGoBytes(t, rows)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			for index, row := range rows {
				body, declaration := x86CLMULNativeOriginSource(row, target.arch, "", true, false, false)
				name := fmt.Sprint("Carryless", start+index)
				source.WriteString(strings.ReplaceAll(body, "Carryless", name))
				declarations.WriteString(strings.ReplaceAll(declaration, "Carryless", name))
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized original CLMUL lost its exact selected inputs, whole native tuple or defined FLAGS/DF", err)
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						compileLLVMToObject(t, llc, target.triple, "clmul-native-origin.ll", "clmul-native-origin.o", body)
					}
					x86PackedStringCompileObject(t, llc, target.triple, ir, "-O2")
				})
			}
		})
	}
}

func TestX86CLMULNativeNamedCompleteMemoryAndRegisterControls(t *testing.T) {
	for _, memory := range []bool{false, true} {
		t.Run(fmt.Sprint("memory", memory), func(t *testing.T) {
			var source, declarations strings.Builder
			index := 0
			for _, row := range x86CLMULNativeOriginCases() {
				if row.w || row.memory != memory || row.encoding == "evex" && row.width != 64 {
					continue // These named low banks select VEX; their physical EVEX controls are above.
				}
				body, declaration := x86CLMULNativeOriginSource(row, "amd64", "", false, false, false)
				name := fmt.Sprint("Carryless", index)
				index++
				source.WriteString(strings.ReplaceAll(body, "Carryless", name))
				declarations.WriteString(strings.ReplaceAll(declaration, "Carryless", name))
			}
			if index != 32 {
				t.Fatal("complete canonical named legacy/X/Y/Z controls changed", index)
			}
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					if ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", "x86_64-unknown-linux-gnu", api); ir == "" || err != nil {
						t.Fatal("complete same-source named CLMUL control failed", err)
					}
				})
			}
		})
	}
}

func TestX86CLMULNativeVoidAndUnusedBoolKeepInputRoles(t *testing.T) {
	for _, row := range x86CLMULNativeOriginCases() {
		for _, control := range []string{"first", "second", "address", "numeric address"} {
			if control == "first" && row.memory ||
				(control == "address" || control == "numeric address") && !row.memory {
				continue
			}
			t.Run(row.name()+"/"+control, func(t *testing.T) {
				for _, arch := range []string{"386", "amd64"} {
					for _, unused := range []bool{false, true} {
						// Unknown selected numerical bytes may propagate to dead
						// results. Native address obligations cannot be discarded.
						for _, dead := range []bool{false, true} {
							if dead && (control == "first" || control == "second") {
								continue
							}
							source, declaration := x86CLMULNativeOriginSource(row, arch, control, true, dead, unused)
							for _, api := range []string{"text", "module", "Go"} {
								if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, x86AddressMemoryTargets(arch)[0], api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("raw CLMUL invented a selected byte or native pointer role", arch, dead, unused, api, err)
								}
							}
						}
					}
				}
			})
		}
	}
}

func TestX86CLMULNativeInitializedUnusedBoolAndDeadForms(t *testing.T) {
	rows := x86CLMULNativeOriginCases()
	for start := 0; start < len(rows); start += x86CLMULNativeOriginBatchSize {
		end := start + x86CLMULNativeOriginBatchSize
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprint(start/x86CLMULNativeOriginBatchSize), func(t *testing.T) {
			for _, target := range x86RawReturnTargets {
				t.Run(target.triple, func(t *testing.T) {
					var source, declarations strings.Builder
					for index, row := range rows[start:end] {
						for _, dead := range []bool{false, true} {
							body, declaration := x86CLMULNativeOriginSource(row, target.arch, "", true, dead, true)
							name := fmt.Sprintf("Carryless%dDead%t", start+index, dead)
							source.WriteString(strings.ReplaceAll(body, "Carryless", name))
							declarations.WriteString(strings.ReplaceAll(declaration, "Carryless", name))
						}
					}
					x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							if ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api); err != nil || ir == "" {
								t.Fatal("unused bool or dead product changed valid original CLMUL inputs/native access", err)
							}
						})
					}
				})
			}
		})
	}
}
