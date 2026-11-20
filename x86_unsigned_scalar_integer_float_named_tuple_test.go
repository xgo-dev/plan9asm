package plan9asm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Follow only the actual native memory operand, not another offset or a comment
// elsewhere in the function. Base/index register loads are symbolic variables;
// this observer measures the constant displacement, never their numerical value.
func x86UnsignedScalarNativeDisplacement(t *testing.T, ir string) int64 {
	t.Helper()
	definitions := make(map[string]string)
	definition := regexp.MustCompile(`^\s*(%[-A-Za-z0-9._]+) = (.*)$`)
	argument := regexp.MustCompile(`ptr elementtype\(\[4 x i8\]\) (%[-A-Za-z0-9._]+)\)`)
	pointer, calls := "", 0
	for _, line := range strings.Split(ir, "\n") {
		if match := definition.FindStringSubmatch(line); match != nil {
			definitions[match[1]] = match[2]
		}
		if !strings.Contains(line, `asm sideeffect "vcvtusi2s`) {
			continue
		}
		calls++
		match := argument.FindStringSubmatch(line)
		if match == nil {
			t.Fatal("actual scalar memory opcode lost its exact m32 operand", line)
		}
		pointer = match[1]
	}
	if calls != 1 {
		t.Fatal("named-source displacement observer needs exactly one actual scalar native memory call", calls)
	}
	cast := regexp.MustCompile(`^inttoptr i64 (%[-A-Za-z0-9._]+) to ptr$`).FindStringSubmatch(definitions[pointer])
	if cast == nil {
		t.Fatal("actual scalar native memory pointer lost its original address expression", pointer, definitions[pointer])
	}
	add := regexp.MustCompile(`^add i64 (%[-A-Za-z0-9._]+), (%[-A-Za-z0-9._]+|-?[0-9]+)$`)
	var displacement func(string, int) int64
	displacement = func(value string, depth int) int64 {
		if depth > 16 {
			t.Fatal("native pointer expression exceeds this bounded independent fixture")
		}
		if number, err := strconv.ParseInt(value, 10, 64); err == nil {
			return number
		}
		if match := add.FindStringSubmatch(definitions[value]); match != nil {
			return displacement(match[1], depth+1) + displacement(match[2], depth+1)
		}
		if strings.HasPrefix(definitions[value], "load i64,") || strings.HasPrefix(definitions[value], "mul i64 ") {
			return 0 // Independently initialized symbolic base/index, not a literal offset.
		}
		t.Fatal("unmodeled native address expression in independent source fixture", value, definitions[value])
		return 0
	}
	return displacement(cast[1], 0)
}

func TestX86UnsignedScalarIntegerFloatNamed386QProducerDisplacements(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("named Go386 producer displacement prior requires LLVM22 llvm-mc")
	}
	offsets := []int64{0, 1, -1, 4, -4, 7, -7, 8, -8, 16, -16,
		1008, 1016, 1017, 1024, -1016, -1024, -1025, -1032}
	for _, op := range []string{"VCVTUSI2SDQ", "VCVTUSI2SSQ"} {
		for _, indexed := range []bool{false, true} {
			for _, offset := range offsets {
				t.Run(fmt.Sprintf("%s/indexed=%t/offset%d", op, indexed, offset), func(t *testing.T) {
					address := fmt.Sprintf("%d(BX)", offset)
					if indexed {
						address += "(SI*2)"
					}
					instruction := op + " " + address + ",X0,X1"
					code := x86OrderingHintGoBytes(t, "386", "TEXT actual(SB),4,$0-0\n"+instruction+"\nRET\n")
					if len(code) < 7 || code[0] != 0x62 || code[2]&0x80 == 0 || code[4] != 0x7b || code[len(code)-1] != 0xc3 {
						t.Fatal("actual Go producer lost its complete W1 scalar opcode and return", code)
					}
					modrm, displacementAt := code[5], 6
					if modrm&7 == 4 {
						displacementAt++ // The independent SIB input is retained.
					}
					actual, end := int64(0), displacementAt
					switch modrm >> 6 {
					case 0:
					case 1:
						actual, end = int64(int8(code[displacementAt]))*4, displacementAt+1
					case 2:
						if displacementAt+4 > len(code)-1 {
							t.Fatal("actual Go producer truncated its complete disp32", code)
						}
						actual, end = int64(int32(binary.LittleEndian.Uint32(code[displacementAt:]))), displacementAt+4
					default:
						t.Fatal("actual Go memory producer became a register", code)
					}
					if end != len(code)-1 {
						t.Fatal("independent complete original memory instruction has unaccounted bytes", code, end)
					}
					want := offset
					if offset != 0 && offset%8 == 0 && offset/8 >= -128 && offset/8 <= 127 {
						want = offset / 2 // Actual producer N8, independently observed physical N4.
					}
					if actual != want {
						t.Fatal("actual Go table producer changed its compressed/uncompressed boundary", code, actual, want)
					}
					var input strings.Builder
					for _, value := range code[:len(code)-1] {
						fmt.Fprintf(&input, "0x%02x ", value)
					}
					ctx, cancel := runtimeOracleStageContext(t)
					defer cancel()
					command := exec.CommandContext(ctx, mc, "--disassemble", "--triple=i386-unknown-linux-gnu", "--mattr=+avx512f")
					command.Stdin = strings.NewReader(input.String() + "\n")
					output, err := runtimeOracleCombinedOutput(ctx, command)
					prefix := ""
					if actual != 0 {
						prefix = fmt.Sprint(actual)
					}
					if err != nil || strings.Contains(string(output), "warning:") ||
						!strings.Contains(string(output), prefix+"(%ebx") || !strings.Contains(string(output), "vcvtusi2s") {
						t.Fatal("LLVM did not independently confirm the actual Go physical m32 address", err, string(output))
					}
					declaration := "func view(p *byte) uint32\n"
					source := x86ResultGPSIMDAdmissionSource(t, "386", declaration,
						"MOVL p+0(FP),BX\nMOVL $0,SI\nPXOR X0,X0\n"+instruction+"\nMOVL X1,AX\nMOVL AX,ret+RESULT(FP)")
					goAssemblerOracleOutput(t, "386", source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "386", "i386-unknown-linux-gnu", api)
							if actual != offset && ir == "" && errors.Is(err, ErrProbeNeedsContext) {
								return // Safe source-encoder Context, not a claimed numerical success.
							}
							if err != nil || ir == "" {
								t.Fatal("unambiguous initialized Go386 memory producer lost its numerical continuation", err)
							}
							if got := x86UnsignedScalarNativeDisplacement(t, ir); got != actual {
								t.Fatal("translation substituted the written source displacement for actual Go machine semantics", got, actual, instruction)
							}
						})
					}
				})
			}
		}
	}
}
