package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// The ratios and 20..25 opcodes come from PMOVSX in the Intel/Go tables,
// independently of both production membership and zero-extension results.
var x86PackedSignExtendOracleRatios = []struct {
	suffix        string
	input, output int
}{
	{"BW", 1, 2}, {"BD", 1, 4}, {"BQ", 1, 8},
	{"WD", 2, 4}, {"WQ", 2, 8}, {"DQ", 4, 8},
}

func TestX86PackedSignExtendCompleteOfficialRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]int)
	for index, ratio := range x86PackedSignExtendOracleRatios {
		opcode := 0x20 + index
		legacy := "PMOVSX" + ratio.suffix
		if !strings.Contains(string(data), fmt.Sprintf("{A%s, yxm_q4, Pq4, opBytes{0x%02x}}", legacy, opcode)) {
			t.Fatal("original legacy sign-extension row changed", legacy)
		}
		member := "V" + legacy
		table := "_yvbroadcastss"
		if ratio.output == 2*ratio.input {
			table = "_yvcvtdq2pd"
		}
		var bytes []string
		for _, bits := range []int{128, 256} {
			bytes = append(bytes, fmt.Sprintf("avxEscape | vex%d | vex66 | vex0F38 | vexW0", bits), fmt.Sprintf("0x%02x", opcode))
		}
		for _, bits := range []int{128, 256, 512} {
			bytes = append(bytes, fmt.Sprintf("avxEscape | evex%d | evex66 | evex0F38 | evexW0", bits),
				fmt.Sprintf("evexN%d | evexZeroingEnabled", bits/8*ratio.input/ratio.output), fmt.Sprintf("0x%02x", opcode))
		}
		for _, rule := range rules {
			if rule.Opcode != member {
				continue
			}
			row := counts[member]
			if row > 7 || rule.RowIndex != row || rule.Ytab != table || rule.Prefix != "Pavx" ||
				rule.EncodingOffset != []int{0, 2, 4, 4, 7, 7, 10, 10}[row] ||
				rule.ZOffset != []int{2, 2, 0, 3, 0, 3, 0, 3}[row] || !reflect.DeepEqual(rule.OpBytes, bytes) {
				t.Fatal("complete signed widening encoding/tuple attributes changed", member, rule)
			}
			classes, zcase := []string{"Yxm", "Yxr"}, "Zvex_rm_v_r"
			if row == 1 {
				classes[1] = "Yyr"
			} else if row >= 2 {
				classes = []string{"YxmEvex", []string{"YxrEvex", "YyrEvex", "Yzr"}[(row-2)/2]}
				if row >= 6 && ratio.output == 2*ratio.input {
					classes[0] = "YymEvex"
				}
				zcase = "Zevex_rm_v_r"
				if row%2 == 1 {
					classes = []string{classes[0], "Yknot0", classes[1]}
					zcase = "Zevex_rm_k_r"
				}
			}
			if rule.ZCase != zcase || !reflect.DeepEqual(rule.Classes, classes) {
				t.Fatal("complete signed widening operand row changed", member, rule)
			}
			counts[member]++
		}
		if counts[member] != 8 {
			t.Fatal("complete eight-row VEX/EVEX denominator changed", member, counts[member])
		}
	}
	for _, arch := range []string{"386", "amd64"} {
		var source strings.Builder
		source.WriteString("TEXT Prior(SB),4,$0-0\n")
		for _, ratio := range x86PackedSignExtendOracleRatios {
			for _, prefix := range []string{"P", "VP"} {
				// Reuse only the independently specified operand-shape generator;
				// sign-byte dependencies below are not copied from MOVZX.
				for _, row := range x86ZeroExtendAcceptedForms(prefix+"MOVSX"+ratio.suffix, arch) {
					fmt.Fprintln(&source, row)
				}
			}
		}
		source.WriteString("RET\n")
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
	}
}

func TestX86PackedSignExtendEveryByteAndUpperAliases(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, ratio := range x86PackedSignExtendOracleRatios {
			for _, prefix := range []string{"P", "VP"} {
				for _, bank := range []string{"X", "Y", "Z"} {
					if prefix == "P" && bank != "X" {
						continue
					}
					width, sourceBank := map[string]int{"X": 16, "Y": 32, "Z": 64}[bank], "X"
					if width*ratio.input/ratio.output > 16 {
						sourceBank = "Y"
					}
					modes := []string{"plain"}
					if prefix == "VP" {
						modes = append(modes, "merge", "zero")
					}
					for _, mode := range modes {
						name, mask := prefix+"MOVSX"+ratio.suffix, ""
						if mode != "plain" {
							mask = "K1,"
						}
						if mode == "zero" {
							name += ".Z"
						}
						for _, destination := range []int{0, 1} {
							row := fmt.Sprintf("%s %s0,%s%s%d", name, sourceBank, mask, bank, destination)
							t.Run(arch+"/"+row, func(t *testing.T) {
								ins := x86ScalarLaneInstruction(t, row)
								effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
								if !known || err != nil || !effect.requiresResultProof ||
									effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 {
									t.Fatal("signed widening lacks its independent typed input obligation", known, err)
								}
								for input := 0; input < 3; input++ {
									for missing := -1; missing < 64; missing++ {
										state := x86FMA3ResultInputState()
										if missing >= 0 {
											state.writeVector(input, 64, state.vectorBytes(input)&^(uint64(1)<<uint(missing)), false)
										}
										before := state.clone()
										var defined uint64
										for output := 0; output < width; output++ {
											part := output % ratio.output
											if part >= ratio.input {
												part = ratio.input - 1 // Every high byte depends on the sign byte.
											}
											at := output/ratio.output*ratio.input + part
											available := before.vectorBytes(0)>>uint(at)&1 != 0
											if mode == "merge" {
												available = available && before.vectorBytes(destination)>>uint(output)&1 != 0
											}
											if available {
												defined |= uint64(1) << uint(output)
											}
										}
										want := before.clone()
										want.writeVector(destination, width, defined, prefix == "P")
										if !x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, want) {
											t.Fatal("sign extension invented a sign byte or changed aliases/FLAGS/storage", input, missing)
										}
									}
								}
							})
						}
					}
				}
			}
		}
	}
}

func TestX86PackedSignExtendOriginalCompletePrograms(t *testing.T) {
	data, err := os.ReadFile("testdata/conformance/amd64/conformance_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range []struct{ name, declaration string }{
		{"packedSignExtendMoveVEXSemantics", "func packedSignExtendMoveVEXSemantics(out *[288]byte,src *[32]byte)"},
		{"packedSignExtendMoveMaskSemantics", "func packedSignExtendMoveMaskSemantics(out *[768]byte,src,old *[64]byte)"},
	} {
		t.Run(member.name, func(t *testing.T) {
			start := strings.Index(string(data), "TEXT ·"+member.name+"(SB)")
			if start < 0 {
				t.Fatal("original signed widening entry missing")
			}
			end := strings.Index(string(data[start:]), "\n\tRET\n")
			if end < 0 {
				t.Fatal("original complete signed widening return missing")
			}
			x86PackedFaultProgramObjects(t, "#include \"textflag.h\"\n"+string(data[start:start+end+len("\n\tRET\n")]), member.declaration)
		})
	}
}
