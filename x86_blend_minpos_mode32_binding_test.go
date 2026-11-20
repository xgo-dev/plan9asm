package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// The first minimum-position instruction fully defines its output. It must
// not manufacture a physical high-bank identity for the second instruction
// on mode32 merely because Go's named encoder accepts that spelling.
func x86BlendMinposBankProgram(arch string, registers []int) (string, string) {
	word, move := goWordSize(arch), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	var source, declarations strings.Builder
	for _, register := range registers {
		fmt.Fprintf(&source, "TEXT ·Bank%d(SB),4,$0-%d\n%s out+0(FP),DI\nPXOR X0,X0\n"+
			"VPHMINPOSUW X0,X%d\nVPHMINPOSUW X%d,X0\nMOVOU X0,(DI)\nRET\n",
			register, word, move, register, register)
		fmt.Fprintf(&declarations, "func Bank%d(out *[16]byte)\n", register)
	}
	return source.String(), declarations.String()
}

func x86BlendMinposFourOperandProgram(row x86BlendMinposCase, code []byte, arch string, raw bool) (string, string) {
	word, move := goWordSize(arch), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	var source strings.Builder
	fmt.Fprintf(&source, "TEXT ·Value(SB),4,$0-%d\n%s out+0(FP),DI\n%s input+%d(FP),BX\n", 2*word, move, move, word)
	for register := 0; register < 3; register++ {
		fmt.Fprintf(&source, "VXORPS %s%d,%s%d,%s%d\n", row.bank, register, row.bank, register, row.bank, register)
	}
	if raw {
		source.WriteString(x86RawDisplacementDirectives(code))
	} else {
		source.WriteString(row.instruction() + "\n")
	}
	fmt.Fprintf(&source, "VMOVUPS %s3,(DI)\nRET\n", row.bank)
	return source.String(), "func Value(out,input *[32]byte)\n"
}

func TestX86BlendMinposMode32NamedFourOperandCannotBorrowPhysicalRaw(t *testing.T) {
	var rows []x86BlendMinposCase
	for _, row := range x86BlendMinposCanonicalRows() {
		if !row.legacy && !row.minimum {
			rows = append(rows, row)
		}
	}
	if len(rows) != 12 {
		t.Fatal("complete three-name X/Y register/memory named/raw partition changed")
	}
	codes := x86BlendMinposOriginalCodes(t, rows)
	var input strings.Builder
	for index, row := range rows {
		named, _ := x86BlendMinposFourOperandProgram(row, nil, "386", false)
		goAssemblerOracleOutput(t, "386", named, "", false)
		for _, value := range codes[index] {
			fmt.Fprintf(&input, "0x%02x ", value)
		}
		input.WriteByte('\n')
		x86HandoffOriginalBytes(t, "386", codes[index])
	}
	mc, llc := findLLVM22Tool("llvm-mc"), findLLVM22Tool("llc")
	if mc == "" || llc == "" {
		t.Fatal("genuine physical low-bank VEX prior and complete objects require LLVM22 llvm-mc/llc")
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "x86_64-unknown-linux-gnu"} {
		stage, cancel := runtimeOracleStageContext(t)
		command := exec.CommandContext(stage, mc, "--disassemble", "--triple="+triple, "--mattr=+avx2")
		command.Stdin = strings.NewReader(input.String())
		output, err := runtimeOracleCombinedOutput(stage, command)
		cancel()
		if err != nil || strings.Contains(string(output), "warning") || strings.Contains(string(output), "invalid") {
			t.Fatalf("independent low-bank VEX physical prior: %v\n%s", err, output)
		}
		for _, name := range []string{"vblendvps", "vblendvpd", "vpblendvb"} {
			count := 0
			for _, line := range strings.Split(string(output), "\n") {
				fields := strings.Fields(line)
				if len(fields) != 0 && fields[0] == name {
					count++
				}
			}
			if count != 4 {
				t.Fatal("LLVM22 lost complete X/Y register/memory physical rows", triple, name, count, string(output))
			}
		}
	}
	// Complete initialized positive batches retain AMD64's named grammar
	// and mode32's genuinely decoded physical instruction independently.
	for _, arch := range []string{"386", "amd64"} {
		raw := arch == "386"
		triple := "x86_64-unknown-linux-gnu"
		if raw {
			triple = "i386-unknown-linux-gnu"
		}
		var source, declarations strings.Builder
		for index, row := range rows {
			body, declaration := x86BlendMinposFourOperandProgram(row, codes[index], arch, raw)
			name := fmt.Sprintf("Variant%d", index)
			source.WriteString(strings.Replace(body, "·Value(SB)", "·"+name+"(SB)", 1))
			declarations.WriteString(strings.Replace(declaration, "Value(", name+"(", 1))
		}
		x86LEAActualTargetGoObject(t, arch, triple, source.String())
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/positive/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
				if err != nil || ir == "" {
					t.Fatal("actual physical/raw or legal AMD64 named initialized family failed", err)
				}
				compileLLVMToObject(t, llc, triple, "bound-four-operand.ll", "bound-four-operand.o", ir)
			})
		}
	}
	for index, row := range rows {
		t.Run(row.instruction(), func(t *testing.T) {
			named, declaration := x86BlendMinposFourOperandProgram(row, nil, "386", false)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, named, declaration, "386", "i386-unknown-linux-gnu", api)
					if err == nil || ir != "" {
						t.Fatal("Go-invalid mode32 named grammar borrowed physical raw permission", err)
					}
				})
			}
			t.Run("typed-named-grammar", func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction())
				if _, known, err := x86BlendMinposProperties(ins.Op, ins, "386"); !known || err == nil {
					t.Fatal("typed named grammar accepted Go-rejected mode32 four operands", err)
				}
			})
			t.Run("physical-identity-replay", func(t *testing.T) {
				source, declaration := x86BlendMinposFourOperandProgram(row, codes[index], "386", true)
				file, err := normalizeX86RawFile(mustParseX86RawReturn(t, source), "386")
				if err != nil || len(file.Funcs) != 1 || file.Funcs[0].x86RawReplay == nil {
					t.Fatal("complete physical source lacks its original replay", err)
				}
				candidate := file.Funcs[0]
				candidate.Instrs = cloneX86ReplayInstrs(candidate.Instrs)
				changed := 0
				for at := range candidate.Instrs {
					if candidate.Instrs[at].Op == Op(row.op) {
						candidate.Instrs[at].x86Encoded = !candidate.Instrs[at].x86Encoded
						changed++
					}
				}
				if changed != 1 {
					t.Fatal("physical source target inventory changed", changed)
				}
				check := x86LegacyFloatReplayCheck(t, "386", source, declaration)
				if err := check(candidate); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("edited physical/named projection acquired original source permission", err)
				}
			})
		})
	}
}

func TestX86BlendMinposMode32HighNamedNeedsPhysicalBinding(t *testing.T) {
	registers := []int{8, 9, 10, 11, 12, 13, 14, 15}
	complete, _ := x86BlendMinposBankProgram("386", registers)
	// A successful real Go object is only a frontend premise, not evidence
	// that physical mode32 has distinct X8-X15 registers.
	x86LEAActualTargetGoObject(t, "386", "i386-unknown-linux-gnu", complete)
	for _, register := range registers {
		t.Run(fmt.Sprintf("X%d", register), func(t *testing.T) {
			source, declarations := x86BlendMinposBankProgram("386", []int{register})
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "386", "i386-unknown-linux-gnu", api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("initialized numerical bytes acquired an unbound physical mode32 vector identity", err)
					}
				})
			}
			for _, instruction := range []string{fmt.Sprintf("VPHMINPOSUW X0,X%d", register), fmt.Sprintf("VPHMINPOSUW X%d,X0", register)} {
				t.Run(instruction, func(t *testing.T) {
					ins := x86ScalarLaneInstruction(t, instruction)
					if _, known, err := x86BlendMinposProperties(ins.Op, ins, "386"); !known || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("typed grammar confused Go-accepted spelling with a physical mode32 binding", err)
					}
				})
			}
		})
	}
}

func TestX86BlendMinposSameHighNamedAMD64StillWorks(t *testing.T) {
	source, declarations := x86BlendMinposBankProgram("amd64", []int{8, 9, 10, 11, 12, 13, 14, 15})
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("same initialized AMD64 high bank requires LLVM22 object compilation")
	}
	for _, target := range x86AddressMemoryTargets("amd64") {
		t.Run(target, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", target, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", target, api)
					if err != nil || ir == "" {
						t.Fatal("physical AMD64 high bank regressed to mode32 Context", err)
					}
					compileLLVMToObject(t, llc, target, "high-bank.ll", "high-bank.o", ir)
				})
			}
		})
	}
}

func TestX86BlendMinposLowBankPhysicalAndInitializedFiveTargets(t *testing.T) {
	registers := []int{0, 1, 2, 3, 4, 5, 6, 7}
	var body strings.Builder
	for _, register := range registers {
		fmt.Fprintf(&body, "VPHMINPOSUW X0,X%d\nVPHMINPOSUW X%d,X0\n", register, register)
	}
	code, pcs := x86NumericalBoundaryGoBytes(t, "386", body.String()+"RET")
	if len(pcs) != 17 || len(code) == 0 || code[len(code)-1] != 0xc3 {
		t.Fatal("actual Go mode32 low-bank directory is incomplete")
	}
	for index, register := range registers {
		for direction, modrm := range []byte{0xc0 | byte(register)<<3, 0xc0 | byte(register)} {
			at := 2*index + direction
			want := []byte{0xc4, 0xe2, 0x79, 0x41, modrm}
			if !bytes.Equal(code[pcs[at]:pcs[at+1]], want) {
				t.Fatal("Go bytes differ from independent VEX.128.66.0F38.W0 NOVSR low-bank fields", register, direction)
			}
		}
	}
	x86HandoffOriginalBytes(t, "386", code)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("initialized physical low-bank objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86BlendMinposBankProgram(target.arch, registers)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("initialized physically bound low-bank producer failed", err)
					}
					compileLLVMToObject(t, llc, target.triple, "low-bank.ll", "low-bank.o", ir)
				})
			}
		})
	}
}
