package plan9asm

import (
	"fmt"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func x86PackedShiftRawDecode(code []byte, mode int) (Instr, int, bool, error) {
	for _, decode := range []func([]byte, int) (Instr, int, bool, error){
		decodedX86PerLaneVariableShiftInstruction,
		decodedX86PackedUniformShiftInstruction,
		decodedX86RawVectorByteShiftInstruction,
	} {
		if ins, consumed, known, err := decode(code, mode); known {
			return ins, consumed, known, err
		}
	}
	return Instr{}, 0, false, nil
}

func TestX86PackedShiftRawCompletePhysicalLLVM22AndWIG(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("independent packed-shift WIG validation requires LLVM22 llvm-mc")
	}
	var rows []x86PackedShiftRawCase
	var input strings.Builder
	wantMnemonics := map[string]int{}
	for _, row := range x86PackedShiftRawCases() {
		values := []bool{false}
		if row.wig() && !row.llvm22WordCountWIGGap() {
			rows = append(rows, row)
			values = append(values, true)
		}
		for _, w := range values {
			for _, value := range row.code(w) {
				fmt.Fprintf(&input, "0x%02x ", value)
			}
			input.WriteByte('\n')
			wantMnemonics[strings.ToLower(row.member.op)]++
		}
	}
	if len(rows) != 118 || len(wantMnemonics) != 20 {
		t.Fatal("complete uniform-word/byte WIG directory changed", len(rows), len(wantMnemonics))
	}
	count := 0
	for _, expected := range wantMnemonics {
		count += expected
	}
	if count != 796 {
		t.Fatal("complete LLVM22-positive physical row denominator changed", count)
	}
	for _, mode := range []int{32, 64} {
		triple := map[int]string{32: "i386-unknown-linux-gnu", 64: "x86_64-unknown-linux-gnu"}[mode]
		t.Run(triple, func(t *testing.T) {
			// An external decoder must recognize all 796 positive bytes first.
			// The 54 valid-but-unrecognized word-count W1 forms have a separate
			// one-instruction receipt below; none enters this positive batch.
			// Go choosing W0 is not evidence that W1 is an invalid instruction.
			stage, cancel := runtimeOracleStageContext(t)
			command := exec.CommandContext(stage, mc, "--disassemble", "--triple="+triple,
				"--mattr=+avx,+avx2,+avx512f,+avx512bw,+avx512vl")
			command.Stdin = strings.NewReader(input.String())
			output, err := runtimeOracleCombinedOutput(stage, command)
			cancel()
			if err != nil || strings.Contains(string(output), "warning") || strings.Contains(string(output), "invalid") {
				t.Fatalf("independent LLVM22 rejected complete WIG source bytes: %v\n%s", err, output)
			}
			for mnemonic, want := range wantMnemonics {
				if got := len(regexp.MustCompile(`(?m)\b`+mnemonic+`[ \t]+`).FindAll(output, -1)); got != want {
					t.Fatalf("independent LLVM22 WIG row count for %s: %d != %d\n%s", mnemonic, got, want, output)
				}
			}
			for _, row := range rows {
				t.Run(row.name(), func(t *testing.T) {
					var control Instr
					for _, w := range []bool{false, true} {
						code := row.code(w)
						ins, consumed, known, err := x86PackedShiftRawDecode(code, mode)
						if !known || err != nil || consumed != len(code) {
							t.Fatal("ISA WIG does not close the complete typed shift grammar", w, known, consumed, err)
						}
						generation := x86RawPackedShiftVEX
						if row.evex {
							generation = x86RawPackedShiftEVEX
						}
						if !ins.x86Encoded || ins.x86PackedShiftEncoding != generation || ins.x86PackedShiftW != w {
							t.Fatal("ignored W lost its actual physical generation or bit", w, ins.x86PackedShiftEncoding, ins.x86PackedShiftW)
						}
						if !w {
							control = ins
						} else if ins.Op != control.Op || !reflect.DeepEqual(ins.Args, control.Args) {
							t.Fatal("ignored W changed the original shift's semantic operands", ins.Raw, control.Raw)
						}
					}
				})
			}
		})
	}
}

func (row x86PackedShiftRawCase) llvm22WordCountWIGGap() bool {
	return row.evex && row.member.mode == "uniform" && row.member.bits == 16 && !row.immediate
}

func x86PackedShiftRawSingleMC(t *testing.T, mc, triple string, code []byte) string {
	t.Helper()
	var input strings.Builder
	for _, value := range code {
		fmt.Fprintf(&input, "0x%02x ", value)
	}
	input.WriteByte('\n')
	stage, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(stage, mc, "--disassemble", "--triple="+triple,
		"--mattr=+avx,+avx2,+avx512f,+avx512bw,+avx512vl")
	command.Stdin = strings.NewReader(input.String())
	output, err := runtimeOracleCombinedOutput(stage, command)
	cancel()
	if err != nil {
		t.Fatalf("independent one-instruction LLVM22 observation: %v\n%s", err, output)
	}
	return string(output)
}

func TestX86PackedShiftRawSDMWordCountWIGAndLLVM22Difference(t *testing.T) {
	// Intel SDM 325462-089 Vol.2B 4-443..445 and Intel XED's
	// datafiles/avx512-skx/skx-isa.xed.txt specify EVEX.WIG F1/D1/E1.
	// LLVM22 X86InstrAVX512.td avx512_shift_types omits WIG on its W
	// count branch, although avx512_shift_rmi_w has it. Observe that exact
	// external decoder difference separately; it is never a positive LLVM
	// witness or a justification to drop these 54 valid physical shapes.
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("independent word-count WIG observations require LLVM22 llvm-mc")
	}
	var rows []x86PackedShiftRawCase
	for _, row := range x86PackedShiftRawCases() {
		if row.llvm22WordCountWIGGap() {
			rows = append(rows, row)
		}
	}
	if len(rows) != 54 {
		t.Fatal("complete external word-count WIG difference denominator changed", len(rows))
	}
	for _, mode := range []int{32, 64} {
		triple := map[int]string{32: "i386-unknown-linux-gnu", 64: "x86_64-unknown-linux-gnu"}[mode]
		for _, row := range rows {
			t.Run(triple+"/"+row.name(), func(t *testing.T) {
				mnemonic := regexp.MustCompile(`(?m)\b` + strings.ToLower(row.member.op) + `[ \t]+`)
				control := x86PackedShiftRawSingleMC(t, mc, triple, row.code(false))
				if strings.Contains(control, "warning") || strings.Contains(control, "invalid") ||
					len(mnemonic.FindAllString(control, -1)) != 1 {
					t.Fatal("independent fresh-process W0 prerequisite failed", control)
				}
				observation := x86PackedShiftRawSingleMC(t, mc, triple, row.code(true))
				if !strings.Contains(observation, "warning: invalid instruction encoding") ||
					strings.Contains(observation, "error:") || mnemonic.MatchString(observation) {
					t.Fatal("LLVM22 word-count W1 difference changed; audit the independent decoder before updating this receipt", observation)
				}
				// A fresh process contains exactly this six-byte instruction. Its
				// warning cannot desynchronize the subsequent W0/other-family rows.
				if len(row.code(true)) != 6 {
					t.Fatal("external decoder difference grew beyond its exact instruction")
				}
				var named Instr
				for _, w := range []bool{false, true} {
					code := row.code(w)
					ins, consumed, known, err := x86PackedShiftRawDecode(code, mode)
					if !known || err != nil || consumed != len(code) {
						t.Fatal("SDM/XED word-count WIG source is missing from the complete decoder", w, known, consumed, err)
					}
					if !ins.x86Encoded || ins.x86PackedShiftEncoding != x86RawPackedShiftEVEX || ins.x86PackedShiftW != w {
						t.Fatal("word-count WIG lost its original EVEX/W physical snapshot", w, ins.x86PackedShiftEncoding, ins.x86PackedShiftW)
					}
					if !w {
						named = ins
					} else if ins.Op != named.Op || !reflect.DeepEqual(ins.Args, named.Args) {
						t.Fatal("ignored word-count W changed its exact semantic operands")
					}
				}
			})
		}
	}
}

func TestX86PackedShiftRawPhysicalRestrictionsStayLocal(t *testing.T) {
	for _, row := range x86PackedShiftRawCases() {
		if row.input != "register" || row.mask != 0 {
			continue
		}
		t.Run(row.name(), func(t *testing.T) {
			valid := row.code(false)
			if _, consumed, known, err := x86PackedShiftRawDecode(valid, 32); !known || err != nil || consumed != len(valid) {
				t.Fatal("legitimate low-bank mode32 physical shift rejected", err)
			}
			controls := map[string][]byte{
				"address-override": append([]byte{0x67}, valid...),
				"truncated":        append([]byte(nil), valid[:len(valid)-1]...),
			}
			if row.evex {
				for _, name := range []string{"fixed-bit", "reserved-length", "zero-without-mask", "physical-register8"} {
					code := append([]byte(nil), valid...)
					switch name {
					case "fixed-bit":
						code[2] &^= 4
					case "reserved-length":
						code[3] |= 0x60
					case "zero-without-mask":
						code[3] |= 0x80
					case "physical-register8":
						code[1] &^= 0x20 // ModRM.r/m is physically register8.
					}
					controls[name] = code
				}
			} else {
				code := append([]byte(nil), valid...)
				code[1] &^= 0x20
				controls["physical-register8"] = code
				if row.immediate {
					code := append([]byte(nil), valid...)
					code[4] = row.member.group<<3 | 3
					controls["VEX-immediate-memory"] = code
				}
			}
			if row.member.mode == "lane" && row.member.bits == 16 {
				code := append([]byte(nil), valid...)
				code[2] &^= 0x80
				controls["per-lane-word-W0"] = code
			}
			if row.member.mode == "bytes" && row.evex {
				code := append([]byte(nil), valid...)
				code[3] |= 1
				controls["byte-shift-mask"] = code
			}
			for name, code := range controls {
				if _, _, known, err := x86PackedShiftRawDecode(code, 32); known && err == nil {
					t.Fatal("malformed or unavailable physical shift became valid", name, code)
				}
			}
		})
	}
}
