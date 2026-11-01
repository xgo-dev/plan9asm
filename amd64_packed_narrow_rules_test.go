package plan9asm

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestX86PackedNarrowMemoryShapeConsumesTheCompleteGrammar(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		rows := x86OfficialPackedNarrowRows(t, arch)
		for _, opcode := range []string{"PACKSSLW", "PACKSSWB", "PACKUSDW", "PACKUSWB"} {
			rows = append(rows, opcode+" (AX),X1")
			if arch == "amd64" && opcode != "PACKUSDW" {
				rows = append(rows, opcode+" (AX),M1")
			}
		}
		for _, row := range rows {
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			instruction := file.Funcs[0].Instrs[1]
			if instruction.Args[0].Kind != OpMem {
				continue
			}
			t.Run(arch+"/"+row, func(t *testing.T) {
				want := int64(amd64VectorByteWidth(instruction.Args[len(instruction.Args)-1].Reg))
				if _, mmx := amd64ParseMReg(instruction.Args[len(instruction.Args)-1].Reg); mmx {
					want = 8
				}
				if strings.Contains(row, ".BCST") {
					want = 4
				}
				width, write, valid := x86InstructionMemoryShape(instruction, 0, arch)
				if !valid || write || width != want {
					t.Fatalf("memory-shape consumer diverged from Go's pack grammar: %d/%t/%t, want %d/false/true", width, write, valid, want)
				}
				for index := 1; index < len(instruction.Args); index++ {
					if _, _, valid := x86InstructionMemoryShape(instruction, index, arch); valid {
						t.Fatal("non-memory operand received a memory envelope")
					}
				}
			})
		}
	}
}

func TestX86PackedNarrowRawWIGAttributesAndPhysicalMode32Masks(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM 22 llvm-mc required")
	}
	// Intel SDM Vol.2B PACK tables: VEX W is ignored; EVEX word-to-byte
	// ignores W, but EVEX dword-to-word requires W0. This independent table
	// deliberately does not copy the implementation's encoder attributes.
	for _, opcode := range []string{"VPACKSSDW", "VPACKSSWB", "VPACKUSDW", "VPACKUSWB"} {
		for _, width := range []string{"X", "Y", "Z"} {
			for _, evex := range []bool{false, true} {
				if !evex && width == "Z" {
					continue
				}
				row := opcode + " " + width + "1," + width + "2,"
				if evex {
					row += "K1,"
				}
				row += width + "3"
				original := assembleX87ControlBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
				original = original[:len(original)-1]
				if evex && original[0] != 0x62 || !evex && original[0] != 0xc4 && original[0] != 0xc5 {
					t.Fatal("actual Go encoder selected a different generation", row, original)
				}
				code := append([]byte(nil), original...)
				if code[0] == 0xc5 {
					// Expand the actual C5 prefix to C4 before changing its W bit.
					code = append([]byte{0xc4, code[1]&0x80 | 0x61, code[1] & 0x7f}, code[2:]...)
				}
				code[2] |= 0x80
				validW1 := !evex || opcode == "VPACKSSWB" || opcode == "VPACKUSWB"
				for _, arch := range []string{"amd64", "386"} {
					t.Run(arch+"/"+row, func(t *testing.T) {
						if validW1 {
							var encoded strings.Builder
							for _, value := range code {
								fmt.Fprintf(&encoded, "0x%02x ", value)
							}
							triple := "x86_64"
							if arch == "386" {
								triple = "i386"
							}
							ctx, cancel := runtimeOracleStageContext(t)
							command := exec.CommandContext(ctx, mc, "--disassemble", "--triple="+triple, "--mattr=+avx2,+avx512bw,+avx512vl")
							command.Stdin = strings.NewReader(encoded.String() + "\n")
							output, err := runtimeOracleCombinedOutput(ctx, command)
							cancel()
							if err != nil || !strings.Contains(string(output), strings.ToLower(opcode)) || strings.Contains(string(output), "warning:") {
								t.Fatalf("independent LLVM22 WIG identity: %x %v\n%s", code, err, output)
							}
						}
						got, size, matched, err := decodedX86VectorPackedSaturatingNarrowInstruction(code, map[string]int{"amd64": 64, "386": 32}[arch])
						if !matched || (err == nil) != validW1 || validW1 && size != len(code) {
							t.Fatalf("WIG/W0 family contract: %x known=%t bytes=%d error=%v valid=%t", code, matched, size, err, validW1)
						}
						if !validW1 {
							return
						}
						before := fmt.Sprintf("%#v", got)
						form, known, err := x86PackedNarrowProperties(got, arch)
						if !known || err != nil || form.byteWidth != amd64VectorByteWidth(Reg(width+"0")) {
							t.Fatal("physical raw input lost typed grammar", got, form, err)
						}
						copy := got
						if form2, _, err := x86PackedNarrowProperties(copy, arch); err != nil || !reflect.DeepEqual(form, form2) {
							t.Fatal("ordinary value copy lost private physical provenance", err)
						}
						if arch == "386" && evex {
							data, err := json.Marshal(got)
							if err != nil {
								t.Fatal(err)
							}
							var detached Instr
							if err := json.Unmarshal(data, &detached); err != nil {
								t.Fatal(err)
							}
							if _, _, err := x86PackedNarrowProperties(detached, arch); err == nil {
								t.Fatal("JSON fabricated Go-rejected mode32 source-mask authority")
							}
						}
						if before != fmt.Sprintf("%#v", got) {
							t.Fatal("grammar changed original decoded input")
						}
					})
				}
			}
		}
	}
}
