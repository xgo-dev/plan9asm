package plan9asm

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86ExplicitIMULCompleteGoOpcodeAttributes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	actual := regexp.MustCompile(`(?m)^\s*\{AIMUL(?:3)?[WLQ],.*$`).FindAllString(string(data), -1)
	expected := []string{
		`{AIMULL, yimul, Px, opBytes{0xf7, 05, 0x6b, 0x69, Pm, 0xaf}},`,
		`{AIMULQ, yimul, Pw, opBytes{0xf7, 05, 0x6b, 0x69, Pm, 0xaf}},`,
		`{AIMULW, yimul, Pe, opBytes{0xf7, 05, 0x6b, 0x69, Pm, 0xaf}},`,
		`{AIMUL3W, yimul3, Pe, opBytes{0x6b, 00, 0x69, 00}},`,
		`{AIMUL3L, yimul3, Px, opBytes{0x6b, 00, 0x69, 00}},`,
		`{AIMUL3Q, yimul3, Pw, opBytes{0x6b, 00, 0x69, 00}},`,
	}
	if len(actual) != len(expected) {
		t.Fatalf("actual Go explicit multiply directory changed: %v", actual)
	}
	for index, row := range actual {
		if strings.TrimSpace(row) != expected[index] {
			t.Fatalf("actual opcode/table/prefix/bytes changed: %s", row)
		}
	}
}

func TestX86ExplicitIMULSourceRegistrationAndExactMemoryShape(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, suffix := range []string{"W", "L", "Q"} {
			for _, row := range x86CallerExplicitIMULRows {
				instruction := strings.ReplaceAll(row.instruction, "@", suffix)
				t.Run(arch+"/"+instruction, func(t *testing.T) {
					accepted := arch != "386" || suffix != "Q"
					source := "TEXT ·Shape(SB),4,$0-0\n" + instruction + "\nRET\n"
					goAssemblerOracleOutput(t, arch, source, "", accepted)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					ins := file.Funcs[0].Instrs[1]
					if x86SourceStackInstructionKnown(ins, "MOVQ", "Q", arch) != accepted {
						t.Fatal("source registration disagrees with complete explicit Go form")
					}
					for index, operand := range ins.Args {
						if operand.Kind != OpMem {
							continue
						}
						width, write, valid := x86InstructionMemoryShape(ins, index, arch)
						if valid != accepted || accepted && (write || width != map[string]int64{"W": 2, "L": 4, "Q": 8}[suffix]) {
							t.Fatalf("exact native source width mismatch: %d %t %t", width, write, valid)
						}
						if accepted {
							x86CallerRecordMemory(&ins, index, width, false)
							if arch == "amd64" && !x86CallerMemoryCertified(ins, index) {
								t.Fatal("exact typed read cannot consume its instruction-local certificate")
							}
							ins.Args[index].Mem.Off++
							if x86CallerMemoryCertified(ins, index) {
								t.Fatal("edited read inherited the old memory certificate")
							}
						}
					}
					ins.Op += ".BAD"
					if x86SourceStackInstructionKnown(ins, "MOVQ", "Q", arch) {
						t.Fatal("constructed suffix acquired explicit IMUL registration")
					}
				})
			}
		}
	}
	for _, instruction := range []string{"IMULB AX", "IMULW AX", "IMULL AX", "IMULQ AX", "MULQ AX", "DIVQ AX", "IDIVQ AX"} {
		ins := x86YMMReadSource(t, instruction)
		if x86SourceStackInstructionKnown(ins, "MOVQ", "Q", "amd64") {
			t.Fatalf("implicit multiply/divide acquired explicit effects: %s", instruction)
		}
	}
}
