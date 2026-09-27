package plan9asm

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

type arm64RawStructureCase struct {
	op, arrangement, syntax string
	word                    uint32
	count, bits, lanes      int
	base, first, post       int // post: 0 = none, 1 = fixed, 2 = register
	load, replicate         bool
}

// Enumerate the complete cmd/internal/obj/arm64/asm7.go C_LIST family:
// load rows 81, store rows 84, and maskOpvldvst's opcode/count mapping.
// Do not use the production decoder to construct its own expected answers.
func arm64RawStructureCases() []arm64RawStructureCase {
	var cases []arm64RawStructureCase
	for _, load := range []bool{false, true} {
		for _, replicate := range []bool{false, true} {
			if replicate && !load {
				continue
			}
			for structure := 1; structure <= 4; structure++ {
				for count := 1; count <= 4; count++ {
					if (replicate || structure != 1) && count != structure {
						continue
					}
					for _, arrangement := range []string{"B8", "B16", "H4", "H8", "S2", "S4", "D1", "D2"} {
						if arrangement == "D1" && !replicate && structure != 1 {
							continue // reserved multiple-structure Q=0, size=3
						}
						bits := map[byte]int{'B': 8, 'H': 16, 'S': 32, 'D': 64}[arrangement[0]]
						lanes, _ := strconv.Atoi(arrangement[1:])
						for _, registers := range [][2]int{{3, 25}, {31, 30}} {
							for post := 0; post < 3; post++ {
								base, first := registers[0], registers[1]
								op := fmt.Sprintf("VST%d", structure)
								word := uint32(0x0c000000)
								if load {
									op = fmt.Sprintf("VLD%d", structure)
									word |= 1 << 22
								}
								if replicate {
									op += "R"
									word = 0x0d40c000 | uint32((count-1)%2)<<21 | uint32((count-1)/2)<<13
								} else if structure == 1 {
									word |= map[int]uint32{1: 7, 2: 10, 3: 6, 4: 2}[count] << 12
								} else {
									word |= map[int]uint32{2: 8, 3: 4, 4: 0}[structure] << 12
								}
								if bits*lanes == 128 {
									word |= 1 << 30
								}
								word |= map[int]uint32{8: 0, 16: 1, 32: 2, 64: 3}[bits]<<10 | uint32(base)<<5 | uint32(first)
								baseName := fmt.Sprintf("R%d", base)
								if base == 31 {
									baseName = "RSP"
								}
								memory := "(" + baseName + ")"
								suffix := ""
								if post != 0 {
									suffix = ".P"
									word |= 1 << 23
									if post == 1 {
										word |= 31 << 16
										increment := count * bits * lanes / 8
										if replicate {
											increment = count * bits / 8
										}
										memory = strconv.Itoa(increment) + memory
									} else {
										word |= 7 << 16
										memory += "(R7)"
									}
								}
								list := arm64TestVectorList(first, count, arrangement)
								syntax := op + suffix + " " + list + ", " + memory
								if load {
									syntax = op + suffix + " " + memory + ", " + list
								}
								cases = append(cases, arm64RawStructureCase{op, arrangement, syntax, word, count, bits, lanes, base, first, post, load, replicate})
							}
						}
					}
				}
			}
		}
	}
	return cases
}

func TestARM64RawStructureReportedVST4(t *testing.T) {
	const source = "TEXT rawStructureReported(SB),$0-0\nWORD $0x0c9f0079\nRET\n"
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", Sigs: map[string]FuncSig{
		"rawStructureReported": {Name: "rawStructureReported", Ret: Void},
	}}); err != nil {
		t.Fatal(err)
	}
}

func TestARM64RawStructureRejectsReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x0c018079, // Rm is reserved without post-indexing.
		0x0c008c79, // ST2 with Q=0 and size=3 is reserved.
		0x0c208079, // Reserved bit 21 in the multiple-structure space.
	} {
		if decoded, err := decodeARM64RawWordInstruction(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}}); err == nil {
			t.Fatalf("decoded reserved structure encoding %#08x as %s", word, decoded.Raw)
		}
	}
	// Bit 29 selects the adjacent vector-pair instruction space, not an
	// invalid structure encoding. It must retain its own opcode and grammar.
	decoded, err := decodeARM64RawWordInstruction(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: 0x2c008079}}})
	if err != nil || decoded.Op != "VSTNP" {
		t.Fatalf("adjacent vector-pair decoding = %s, %v; want VSTNP", decoded.Raw, err)
	}
}

func TestARM64RawStructureCompleteGoForms(t *testing.T) {
	cases := arm64RawStructureCases()
	var named, raw strings.Builder
	named.WriteString("TEXT rawStructureForms(SB),$0-0\n")
	raw.WriteString("TEXT rawStructureForms(SB),$0-0\n")
	for _, test := range cases {
		fmt.Fprintln(&named, test.syntax)
		fmt.Fprintf(&raw, "WORD $%#08x\n", test.word)
	}
	named.WriteString("RET\n")
	raw.WriteString("RET\n")
	// These forms predate Go 1.20, so use each compatibility lane's real
	// assembler. Checking WORD acceptance alone cannot validate an encoding.
	code := assembleARM64StructureTestBytes(t, named.String())
	if len(code) < 4*(len(cases)+1) {
		t.Fatalf("Go assembler emitted %d bytes for %d instructions", len(code), len(cases)+1)
	}
	for i, test := range cases {
		if got := binary.LittleEndian.Uint32(code[4*i:]); got != test.word {
			t.Fatalf("Go encoded %s as %#08x, fixture expected %#08x", test.syntax, got, test.word)
		}
	}
	file, err := Parse(ArchARM64, named.String())
	if err != nil {
		t.Fatal(err)
	}
	for i, test := range cases {
		got, err := decodeARM64RawWordInstruction(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(test.word)}}})
		if err != nil {
			t.Fatalf("decode %s (%#08x): %v", test.syntax, test.word, err)
		}
		want := file.Funcs[0].Instrs[i+1]
		if got.Op != want.Op || !reflect.DeepEqual(got.Args, want.Args) {
			t.Fatalf("decode %#08x = %s %+v; want %s %+v", test.word, got.Op, got.Args, want.Op, want.Args)
		}
	}
	t.Logf("checked %d exact Go encodings and typed operand forms", len(cases))
	file, err = Parse(ArchARM64, raw.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{
				"rawStructureForms": {Name: "rawStructureForms", Ret: Void},
			}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-structure.ll", "raw-structure.o", ir)
		})
	}
}

func assembleARM64StructureTestBytes(t *testing.T, source string) []byte {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "forms.s")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "tool", "asm", "-S", "-o", filepath.Join(dir, "forms.o"), path)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Go assembler rejected structure family: %v\n%s", err, out)
	}
	var code []byte
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "0x") || len(fields[1]) != 2 {
			continue
		}
		offset, err := strconv.ParseUint(fields[0][2:], 16, 32)
		if err != nil || int(offset) != len(code) {
			t.Fatalf("noncontiguous Go instruction bytes: %s", line)
		}
		for _, field := range fields[1:] {
			if len(field) != 2 {
				break
			}
			value, err := strconv.ParseUint(field, 16, 8)
			if err != nil {
				break
			}
			code = append(code, byte(value))
		}
	}
	return code
}

func TestARM64RawStructureRuntimeSemantics(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	if runtime.GOARCH != "arm64" || (runtime.GOOS != "darwin" && runtime.GOOS != "linux") {
		t.Skip("native structure execution requires a Darwin or Linux ARM64 host; the complete object matrix runs on every host")
	}
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	for i, test := range arm64RawStructureCases() {
		if test.base != 3 {
			continue // SP and wraparound are covered by the all-host matrix.
		}
		name := fmt.Sprintf("rawStructure%d", i)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: I64}
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\nMOVD $5,R7\n", name)
		list := arm64TestVectorList(test.first, test.count, test.arrangement)
		if test.load {
			fmt.Fprintf(&source, "MOVD R0,R3\nWORD $%#08x\nVST1 %s,(R1)\n", test.word, list)
		} else {
			fmt.Fprintf(&source, "MOVD R1,R3\nVLD1 (R0),%s\nWORD $%#08x\n", list, test.word)
		}
		source.WriteString("MOVD R3,R0\nRET\n")
		fmt.Fprintf(&declarations, "extern uintptr_t %s(const unsigned char *, unsigned char *);\n", name)
		checks.WriteString("memset(output, 0xcc, sizeof(output)); memset(expected, 0xcc, sizeof(expected));\n")
		for reg := 0; reg < test.count; reg++ {
			for lane := 0; lane < test.lanes; lane++ {
				linear := (reg*test.lanes + lane) * test.bits / 8
				structured := (lane*test.count + reg) * test.bits / 8
				if test.op == "VLD1" || test.op == "VST1" {
					structured = linear
				}
				if test.replicate {
					structured = reg * test.bits / 8
				}
				from, to := linear, structured
				if test.load {
					from, to = structured, linear
				}
				fmt.Fprintf(&checks, "memcpy(expected+3+%d, input+1+%d, %d);\n", to, from, test.bits/8)
			}
		}
		base := "output+3"
		if test.load {
			base = "input+1"
		}
		increment := 0
		if test.post == 1 {
			increment = test.count * test.bits * test.lanes / 8
			if test.replicate {
				increment = test.count * test.bits / 8
			}
		} else if test.post == 2 {
			increment = 5
		}
		fmt.Fprintf(&checks, "if (%s(input+1,output+3) != (uintptr_t)(%s+%d) || memcmp(output,expected,sizeof(output))) { fprintf(stderr, \"%s failed\\n\"); return 1; }\n", name, base, increment, name)
	}
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	mainC := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + declarations.String() +
		"int main(void) { unsigned char input[160], output[160], expected[160]; for (int i=0;i<160;i++) input[i]=(unsigned char)(i*37+11);\n" + checks.String() + "return 0;}\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_structure", triple, ir, mainC, nil)
	t.Logf("executed %d raw structure load/store/replicate cases with unaligned buffers and writeback checks", len(sigs))
}
