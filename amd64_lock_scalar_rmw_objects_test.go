package plan9asm

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestX86LockScalarRMWThreeAPIsFiveTargetsNativeObjects(t *testing.T) {
	x86LockScalarRMWNativeObjectMatrix(t, false)
}

func TestX86LockScalarRMWIndexedSegmentsThreeAPIsFiveTargetsObjects(t *testing.T) {
	x86LockScalarRMWNativeObjectMatrix(t, true)
}

func x86LockScalarRMWNativeObjectMatrix(t *testing.T, indexed bool) {
	t.Helper()
	llc, disassembler := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || disassembler == "" {
		t.Fatal("LLVM22 compiler and disassembler are required")
	}
	for _, target := range x86OrderingHintTargets {
		var source, declarations strings.Builder
		declarations.WriteString("package ordering\n")
		type expectedInstruction struct {
			op      string
			bits    int
			segment x86asm.Reg
		}
		want := make(map[string]expectedInstruction)
		for index, row := range x86LockScalarOracleForms(target.arch) {
			for _, segment := range []string{"native", "FS", "GS"} {
				memory := "1(SI)"
				if segment != "native" {
					memory = "1(" + segment + ")"
					if indexed {
						memory = "1(AX)(" + segment + "*4)"
					}
				}
				body := strings.Replace(row.text, "1(SI)", memory, 1)
				name := fmt.Sprintf("rmw%d_%s", index, strings.ToLower(segment))
				original := strings.Replace(x86NamedLockOracleSource(target.arch,
					"CMPL AX,AX\n\tLOCK\n\t"+body), "·locked", "·"+name, 1)
				x86LockScalarOriginalInstruction(t, target.arch, original)
				source.WriteString(original)
				fmt.Fprintf(&declarations, "func %s(p *[16]byte)\n", name)

				bits := map[byte]int{'B': 8, 'W': 16, 'L': 32, 'Q': 64}[row.op[len(row.op)-1]]
				stem := strings.ToLower(row.op[:len(row.op)-1])
				helper := "__plan9asm_lock_rmw_0_" + target.arch + "_" +
					stem + fmt.Sprint(bits) + "_" + strings.ToLower(segment)
				if strings.Contains(row.text, "$1") {
					helper += "_imm_0000000000000001"
				}
				physicalSegment := x86asm.Reg(0)
				if segment == "FS" {
					physicalSegment = x86asm.FS
				} else if segment == "GS" {
					physicalSegment = x86asm.GS
				}
				want[helper] = expectedInstruction{strings.ToUpper(stem), bits, physicalSegment}
			}
		}

		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86OrderingHintTranslateAPI(t, api, source.String(),
					declarations.String(), target.arch, target.triple)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(ir, "atomicrmw ") || strings.Contains(ir, " = cmpxchg ") {
					t.Fatal("source RMW acquired a guessed LLVM atomic alignment or software replacement")
				}
				for _, level := range []string{"-O0", "-O2"} {
					t.Run(level, func(t *testing.T) {
						dir := t.TempDir()
						input, object := filepath.Join(dir, "lock.ll"), filepath.Join(dir, "lock.o")
						if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
							t.Fatal(err)
						}
						x86FloatCompareCaptureCommand(t, exec.Command(llc, level,
							"-mtriple="+target.triple, "-filetype=obj", input, "-o", object))
						listing := x86FloatCompareCaptureCommand(t,
							exec.Command(disassembler, "--disassemble", object))
						sections := regexp.MustCompile(`(?m)^[0-9a-f]+ <([^>]+)>:\n`).FindAllSubmatchIndex(listing, -1)
						seen := make(map[string]bool)
						for index, section := range sections {
							name := string(listing[section[2]:section[3]])
							if strings.HasPrefix(name, "___plan9asm_lock_rmw_") {
								name = strings.TrimPrefix(name, "_") // Mach-O/COFF leading underscore.
							}
							expected, known := want[name]
							if !known {
								continue
							}
							if seen[name] {
								t.Fatal("duplicate compiler helper", name)
							}
							end := len(listing)
							if index+1 < len(sections) {
								end = sections[index+1][0]
							}
							var code []byte
							for _, line := range strings.Split(string(listing[section[1]:end]), "\n") {
								fields := strings.Fields(line)
								if len(fields) < 2 || !strings.HasSuffix(fields[0], ":") {
									continue
								}
								for _, field := range fields[1:] {
									if len(field) != 2 {
										break
									}
									value, err := hex.DecodeString(field)
									if err != nil {
										break
									}
									code = append(code, value[0])
								}
							}
							mode := 64
							if target.arch == "386" {
								mode = 32
							}
							count := 0
							for len(code) != 0 {
								physical, err := x86asm.Decode(code, mode)
								if err != nil || physical.Len <= 0 || physical.Len > len(code) {
									t.Fatalf("incomplete physical helper %s: %x %v", name, code, err)
								}
								machine := code[:physical.Len]
								code = code[physical.Len:]
								locked, segmentPrefixes := false, 0
								for _, prefix := range physical.Prefix {
									if byte(prefix) == 0xf0 {
										locked = true
									}
									if byte(prefix) == 0x64 || byte(prefix) == 0x65 {
										segmentPrefixes++
									}
								}
								if !locked {
									continue
								}
								count++
								var memory x86asm.Mem
								foundMemory := false
								for _, argument := range physical.Args {
									if value, ok := argument.(x86asm.Mem); ok {
										memory, foundMemory = value, true
									}
								}
								wantSegments := 0
								if expected.segment != 0 {
									wantSegments = 1
								}
								if physical.Op.String() != expected.op || !foundMemory ||
									physical.MemBytes*8 != expected.bits ||
									memory.Segment != expected.segment || segmentPrefixes != wantSegments ||
									physical.AddrSize != mode {
									t.Fatalf("native width/segment/address/prefix identity changed: %s bytes=%x decoded=%s memBytes=%d segmentPrefixes=%d expected=%+v",
										name, machine, x86asm.GoSyntax(physical, 0, nil), physical.MemBytes, segmentPrefixes, expected)
								}
							}
							if count != 1 {
								t.Fatalf("%s helper has %d complete native RMW instructions", name, count)
							}
							seen[name] = true
						}
						if len(seen) != len(want) {
							t.Fatalf("emitted %d/%d complete native helpers\n%s", len(seen), len(want), listing)
						}
						t.Logf("actual %s object independently decoded %d whole native RMW helpers", target.triple, len(seen))
					})
				}
			})
		}
	}
}
