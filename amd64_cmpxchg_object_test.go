package plan9asm

import (
	"bytes"
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

func TestX86CMPXCHGThreeAPIsFiveTargetsExactNativeO0O2Objects(t *testing.T) {
	llc, disassembler := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || disassembler == "" {
		t.Fatal("LLVM22 compiler and disassembler are required")
	}
	for _, target := range x86OrderingHintTargets {
		var source, declarations strings.Builder
		declarations.WriteString("package ordering\n")
		want := make(map[string]struct {
			op     string
			bits   int
			locked bool
		})
		for index, row := range x86CMPXCHGOriginalRows {
			if target.arch == "386" && (row.op == "CMPXCHGQ" || row.bits == 128) {
				continue
			}
			for _, locked := range []bool{false, true} {
				name := fmt.Sprintf("cas%d_%t", index, locked)
				body := x86CMPXCHGOriginalBody(index, "1(SI)")
				if locked {
					body = "LOCK\n\t" + body
				}
				original := strings.Replace(x86NamedLockOracleSource(target.arch, body), "·locked", "·"+name, 1)
				// Original objects are accepted without executing unsafe forms.
				x86OrderingHintGoBytes(t, target.arch, original)
				source.WriteString(original)
				fmt.Fprintf(&declarations, "func %s(p *[32]byte)\n", name)
				opcode := "CMPXCHG"
				if row.pair {
					opcode = row.op
				}
				want[name] = struct {
					op     string
					bits   int
					locked bool
				}{opcode, row.bits, locked}
			}
		}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86OrderingHintTranslateAPI(t, api, source.String(), declarations.String(), target.arch, target.triple)
				if err != nil {
					t.Fatal(err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					dir := t.TempDir()
					input, object := filepath.Join(dir, "native.ll"), filepath.Join(dir, "native.o")
					if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
						t.Fatal(err)
					}
					x86FloatCompareCaptureCommand(t, exec.Command(llc, level, "-mtriple="+target.triple, "-filetype=obj", input, "-o", object))
					listing := x86FloatCompareCaptureCommand(t, exec.Command(disassembler, "--disassemble", object))
					sections := regexp.MustCompile(`(?m)^[0-9a-f]+ <_?(cas[0-9]+_(?:false|true))>:\n`).FindAllSubmatchIndex(listing, -1)
					seen := make(map[string]bool)
					for index, section := range sections {
						name := string(listing[section[2]:section[3]])
						expected, known := want[name]
						if !known || seen[name] {
							t.Fatalf("unexpected or duplicate original function identity %s", name)
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
							var machine []byte
							for _, field := range fields[1:] {
								if len(field) != 2 {
									break
								}
								value, err := hex.DecodeString(field)
								if err != nil {
									break
								}
								machine = append(machine, value[0])
							}
							code = append(code, machine...)
						}
						// LLVM's disassembler displays a standalone F0 byte as a
						// separate "lock" line. Decode complete contiguous bytes,
						// not that presentation boundary, as the CPU does.
						mode := 64
						if target.arch == "386" {
							mode = 32
						}
						count := 0
						for len(code) != 0 {
							physical, err := x86asm.Decode(code, mode)
							if err != nil || physical.Len <= 0 || physical.Len > len(code) {
								t.Fatalf("incomplete physical function decode %s: %x %v", name, code, err)
							}
							machine := code[:physical.Len]
							code = code[physical.Len:]
							if !strings.HasPrefix(physical.Op.String(), "CMPXCHG") {
								continue
							}
							count++
							locked := false
							for _, prefix := range physical.Prefix {
								if byte(prefix) == 0xf0 {
									locked = true
								}
							}
							width := physical.DataSize
							if bytes.Contains(machine, []byte{0x0f, 0xb0}) {
								// x/arch DataSize retains the operand-size state for
								// B0, whose opcode independently specifies byte width.
								width = 8
							}
							if physical.Op.String() != expected.op || locked != expected.locked ||
								expected.op == "CMPXCHG" && width != expected.bits {
								t.Fatalf("%s/%s lost native width/prefix/opcode: %x %s\n%s", level, name, machine,
									x86asm.GoSyntax(physical, 0, nil), listing)
							}
						}
						if count != 1 {
							t.Fatalf("%s/%s has %d complete native operations\n%s", level, name, count, listing)
						}
						seen[name] = true
					}
					if len(seen) != len(want) {
						t.Fatalf("%s emitted %d/%d complete functions\n%s", level, len(seen), len(want), listing)
					}
					t.Logf("%s independently decoded %d native opcodes with exact width and LOCK identity", level, len(seen))
				}
			})
		}
	}
}
