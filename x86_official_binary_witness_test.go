package plan9asm

import (
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Official syntax witnesses have no entry inputs. Probe classification may
// therefore require context; actual lowering remains mandatory independently
// of that classification. This does not certify a public or runtime entry.
func x86OfficialBinaryWitnessLowerer(t *testing.T, file *File, arch string) {
	t.Helper()
	if err := ProbeInstruction(ArchAMD64, arch, file.Funcs[0].Instrs[1]); err != nil && !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("actual Go-accepted table witness failed instruction classification: %v", err)
	}
	triple := "x86_64-unknown-linux-gnu"
	if arch == "386" {
		triple = "i386-unknown-linux-gnu"
	}
	x86ScalarFormatObjectUnit(t, file, map[string]FuncSig{"f": {Name: "f", Ret: Void}}, arch, triple, 0)
}

func x86OfficialPackedBinaryWitnesses(t *testing.T) map[string][]string {
	t.Helper()
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	byOpcode := map[string]map[string]bool{}
	for _, rule := range rules {
		if rule.Ytab != "_yvandnpd" {
			continue
		}
		witnesses, err := goasmrules.X86PackedBinarySyntaxWitnesses(rule)
		if err != nil {
			t.Fatal(err)
		}
		if byOpcode[rule.Opcode] == nil {
			byOpcode[rule.Opcode] = map[string]bool{}
		}
		for _, witness := range witnesses {
			byOpcode[rule.Opcode][witness] = true
		}
	}
	result := map[string][]string{}
	for opcode, witnesses := range byOpcode {
		for witness := range witnesses {
			result[opcode] = append(result[opcode], witness)
		}
		sort.Strings(result[opcode])
	}
	return result
}

func TestX86OfficialPackedBinarySourceWitnessesCompileWithGo(t *testing.T) {
	byOpcode := x86OfficialPackedBinaryWitnesses(t)
	if len(byOpcode) < 60 {
		t.Fatal("official packed-binary table inventory is incomplete")
	}
	opcodes := make([]string, 0, len(byOpcode))
	for opcode := range byOpcode {
		opcodes = append(opcodes, opcode)
	}
	sort.Strings(opcodes)
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			var source strings.Builder
			accepted, maskedFrontendRows := 0, 0
			for _, opcode := range opcodes {
				for _, witness := range byOpcode[opcode] {
					if arch == "386" && strings.Count(witness, ",") == 3 {
						// This is a separate frontend limitation, not a missing
						// encoder row or a successful translated object. Its real
						// Go rejection is checked below for each family opcode.
						maskedFrontendRows++
						continue
					}
					fmt.Fprintf(&source, "TEXT probe%d(SB),4,$0-0\n%s\nRET\n", accepted, witness)
					accepted++
				}
			}
			goAssemblerOracleOutput(t, arch, source.String(), "", true)
			t.Logf("actual Go assembled %d complete-table syntax witnesses/%d opcodes; %d masked mode32 candidates have separate frontend refusals; not LLVM/runtime coverage", accepted, len(opcodes), maskedFrontendRows)
		})
	}
	for _, opcode := range opcodes {
		t.Run("386_masked_frontend/"+opcode, func(t *testing.T) {
			goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+opcode+" Z0,Z1,K1,Z2\nRET\n", "", false)
		})
	}
}

func TestX86OfficialWordMultiplyWitnessesReachActualLowerer(t *testing.T) {
	byOpcode := x86OfficialPackedBinaryWitnesses(t)
	// These names select a coherent semantic family. All operand formats below
	// come from the independent Go table, not the lowerer's own spec or a
	// discovering external library.
	for _, arch := range []string{"amd64", "386"} {
		for _, opcode := range []string{"VPMULLW", "VPMULHW", "VPMULHUW", "VPMULHRSW"} {
			witnesses := byOpcode[opcode]
			if len(witnesses) == 0 {
				t.Fatalf("actual Go encoder family lacks %s", opcode)
			}
			for _, witness := range witnesses {
				if arch == "386" && strings.Count(witness, ",") == 3 {
					continue // Independently tested actual frontend refusal above.
				}
				t.Run(arch+"/"+witness, func(t *testing.T) {
					source := "TEXT f(SB),4,$0-0\n" + witness + "\nRET\n"
					goAssemblerOracleOutput(t, arch, source, "", true)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					x86OfficialBinaryWitnessLowerer(t, file, arch)
				})
			}
		}
	}
}

func TestX86OfficialPackedBinaryWitnessesReachActualLowerer(t *testing.T) {
	byOpcode := x86OfficialPackedBinaryWitnesses(t)
	opcodes := make([]string, 0, len(byOpcode))
	for opcode := range byOpcode {
		opcodes = append(opcodes, opcode)
	}
	sort.Strings(opcodes)
	if len(opcodes) < 60 {
		t.Fatal("complete shared grammar has no independent opcode inventory")
	}
	for _, arch := range []string{"amd64", "386"} {
		// Bind the entire syntax matrix to an actual original Go object before
		// asking our lowerers. This avoids deriving the test denominator from
		// production specs or launching one assembler for every candidate.
		var source strings.Builder
		accepted := 0
		for _, opcode := range opcodes {
			for _, witness := range byOpcode[opcode] {
				if arch == "386" && strings.Count(witness, ",") == 3 {
					continue // Separate required actual frontend refusal test.
				}
				fmt.Fprintf(&source, "TEXT probe%d(SB),4,$0-0\n%s\nRET\n", accepted, witness)
				accepted++
			}
		}
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
		for _, opcode := range opcodes {
			for _, witness := range byOpcode[opcode] {
				if arch == "386" && strings.Count(witness, ",") == 3 {
					continue
				}
				t.Run(arch+"/"+witness, func(t *testing.T) {
					file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+witness+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					x86OfficialBinaryWitnessLowerer(t, file, arch)
				})
			}
		}
		t.Logf("checked %d actual Go-accepted grammar witnesses/%d opcodes on %s; syntax lowering only, not LLVM objects or runtime", accepted, len(opcodes), arch)
	}
}
