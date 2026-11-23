package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestX86OfficialRMWSharedAddressObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, mode := range []struct {
		arch, triple string
	}{
		{"amd64", "x86_64-unknown-linux-gnu"},
		{"386", "i386-unknown-linux-gnu"},
	} {
		t.Run(mode.arch, func(t *testing.T) {
			var source, declarations strings.Builder
			var names, locations []string
			word, move := 8, "MOVQ"
			if mode.arch == "386" {
				word, move = 4, "MOVL"
			}
			add := func(instruction, location, data, base string) {
				name := fmt.Sprintf("Value%d", len(names))
				argument := "*uint64"
				if data == base {
					argument = "uintptr"
				}
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s $0x2468,AX\n", name, word, move)
				if data != base {
					fmt.Fprintf(&source, "%s $1,%s\n", move, data)
				}
				fmt.Fprintf(&source, "%s memory+0(FP),%s\n%s\nRET\n", move, base, instruction)
				fmt.Fprintf(&declarations, "func %s(memory %s)\n", name, argument)
				names = append(names, name)
				locations = append(locations, location)
			}
			if mode.arch == "amd64" {
				x86OfficialRMWRegisterMemoryRows(t, add)
				if len(names) != 96 {
					t.Fatalf("found %d official RMW source occurrences, want 96", len(names))
				}
			} else {
				for _, stem := range []string{"XADD", "XCHG", "CMPXCHG", "BT", "BTC", "BTR", "BTS"} {
					for _, width := range "BWL" {
						if width == 'B' && strings.HasPrefix(stem, "BT") {
							continue
						}
						register := "BX"
						if width == 'B' {
							register = "BL"
						}
						instruction := fmt.Sprintf("%s%c %s, 1(BX)", stem, width, register)
						add(instruction, instruction, "BX", "BX")
					}
				}
			}
			text := source.String()
			x86LEAActualTargetGoObject(t, mode.arch, mode.triple, text)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, text, declarations.String(), mode.arch, mode.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						object := x86PackedStringCompileObject(t, llc, mode.triple, ir, level)
						requireX86ELFTestFunctions(t, mode.arch, object, names, locations)
					}
				})
			}
		})
	}
}

func x86OfficialRMWRegisterMemoryRows(t *testing.T, add func(instruction, location, data, base string)) {
	t.Helper()
	pattern := regexp.MustCompile(`^(?:XCHG|XADD|CMPXCHG|BT[CRS]?)[BWLQ]\s+([A-Z0-9]+),\s+\(([A-Z0-9]+)\)$`)
	for _, path := range x86OfficialAssemblerSourcePaths(t, "amd64") {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for line, raw := range strings.Split(string(data), "\n") {
			code, _, _ := strings.Cut(raw, "//")
			code = strings.TrimSpace(code)
			match := pattern.FindStringSubmatch(code)
			if match == nil {
				continue
			}
			register := match[1]
			if register == "DL" {
				register = "DX"
			}
			add(code, fmt.Sprintf("%s:%d", filepath.Base(path), line+1), register, match[2])
		}
	}
}

func TestX86RMWSharedAddressNeedsCompleteNumericalInputs(t *testing.T) {
	const triple = "x86_64-unknown-linux-gnu"
	for _, op := range []string{"XCHGB", "XADDB", "CMPXCHGB", "BTW", "BTCW", "BTRW", "BTSW"} {
		for _, row := range []struct {
			name, declaration, setup, operands string
		}{
			{"partial-base", "func Value()", "MOVW $3,R11\n", "R11,(R11)"},
			{"pointer-as-bits", "func Value(p *byte)", "MOVQ p+0(FP),R11\n", "R11,(R11)"},
			{"unrelated-base", "func Value(p uintptr)", "MOVQ p+0(FP),R11\nMOVQ $1,DX\n", "DX,(R11)"},
			{"unknown-index", "func Value(p uintptr)", "MOVQ p+0(FP),R11\n", "R11,1(R11)(CX*2)"},
		} {
			t.Run(op+"/"+row.name, func(t *testing.T) {
				size := 8
				if row.name == "partial-base" {
					size = 0
				}
				source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\nMOVQ $0,AX\n%s%s %s\nRET\n",
					size, row.setup, op, row.operands)
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, source, row.declaration, "amd64", triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s accepted %s: %v", api, row.name, err)
					}
				}
			})
		}
	}
}
