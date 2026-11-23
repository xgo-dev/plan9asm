package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestX86OfficialNativeMemoryObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	const arch, triple = "amd64", "x86_64-unknown-linux-gnu"
	memory := regexp.MustCompile(`^(V?(?:LD|ST)MXCSR|MOVNTI[LQ] [A-Z0-9]+,|MOVQ R11,)\s+\(([A-Z0-9]+)\)$`)
	masked := regexp.MustCompile(`^(MASKMOVOU|VMASKMOVDQU)\s+X(\d+),\s+X(\d+)$`)
	var source, declarations strings.Builder
	var names, locations []string
	for _, path := range x86OfficialAssemblerSourcePaths(t, arch) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for line, raw := range strings.Split(string(data), "\n") {
			code, _, _ := strings.Cut(raw, "//")
			code = strings.TrimSpace(code)
			name := fmt.Sprintf("Memory%d", len(names))
			if row := memory.FindStringSubmatch(code); row != nil {
				if strings.HasPrefix(row[1], "MOVQ") && row[2] != "R11" {
					continue // Other ordinary scalar stores already have object coverage.
				}
				x86OfficialNativeMemoryFunction(&source, &declarations, name, code, row[1], row[2])
			} else if row := masked.FindStringSubmatch(code); row != nil {
				mask, _ := strconv.Atoi(row[2])
				value, _ := strconv.Atoi(row[3])
				program, declaration := x86ImplicitMaskMoveOracleRegisters(arch, row[1], name, mask, value)
				instruction := fmt.Sprintf("%s X%d,X%d", row[1], mask, value)
				if !strings.Contains(program, instruction+"\n") {
					t.Fatal("implicit store fixture lost the exact register operands")
				}
				source.WriteString(strings.Replace(program, instruction+"\n", code+"\n", 1))
				declarations.WriteString(declaration)
			} else {
				continue
			}
			names = append(names, name)
			locations = append(locations, fmt.Sprintf("%s:%d", filepath.Base(path), line+1))
		}
	}
	if len(names) != 25 {
		t.Fatalf("found %d official native-memory occurrences, want 25", len(names))
	}
	x86LEAActualTargetGoObject(t, arch, triple, source.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				object := x86PackedStringCompileObject(t, llc, triple, ir, level)
				requireX86ELFTestFunctions(t, arch, object, names, locations)
			}
		})
	}
}

func x86OfficialNativeMemoryFunction(source, declarations *strings.Builder, name, code, operation, base string) {
	argument := "*uint32"
	fields := strings.Fields(operation)
	fmt.Fprintf(source, "TEXT ·%s(SB),4,$0-8\n", name)
	if len(fields) == 2 {
		register := strings.TrimSuffix(fields[1], ",")
		argument = "*uint64"
		if register == base {
			argument = "uintptr"
		} else {
			fmt.Fprintf(source, "MOVQ $0x2468,%s\n", register)
		}
	}
	fmt.Fprintf(source, "MOVQ memory+0(FP),%s\n%s\n", base, code)
	if strings.HasPrefix(operation, "MOVNTI") {
		source.WriteString("SFENCE\n")
	}
	source.WriteString("RET\n")
	fmt.Fprintf(declarations, "func %s(memory %s)\n", name, argument)
}
