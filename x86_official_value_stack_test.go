package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestX86OfficialValueStackObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, mode := range []struct {
		arch, triple string
		want         int
	}{
		{"amd64", "x86_64-unknown-linux-gnu", 58},
		{"386", "i386-unknown-linux-gnu", 6},
	} {
		t.Run(mode.arch, func(t *testing.T) {
			source, declarations, names, locations, count := x86OfficialValueStackFunctions(t, mode.arch)
			if count != mode.want {
				t.Fatalf("assembled %d official source occurrences, want %d", count, mode.want)
			}
			x86LEAActualTargetGoObject(t, mode.arch, mode.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, mode.arch, mode.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					object := compileLLVMToObject(t, llc, mode.triple, "official-stack.ll", "official-stack.o", ir)
					requireX86ELFTestFunctions(t, mode.arch, object, names, locations)
				})
			}
			t.Logf("compiled all %d original Go stack occurrences with all three APIs", count)
		})
	}
}

func x86OfficialValueStackFunctions(t *testing.T, arch string) (string, string, []string, []string, int) {
	t.Helper()
	opcode := regexp.MustCompile(`^(PUSH|POP)F?([WLQ])(?:\s|$)`)
	var source, declarations strings.Builder
	var names, locations []string
	count := 0
	if arch == "386" {
		source.WriteString("DATA foo+0(SB)/4,$7\nGLOBL foo(SB),8,$8\n")
	}
	for _, path := range x86OfficialAssemblerSourcePaths(t, arch) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		depth := 0
		for index, raw := range strings.Split(string(data), "\n") {
			code, _, _ := strings.Cut(raw, "//")
			code = strings.TrimSpace(code)
			match := opcode.FindStringSubmatch(code)
			if match == nil {
				if depth != 0 && code != "" {
					t.Fatalf("%s:%d separates an unpaired stack sequence", path, index+1)
				}
				continue
			}
			if len(lines) == 0 {
				locations = append(locations, fmt.Sprintf("%s:%d", filepath.Base(path), index+1))
			}
			lines = append(lines, code)
			size := map[string]int{"W": 2, "L": 4, "Q": 8}[match[2]]
			if match[1] == "PUSH" {
				depth += size
				continue
			}
			depth -= size
			if depth < 0 {
				t.Fatalf("%s:%d has an unpaired pop", path, index+1)
			}
			if depth == 0 {
				name := fmt.Sprintf("Stack%d", len(names))
				x86OfficialValueStackFunction(&source, &declarations, arch, name, lines)
				names = append(names, name)
				count += len(lines)
				lines = lines[:0]
			}
		}
		if depth != 0 {
			t.Fatalf("%s ends with an unpaired push", path)
		}
	}
	return source.String(), declarations.String(), names, locations, count
}

func x86OfficialValueStackFunction(source, declarations *strings.Builder, arch, name string, lines []string) {
	var firstSegment string
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.Contains(" CS DS ES FS GS SS ", " "+fields[1]+" ") {
			firstSegment = fields[1]
			break
		}
	}
	if firstSegment != "" {
		fmt.Fprintf(source, "TEXT ·%s(SB),516,$0-0\n", name)
		fmt.Fprintf(declarations, "func %s()\n", name)
		if strings.HasPrefix(lines[0], "PUSHQ AX") {
			// The selector reaches AX before the original register push.
			// These are physical objects only. Reloading FS/GS can change
			// machine state even when the selector bits are unchanged.
			fmt.Fprintf(source, "PUSHQ %s\nPOPQ AX\n", firstSegment)
		}
	} else {
		word, move := 8, "MOVQ"
		if arch == "386" {
			word, move = 4, "MOVL"
		}
		fmt.Fprintf(source, "TEXT ·%s(SB),4,$0-%d\n%s $0x12345678,AX\n%s AX,DX\n%s memory+0(FP),BX\nCMPL AX,AX\nCLD\n",
			name, word, move, move, move)
		fmt.Fprintf(declarations, "func %s(memory *uint64)\n", name)
		if arch == "amd64" {
			if strings.Contains(strings.Join(lines, "\n"), "(R11)") {
				source.WriteString("MOVQ memory+0(FP),R11\n")
			} else {
				source.WriteString("MOVQ AX,R11\n")
			}
		}
	}
	source.WriteString(strings.Join(lines, "\n"))
	source.WriteString("\nRET\n")
}
