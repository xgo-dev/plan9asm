package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLongAssemblyLinesAndMacroExpansions(t *testing.T) {
	// Page-padding macros in gomonkey expand a short source line beyond
	// bufio.Scanner's default 64 KiB limit. Go's token reader has no such
	// physical-line limit. Test both preprocessing and expanded parsing.
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	const count = 16384
	padding := strings.Repeat("NOP; ", count)
	var nested strings.Builder
	nested.WriteString("#define PAD0 NOP;\n")
	for level := 1; level <= 7; level++ {
		fmt.Fprintf(&nested, "#define PAD%d %s\n", level, strings.Repeat(fmt.Sprintf("PAD%d; ", level-1), 4))
	}
	for _, tc := range []struct {
		name, source string
	}{
		{"physical", "TEXT padding(SB),4,$0-0\n" + padding + "RET\n"},
		{"definition", "#define PAD " + padding + "\nTEXT padding(SB),4,$0-0\nPAD\nRET\n"},
		{"nested", nested.String() + "TEXT padding(SB),4,$0-0\nPAD7\nRET\n"},
	} {
		for _, target := range []struct {
			goarch, triple string
			arch           Arch
		}{
			{"386", "i386-unknown-linux-gnu", ArchAMD64},
			{"amd64", "x86_64-unknown-linux-gnu", ArchAMD64},
			{"arm", "armv7-unknown-linux-gnueabihf", ArchARM},
			{"arm64", "aarch64-unknown-linux-gnu", ArchARM64},
			{"wasm", "wasm32-unknown-unknown", ArchWASM},
		} {
			t.Run(tc.name+"/"+target.goarch, func(t *testing.T) {
				dir := t.TempDir()
				asm := filepath.Join(dir, "padding.s")
				if err := os.WriteFile(asm, []byte(tc.source), 0600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("go", "tool", "asm", "-o", filepath.Join(dir, "padding.o"), asm)
				cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+target.goarch)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("Go assembler rejected fixture: %v\n%s", err, out)
				}
				file, err := Parse(target.arch, tc.source)
				if err != nil {
					t.Fatal(err)
				}
				if len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) != count+2 {
					t.Fatal("long line was truncated or instructions were lost")
				}
				for _, ins := range file.Funcs[0].Instrs[1 : count+1] {
					if ins.Op != "NOP" {
						t.Fatalf("unexpected padding instruction %+v", ins)
					}
				}
				ir, err := Translate(file, Options{
					Goarch: target.goarch, TargetTriple: target.triple,
					Sigs: map[string]FuncSig{"padding": {Name: "padding", Ret: Void}},
				})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "padding.ll", "padding.o", ir)
			})
		}
	}
}

func TestParseLongCommentsPreserveFollowingSource(t *testing.T) {
	for _, source := range []string{
		"//" + strings.Repeat("comment ", 20000) + "\nTEXT padding(SB),4,$0-0\nRET",
		"/*" + strings.Repeat("comment ", 20000) + "*/ TEXT padding(SB),4,$0-0\nRET",
	} {
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		if len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) != 2 || file.Funcs[0].Instrs[1].Op != "RET" {
			t.Fatal("source after a long comment was lost")
		}
	}
}
