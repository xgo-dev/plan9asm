package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestGlobalMutabilityMatchesGoFlags(t *testing.T) {
	for _, test := range []struct {
		flags    string
		constant bool
	}{
		{"", false}, {"0", false}, {"NOPTR", false}, {"(NOPTR|DUPOK)", false},
		{"RODATA", true}, {"8", true}, {"(RODATA|NOPTR)", true}, {"24", true},
		{"RODATA & ~RODATA", false}, {"1 << 3", true},
	} {
		t.Run(test.flags, func(t *testing.T) {
			source := "DATA ·data(SB)/8,$42\nGLOBL ·data(SB),"
			if test.flags != "" {
				source += test.flags + ","
			}
			source += "$8\n"
			requireX86GoAssemblerResult(t, "amd64", "#define RODATA 8\n#define NOPTR 16\n#define DUPOK 2\n"+source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, textual := range []bool{false, true} {
				ir, err := Translate(file, Options{Goarch: "amd64", AnnotateSource: textual,
					ResolveSym: func(s string) string { return strings.TrimPrefix(s, "·") }})
				if err != nil {
					t.Fatal(err)
				}
				kind := "global"
				if test.constant {
					kind = "constant"
				}
				if !strings.Contains(ir, fmt.Sprintf("@data = %s [8 x i8]", kind)) {
					t.Fatalf("textual=%v: GLOBL %q did not retain mutability", textual, test.flags)
				}
			}
		})
	}
}

func TestFileLocalDataLinkage(t *testing.T) {
	for _, flags := range []string{"16", "8"} {
		file, err := Parse(ArchAMD64, "DATA table<>(SB)/8,$42\nGLOBL table<>(SB),"+flags+",$8\n")
		if err != nil {
			t.Fatal(err)
		}
		for _, textual := range []bool{false, true} {
			ir, err := Translate(file, Options{Goarch: "amd64", AnnotateSource: textual})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, " = internal ") {
				t.Fatalf("file-local data must not collide when separately translated files are linked: %s", ir)
			}
		}
	}
}
