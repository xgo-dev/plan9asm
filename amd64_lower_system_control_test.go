package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateX86SystemControlLRETRawAndWAIT(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, test := range []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "lret",
			source: "TEXT lret(SB),NOSPLIT,$0-0\n\tBYTE $0x48; BYTE $0xcb\n",
			want:   `asm sideeffect "lretq"`,
		},
		{
			name:   "wait",
			source: "TEXT wait(SB),NOSPLIT,$0-0\n\tWAIT\n\tRET\n",
			want:   `asm sideeffect "wait"`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, test.source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       "amd64",
				TargetTriple: "x86_64-unknown-linux-gnu",
				Sigs:         map[string]FuncSig{test.name: {Name: test.name, Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, test.want) {
				t.Fatalf("translation omitted %q:\n%s", test.want, ir)
			}
			compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "x86-system-control-"+test.name+".ll", "x86-system-control-"+test.name+".o", ir)
		})
	}
}
