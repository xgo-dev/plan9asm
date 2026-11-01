package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86LocalLabelsDoNotCollideWithIRValues(t *testing.T) {
	for _, target := range []struct {
		arch, triple, mov string
	}{
		{"amd64", "x86_64-apple-darwin", "MOVQ"},
		{"amd64", "x86_64-unknown-linux-gnu", "MOVQ"},
		{"amd64", "x86_64-pc-windows-msvc", "MOVQ"},
		{"386", "i386-unknown-linux-gnu", "MOVL"},
		{"386", "i686-pc-windows-msvc", "MOVL"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			source := fmt.Sprintf(`TEXT collision(SB),4,$0-0
PXOR X1,X1
JMP x1
x1:
%s X1,AX
JMP t1
t1:
JMP reg_AX
reg_AX:
JMP bb_foo
bb_foo:
RET
`, target.mov)
			requireX86GoAssemblerResult(t, target.arch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			ir, err := Translate(file, Options{
				Goarch:       target.arch,
				TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"collision": {
					Name: "collision", Ret: Void,
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "local-label.ll", "local-label.o", ir)
		})
	}
}
