package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestX86RawShiftRotateCompleteGoForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			var lines []string
			widths := []string{"B", "W", "L"}
			mode := 32
			if arch == "amd64" {
				mode = 64
				widths = append(widths, "Q")
			}
			for _, stem := range []string{"ROL", "ROR", "RCL", "RCR", "SHL", "SHR", "SAR"} {
				for _, width := range widths {
					destinations := []string{"AX", "-7(BX)(CX*4)"}
					if width == "B" {
						destinations = []string{"AL", "AH", "-7(BX)(CX*4)"}
					}
					if arch == "amd64" {
						destinations = append(destinations, "R11")
					}
					for _, dst := range destinations {
						for _, count := range []string{"$1", "$255", "CL"} {
							lines = append(lines, fmt.Sprintf("%s%s %s, %s", stem, width, count, dst))
						}
					}
				}
			}
			for _, stem := range []string{"SHL", "SHR"} {
				for _, width := range widths[1:] {
					for _, dst := range []string{"BX", "-7(BX)(CX*4)"} {
						for _, count := range []string{"$-128", "$127", "CL"} {
							lines = append(lines, fmt.Sprintf("%s%s %s, AX, %s", stem, width, count, dst))
						}
					}
				}
			}
			named := "TEXT shifts(SB),4,$0-0\n" + strings.Join(lines, "\n") + "\nRET\n"
			code := assembleX87ControlBytes(t, arch, named)
			offset := 0
			var raw strings.Builder
			raw.WriteString("TEXT shifts(SB),4,$0-0\n")
			for _, line := range lines {
				inst, err := x86asm.Decode(code[offset:], mode)
				if err != nil {
					t.Fatalf("Go encoded %s: %v", line, err)
				}
				encoded := code[offset : offset+inst.Len]
				decoded, err := decodeX86RawDirectives(rawX86Function(encoded), arch)
				if err != nil {
					t.Fatal(err)
				}
				want, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+line+"\n")
				if err != nil {
					t.Fatal(err)
				}
				if len(decoded.Instrs) != 1 || decoded.Instrs[0].Op != want.Funcs[0].Instrs[1].Op || !reflect.DeepEqual(decoded.Instrs[0].Args, want.Funcs[0].Instrs[1].Args) {
					t.Fatalf("decoded %x as %+v, want %s", encoded, decoded.Instrs, line)
				}
				for _, b := range encoded {
					fmt.Fprintf(&raw, "BYTE $%#02x\n", b)
				}
				offset += inst.Len
			}
			raw.WriteString("RET\n")
			file, err := Parse(ArchAMD64, raw.String())
			if err != nil {
				t.Fatal(err)
			}
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
				if (arch == "386") != strings.HasPrefix(triple, "i") {
					continue
				}
				ir, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"shifts": {Name: "shifts", Ret: Void}}})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "raw-shifts.ll", "raw-shifts.o", ir)
			}
		})
	}
}
