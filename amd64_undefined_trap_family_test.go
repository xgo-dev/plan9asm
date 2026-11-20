package plan9asm

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestX86UndefinedTrapRetainsCompleteOfficialFaultEncoding(t *testing.T) {
	table, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(table), "{obj.AUNDEF, ynone, Px, opBytes{0x0f, 0x0b}}") ||
		!strings.Contains(string(table), "var ynone = []ytab{\n\t{Zlit, 1, argList{}},\n}") {
		t.Fatal("complete Go undefined-instruction row changed")
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			source := "TEXT fault(SB),4,$0-0\nUNDEF\nRET\n"
			actual := assembleX87ControlBytes(t, arch, source)
			if !bytes.Equal(actual, []byte{0x0f, 0x0b, 0xc3}) {
				t.Fatalf("actual original Go undefined-instruction identity: %x", actual)
			}
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			ctx.goarch = arch
			before := output.Len()
			known, terminated, err := ctx.lowerArith("UNDEF", file.Funcs[0].Instrs[1])
			ir := output.String()[before:]
			if !known || !terminated || err != nil ||
				!strings.Contains(ir, "asm sideeffect \"ud2\"") || !strings.Contains(ir, "unreachable") {
				t.Fatalf("native undefined fault was changed or discarded: %t/%t/%v\n%s", known, terminated, err, ir)
			}
		})
	}
}

func TestX86UndefinedTrapMalformedOperandsRejectBeforeEmission(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, operands := range []string{"AX", "(AX)", "$1", "AX,DX"} {
			t.Run(arch+"/"+operands, func(t *testing.T) {
				source := "TEXT fault(SB),4,$0-0\nUNDEF " + operands + "\nRET\n"
				goAssemblerOracleOutput(t, arch, source, "", false)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
				ctx.goarch = arch
				before, temporary := output.String(), ctx.tmp
				known, terminated, err := ctx.lowerArith("UNDEF", file.Funcs[0].Instrs[1])
				if !known || terminated || err == nil || before != output.String() || temporary != ctx.tmp {
					t.Fatalf("invalid undefined-instruction form emitted IR: %t/%t/%v", known, terminated, err)
				}
			})
		}
	}
}
