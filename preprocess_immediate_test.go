package plan9asm

import (
	"strings"
	"testing"
)

func TestPreprocessImmediateMacrosRespectCompleteTokens(t *testing.T) {
	for _, test := range []struct{ name, source, want string }{
		{"named_stack_address", "#define buf buffer-(8+4*16)(SP)\nMOVW $buf, R0\n", "MOVW $buffer-(8+4*16)(SP), R0"},
		{"identifier_prefix", "#define CONST 33\nMOVQ $CONSTANT, AX\n", "MOVQ $CONSTANT, AX"},
		{"quoted_string", "#define buf 33\nDATA data(SB)/4, $\"buf\"\n", "DATA data(SB)/4, $\"buf\""},
		{"character", "#define x 33\nBYTE $'x'\n", "BYTE $'x'"},
		{"qualified_symbol", "#define value 33\nMOVQ $pkg·value(SB), AX\n", "MOVQ $pkg·value(SB), AX"},
		{"division_slash_symbol", "#define value 33\nMOVQ $pkg∕value(SB), AX\n", "MOVQ $pkg∕value(SB), AX"},
		{"middle_dot_symbol", "#define value 33\nMOVQ $·value(SB), AX\n", "MOVQ $·value(SB), AX"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := preprocess(test.source)
			if err != nil || strings.TrimSpace(got) != test.want {
				t.Fatalf("preprocess = %q, %v; want complete-token expansion %q", got, err, test.want)
			}
		})
	}
}

func TestARMImmediateNamedStackMacroRetainsRealAddress(t *testing.T) {
	const source = `
#define buf buffer-(8+4*16)(SP)
TEXT stack_address(SB),$84-0
MOVW $buf, R0
RET
`
	requireARMGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	operand := file.Funcs[0].Instrs[1].Args[0]
	address, ok := parseMem(strings.TrimPrefix(operand.Sym, "$"))
	if operand.Kind != OpSym || !ok || address.Base != SP || address.Off != -72 {
		t.Fatalf("named stack address corrupted or replaced with zero: %+v", operand)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple,
				Sigs: map[string]FuncSig{"stack_address": {Name: "stack_address", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, ", -72") {
				t.Fatalf("real stack displacement missing:\n%s", ir)
			}
			compileLLVMToObject(t, llc, triple, "stack-address.ll", "stack-address.o", ir)
		})
	}
}
