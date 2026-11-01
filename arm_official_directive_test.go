package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestTranslateARMEndDirective(t *testing.T) {
	const source = "TEXT endDirective(SB),$0-0\n\tRET\n\tEND\n"
	requireARMGoAssemblerResult(t, source, true)
	ll := translateARMForTest(t, source, map[string]FuncSig{
		"example.endDirective": {Name: "example.endDirective", Ret: Void},
	})
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-end.ll", "arm-end.o", ll)
}

func TestTranslateARMEndDirectiveIgnoresTrailingOperandsLikeGo(t *testing.T) {
	const source = "TEXT endWithIgnoredOperand(SB),$0-0\n\tRET\n\tEND R0\n"
	requireARMGoAssemblerResult(t, source, true)
	translateARMForTest(t, source, map[string]FuncSig{
		"example.endWithIgnoredOperand": {Name: "example.endWithIgnoredOperand", Ret: Void},
	})
}

func TestProbeARMContextDependentOfficialDirectives(t *testing.T) {
	cases := []struct {
		name   string
		source string
	}{
		{name: "return-from-exception", source: "RFE"},
		{name: "undefined-raw-word", source: "WORD $4294967295"},
		{name: "pc-relative-raw-word", source: "WORD $2863311530"},
		{name: "stateful-raw-word", source: "WORD $1431655765"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			file, err := Parse(ArchARM, "TEXT probe(SB),$0-0\n\t"+test.source+"\n")
			if err != nil {
				t.Fatal(err)
			}
			instruction := file.Funcs[0].Instrs[1]
			err = ProbeInstruction(ArchARM, "arm", instruction)
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("ProbeInstruction(%s) error = %v, want ErrProbeNeedsContext", test.source, err)
			}
			if !strings.Contains(err.Error(), test.source) {
				t.Fatalf("context error %q does not identify %q", err, test.source)
			}
		})
	}
}
