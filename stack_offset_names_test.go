package plan9asm

import "testing"

func TestNamedStackOffsetIdentifierLengths(t *testing.T) {
	for _, name := range []string{"n", "N", "_", "x1", "frameSlot"} {
		for _, test := range []struct {
			suffix string
			want   int64
		}{
			{"+8", 8}, {"-8", -8}, {"+(2*4)", 8}, {"-(2*4)", -8},
		} {
			source := name + test.suffix
			if got, ok := parseNamedStackConstantOffset(source); !ok || got != test.want {
				t.Errorf("%s: offset=%d/%v, want %d", source, got, ok, test.want)
			}
			memory, ok := parseMem(source + "(SP)")
			if !ok || memory.Off != test.want {
				t.Errorf("%s(SP): memory=%+v/%v, want offset %d", source, memory, ok, test.want)
			}
		}
	}
	for _, source := range []string{"+8", "-8", "1n+8", "n+", "n+missing"} {
		if got, ok := parseNamedStackConstantOffset(source); ok {
			t.Errorf("invalid named offset %q accepted as %d", source, got)
		}
	}
}

func TestARM64SingleCharacterStackSlots(t *testing.T) {
	source := "TEXT single_stack_names(SB),$32-0\nMOVD R0,n-8(SP)\nMOVD n-8(SP),R1\nRET\n"
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"single_stack_names": {Name: "single_stack_names", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "stack_names.ll", "stack_names.o", ir)
		})
	}
}
