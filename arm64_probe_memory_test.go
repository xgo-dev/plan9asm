package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestARM64MemoryOffsetProbeNeedsMacroContext(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, base := range []string{"RSP", "R1"} {
		for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
			for _, store := range []bool{false, true} {
				instruction := fmt.Sprintf("%s machTimebaseInfo_denom(%s),R21", op, base)
				if store {
					instruction = fmt.Sprintf("%s R21,machTimebaseInfo_denom(%s)", op, base)
				}
				t.Run(instruction, func(t *testing.T) {
					source := "TEXT macroprobe(SB),$16-0\n" + instruction + "\nRET\n"
					file, err := Parse(ArchARM64, source)
					if err != nil {
						t.Fatal(err)
					}
					if err := ProbeInstruction(ArchARM64, "arm64", file.Funcs[0].Instrs[1]); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("unexpanded offset probe error=%v, want macro context", err)
					}
					options := Options{Goarch: "arm64", Sigs: map[string]FuncSig{"macroprobe": {Name: "macroprobe", Ret: Void}}}
					if _, err := Translate(file, options); err == nil {
						t.Fatal("translation silently accepted an unresolved memory offset")
					}
					resolved := "#define machTimebaseInfo_denom 4\n" + source
					requireARM64GoAssemblerResult(t, resolved, true)
					file, err = Parse(ArchARM64, resolved)
					if err != nil {
						t.Fatal(err)
					}
					for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
						options.TargetTriple = triple
						ir, err := Translate(file, options)
						if err != nil {
							t.Fatal(err)
						}
						compileLLVMToObject(t, llc, triple, "macro.ll", "macro.o", ir)
					}
				})
			}
		}
	}
}

func TestARM64MemoryOffsetProbeRetainsConcreteValidation(t *testing.T) {
	for _, test := range []struct {
		instruction string
		valid       bool
	}{
		{"MOVW 4(RSP),R21", true},
		{"MOVW slot+4(SP),R21", true},
		{"MOVW slot(SP),R21", true},
		{"PLDR (VL*1)(RSP),P0", true},
		{"MOVW (OFFSET+)(RSP),R21", false},
		{"MOVW R2<<R3(R1),R21", false},
		{"MOVW VL*1(R1),R21", false},
	} {
		t.Run(test.instruction, func(t *testing.T) {
			source := "TEXT probe(SB),$16-0\n" + test.instruction + "\nRET\n"
			if test.valid {
				requireARM64SVEGoAssemblerResult(t, source, true)
			}
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			err = ProbeInstruction(ArchARM64, "arm64", file.Funcs[0].Instrs[1])
			if errors.Is(err, ErrProbeNeedsContext) || (err == nil) != test.valid {
				t.Fatalf("probe error=%v, want concrete valid=%v", err, test.valid)
			}
		})
	}
}
