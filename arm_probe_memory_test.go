package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestARMMemoryOffsetProbeNeedsMacroContext(t *testing.T) {
	instructions := []string{
		"MOVW gobuf_sp(R1), R13", "MOVW R0, g_stackguard0(g)",
		"MOVW (gobuf_sp+4)(R1), R2", "MOVW R2<<(SHIFT+1)(R1), R4",
		"MOVW R2@>SHIFT(R1), R4", "MOVW R2->SHIFT(R1), R4",
		"MOVW gobuf_lr(R1), LR",
	}
	for _, op := range []string{"MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
		instructions = append(instructions, op+" gobuf_sp(R1), R2", op+" R2, gobuf_sp(R1)")
	}
	for _, instruction := range instructions {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT macroprobe(SB),$0-0\n" + instruction + "\nRET\n"
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			if err := ProbeInstruction(ArchARM, "arm", ins); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unexpanded offset probe error=%v, want macro context", err)
			}
			if _, err := Translate(file, Options{Goarch: "arm", Sigs: map[string]FuncSig{"macroprobe": {Name: "macroprobe", Ret: Void}}}); err == nil {
				t.Fatal("translation silently accepted an unresolved memory offset")
			}
			resolved := "#define gobuf_sp 4\n#define g_stackguard0 8\n#define gobuf_lr 12\n#define LR R14\n#define SHIFT 1\n" + source
			requireARMGoAssemblerResult(t, resolved, true)
			file, err = Parse(ArchARM, resolved)
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
				ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: map[string]FuncSig{"macroprobe": {Name: "macroprobe", Ret: Void}}})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "probe.ll", "probe.o", ir)
			}
		})
	}
}

func TestParenthesizedMemoryExpressionIsNotDiscarded(t *testing.T) {
	for _, source := range []string{"(layout_offset+4)(R1)", "(layout_offset+4)(BX)(CX*2)", "(layout_offset+)(R1)"} {
		memory, ok := parseMem(source)
		if !ok || memory.OffRaw == "" {
			t.Errorf("%s: dropped unresolved or invalid displacement: %+v, parsed=%v", source, memory, ok)
		}
	}
}

func TestARMMemoryContextExpressionGrammar(t *testing.T) {
	for _, expression := range []string{
		"OFFSET", "+OFFSET", "-OFFSET", "~OFFSET", "(OFFSET+4)",
		"OFFSET-4", "OFFSET*4", "OFFSET/4", "OFFSET%4", "OFFSET<<2", "OFFSET>>2",
		"OFFSET&7", "OFFSET|7", "OFFSET^7", "R2<<(SHIFT+1)", "R2@>SHIFT", "R2->SHIFT", "OFFSET+'x'",
	} {
		if !armMemoryOffsetNeedsContext(MemRef{Base: "R1", OffRaw: expression}) {
			t.Errorf("symbolic integer expression %q did not require context", expression)
		}
	}
	for _, expression := range []string{"", "4", "'x'", "1.2", "R2", "g", "R2<<2", "R2<<R3", "R2<<(R3+1)", "OFFSET+", "!OFFSET", "OFFSET==4", "OFFSET(4)", "OFFSET.field"} {
		if armMemoryOffsetNeedsContext(MemRef{Base: "R1", OffRaw: expression}) {
			t.Errorf("concrete or invalid expression %q was hidden as context", expression)
		}
	}
}

func TestARMMemoryOffsetProbeRetainsConcreteValidation(t *testing.T) {
	for _, tc := range []struct {
		offset string
		valid  bool
	}{
		{"0(R1)", true}, {"R2<<2(R1)", true}, {"slot-4(SP)", true},
		{"R2<<R3(R1)", false}, {"R2<<32(R1)", false}, {"R2<<(R3+1)(R1)", false},
		{"(gobuf_sp+)(R1)", false},
	} {
		source := fmt.Sprintf("TEXT concreteprobe(SB),$0-0\nMOVW %s, R4\nRET\n", tc.offset)
		file, err := Parse(ArchARM, source)
		if err != nil {
			if tc.valid {
				t.Fatal(err)
			}
			continue
		}
		err = ProbeInstruction(ArchARM, "arm", file.Funcs[0].Instrs[1])
		if errors.Is(err, ErrProbeNeedsContext) || (err == nil) != tc.valid {
			t.Errorf("%s: err=%v, want concrete valid=%v", tc.offset, err, tc.valid)
		}
	}
}
