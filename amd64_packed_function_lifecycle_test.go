package plan9asm

import (
	"strings"
	"testing"
)

// These expectations describe the emitted native memory carrier, not the
// existence of an opcode in the implementation's family tables.
func TestX86PackedFunctionFeatureViews(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct {
			instruction string
			features    string
		}{
			{"PAVGB (AX),X1", "+sse2"},
			{"PAVGW (AX),X1", "+sse2"},
			{"PMULLW (AX),X1", "+sse2"},
			{"PMULHW (AX),X1", "+sse2"},
			{"PMULHUW (AX),X1", "+sse2"},
			{"PMULHRSW (AX),X1", "+sse2,+ssse3"},
			{"PMADDWL (AX),X1", "+sse2"},
			{"PMADDUBSW (AX),X1", "+sse2,+ssse3"},
			{"PMULULQ (AX),X1", "+sse2"},
			{"PMULDQ (AX),X1", "+sse2,+sse4.1"},
		} {
			t.Run(arch+"/"+row.instruction, func(t *testing.T) {
				function := Func{Instrs: []Instr{x86ScalarLaneInstruction(t, row.instruction)}}
				if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, function); got != row.features {
					t.Fatalf("native memory features = %q, want %q", got, row.features)
				}
				// A new function representation must not reuse a preceding
				// source's physical memory form, even when its slice is reused.
				function.Instrs[0].Args[0] = Operand{Kind: OpFP, FPOffset: 0}
				if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, function); got != "" {
					t.Fatalf("logical FP inherited native memory features: %q", got)
				}
			})
		}
	}
}

func TestX86PackedFunctionRegisterViews(t *testing.T) {
	for _, row := range []struct {
		source, physical Reg
	}{
		{AX, "M0"},
		{SP, "M4"},
	} {
		function := Func{Instrs: []Instr{
			{Op: "PAVGB", Args: []Operand{{Kind: OpReg, Reg: row.source}, {Kind: OpReg, Reg: "M1"}}},
		}}
		for _, arch := range []string{"amd64", "386"} {
			consumer := newX86Ctx(new(strings.Builder), function, FuncSig{}, nil, nil, arch, "", false)
			consumer.scanUsedRegs()
			if consumer.usedRegs[row.physical] != (arch == "amd64") {
				t.Fatalf("%s %s: physical bank discovery = %v", arch, row.source, consumer.usedRegs)
			}
			if function.Instrs[0].Args[0].Reg != row.source {
				t.Fatal("register discovery mutated the original GP spelling")
			}
		}
	}
}

func TestX86PackedFunctionLoweringAcrossLabels(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		source := "TEXT binary(SB),4,$0-0\n" +
			"PXOR X0,X0\nPXOR X1,X1\n" +
			"first:\nPAVGB X0,X1\nPMULHW X0,X1\nJMP second\n" +
			"second:\nPMADDWL X0,X1\nPMULULQ X0,X1\nPAVGB X0,X1\nRET\n"
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		options := Options{Goarch: arch, TargetTriple: triple,
			Sigs: map[string]FuncSig{"binary": {Name: "binary", Ret: Void}}}
		if _, err := Translate(file, options); err != nil {
			t.Fatal("complete initialized four-family function", arch, err)
		}
		// Reusing the parsed file in a later request must observe the new
		// invalid form rather than a preceding request's valid instruction.
		for index := range file.Funcs[0].Instrs {
			if file.Funcs[0].Instrs[index].Op == "PMULHW" {
				file.Funcs[0].Instrs[index].Args[0].Reg = "Y0"
				break
			}
		}
		if _, err := Translate(file, options); err == nil {
			t.Fatal("changed source retained a preceding valid form", arch)
		}
	}
}

func TestX86PackedFunctionErrorPrecedence(t *testing.T) {
	for _, row := range []struct {
		name, first, want string
	}{
		{"unknown_before_form", "NOT_AN_INSTRUCTION", "NOT_AN_INSTRUCTION"},
		{"lock_before_form", "LOCK", "LOCK"},
		{"repeat_before_form", "REP", "REP"},
	} {
		t.Run(row.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row.first+"\nVPAVGB X0,Y1,X2\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			consumer := newX86Ctx(new(strings.Builder), file.Funcs[0], FuncSig{Ret: Void}, nil, nil, "amd64", "", false)
			if err := consumer.lowerBlocks(); err == nil || !strings.Contains(err.Error(), row.want) {
				t.Fatalf("earlier source failure was displaced by a later form: %v", err)
			}
		})
	}
}
