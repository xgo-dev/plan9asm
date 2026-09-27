package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateAMD64LegacyDoubleShiftRegisterPair(t *testing.T) {
	src := `
TEXT shiftpair(SB),NOSPLIT,$0-0
	MOVQ $1, SI
	MOVQ $2, CX
	SHLQ $13, CX:SI
	RET
`
	translateAMD64EcosystemCase(t, src, "shiftpair")
}

func TestTranslateX86UD2CompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 assigns UD2 to ynone on both 386 and amd64: its complete
	// accepted surface is exactly the no-operand form.
	file, err := Parse(ArchAMD64, "TEXT ud2forms(SB),NOSPLIT,$0-0\n\tUD2\n")
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{goarch: "386", triple: "i386-unknown-linux-gnu"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs:         map[string]FuncSig{"ud2forms": {Name: "ud2forms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ll, "unreachable") {
				t.Fatalf("%s UD2 translation is not terminating:\n%s", target.goarch, ll)
			}
			compileLLVMToObject(t, llc, target.triple, "ud2-"+target.goarch+".ll", "ud2-"+target.goarch+".o", ll)
		})
	}
}

func TestTranslateX86UD2RejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\tUD2 AX\n")
	if err != nil {
		return
	}
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{goarch: "386", triple: "i386-unknown-linux-gnu"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
	} {
		if _, err := Translate(file, Options{
			TargetTriple: target.triple,
			Goarch:       target.goarch,
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("%s UD2 with an operand unexpectedly translated", target.goarch)
		}
	}
}

func TestTranslateAMD64ScalarShiftRotateCompleteGoAssemblerForms(t *testing.T) {
	// ROL/ROR/SAR/SAL/SHL/SHR share yshb/yshl. Each width accepts $1,
	// unsigned imm8, CL, and CX counts with a same-width GP-or-memory target.
	var src strings.Builder
	src.WriteString("TEXT scalarshiftrotateforms(SB),NOSPLIT,$0-0\n")
	for _, stem := range []string{"ROL", "ROR", "SAR", "SAL", "SHL", "SHR"} {
		for _, width := range []string{"B", "W", "L", "Q"} {
			op := stem + width
			if width == "B" {
				fmt.Fprintf(&src, "\t%s $1, AH\n", op)
				fmt.Fprintf(&src, "\t%s $255, R11\n", op)
				fmt.Fprintf(&src, "\t%s CL, (BX)\n", op)
				fmt.Fprintf(&src, "\t%s CX, AL\n", op)
			} else {
				fmt.Fprintf(&src, "\t%s $1, AX\n", op)
				fmt.Fprintf(&src, "\t%s $255, R11\n", op)
				fmt.Fprintf(&src, "\t%s CL, (BX)\n", op)
				fmt.Fprintf(&src, "\t%s CX, AX\n", op)
			}
		}
	}
	// Go's special double-shift table adds signed imm8/CL/CX, GP source,
	// GP-or-memory destination rows to SHL/SHR W/L/Q only.
	for _, op := range []string{"SHLW", "SHLL", "SHLQ", "SHRW", "SHRL", "SHRQ"} {
		fmt.Fprintf(&src, "\t%s $-128, AX, BX\n", op)
		fmt.Fprintf(&src, "\t%s $127, R11, (DI)\n", op)
		fmt.Fprintf(&src, "\t%s CL, AX, BX\n", op)
		fmt.Fprintf(&src, "\t%s CX, R11, (DI)\n", op)
	}
	src.WriteString("\tRET\n")
	ll := translateAMD64EcosystemCase(t, src.String(), "scalarshiftrotateforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "scalar-shift-rotate-forms.ll", "scalar-shift-rotate-forms.o", ll)
}

func TestTranslate386ScalarShiftRotateCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT scalarshiftrotateforms386(SB),NOSPLIT,$0-0\n")
	for _, stem := range []string{"ROL", "ROR", "SAR", "SAL", "SHL", "SHR"} {
		for _, width := range []string{"B", "W", "L"} {
			op := stem + width
			if width == "B" {
				fmt.Fprintf(&src, "\t%s $1, AH\n", op)
				fmt.Fprintf(&src, "\t%s $255, DX\n", op)
				fmt.Fprintf(&src, "\t%s CL, (BX)\n", op)
				fmt.Fprintf(&src, "\t%s CX, AL\n", op)
				fmt.Fprintf(&src, "\t%s $1, BP\n", op)
				fmt.Fprintf(&src, "\t%s $255, SI\n", op)
				fmt.Fprintf(&src, "\t%s CL, DI\n", op)
			} else {
				fmt.Fprintf(&src, "\t%s $1, AX\n", op)
				fmt.Fprintf(&src, "\t%s $255, SI\n", op)
				fmt.Fprintf(&src, "\t%s CL, (BX)\n", op)
				fmt.Fprintf(&src, "\t%s CX, DI\n", op)
			}
		}
	}
	for _, op := range []string{"SHLW", "SHLL", "SHRW", "SHRL"} {
		fmt.Fprintf(&src, "\t%s $-128, AX, BX\n", op)
		fmt.Fprintf(&src, "\t%s $127, SI, (DI)\n", op)
		fmt.Fprintf(&src, "\t%s CL, AX, BX\n", op)
		fmt.Fprintf(&src, "\t%s CX, SI, (DI)\n", op)
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"scalarshiftrotateforms386": {Name: "scalarshiftrotateforms386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "scalar-shift-rotate-386-forms.ll", "scalar-shift-rotate-386-forms.o", ll)
}

func TestTranslateX86PortIOCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT portioforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"INB", "INW", "INL", "OUTB", "OUTW", "OUTL"} {
		fmt.Fprintf(&src, "\t%s\n", op)
		fmt.Fprintf(&src, "\t%s $7\n", op)
	}
	for _, op := range []string{"INSB", "INSW", "INSL", "OUTSB", "OUTSW", "OUTSL"} {
		fmt.Fprintf(&src, "\t%s\n", op)
		fmt.Fprintf(&src, "\tCLD; REP; %s\n", op)
		fmt.Fprintf(&src, "\tSTD; REPN; %s\n", op)
		fmt.Fprintln(&src, "\tCLD")
	}
	src.WriteString("\tRET\n")

	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{goarch: "386", triple: "i386-unknown-linux-gnu"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"portioforms": {Name: "portioforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`asm sideeffect "inb`, `asm sideeffect "inw`, `asm sideeffect "inl`,
				`asm sideeffect "outb`, `asm sideeffect "outw`, `asm sideeffect "outl`,
				`asm sideeffect "insb`, `asm sideeffect "insw`, `asm sideeffect "insl`,
				`asm sideeffect "outsb`, `asm sideeffect "outsw`, `asm sideeffect "outsl`,
				`asm sideeffect "rep; insb`, `asm sideeffect "rep; outsb`,
				`asm sideeffect "repne; insb`, `asm sideeffect "repne; outsb`,
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s port-I/O translation missing %q:\n%s", target.goarch, want, ll)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "port-io-"+target.goarch+".ll", "port-io-"+target.goarch+".o", ll)
		})
	}
}

func TestTranslateX86PortIORejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{goarch: "386", triple: "i386-unknown-linux-gnu"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
	} {
		for _, instruction := range []string{
			"INB AX",
			"INW $1, AX",
			"OUTL AX",
			"OUTB $1, AX",
			"INSB AX",
			"OUTSL (SI)",
			"REP; INL",
		} {
			name := target.goarch + "/" + strings.NewReplacer(" ", "_", ";", "_").Replace(instruction)
			t.Run(name, func(t *testing.T) {
				file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
				if err != nil {
					return
				}
				if _, err := Translate(file, Options{
					TargetTriple: target.triple,
					Goarch:       target.goarch,
					Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
				}); err == nil {
					t.Fatalf("%s %q unexpectedly translated", target.goarch, instruction)
				}
			})
		}
	}
}

func TestTranslateX86StringInstructionsCompleteGoAssemblerForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		goarch string
		triple string
		widths []string
	}{
		{goarch: "386", triple: "i386-unknown-linux-gnu", widths: []string{"B", "W", "L"}},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", widths: []string{"B", "W", "L", "Q"}},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			var src strings.Builder
			src.WriteString("TEXT stringforms(SB),NOSPLIT,$0-0\n")
			for _, stem := range []string{"MOVS", "STOS", "SCAS"} {
				for _, width := range target.widths {
					op := stem + width
					fmt.Fprintf(&src, "\t%s\n", op)
					fmt.Fprintf(&src, "\tCLD; REP; %s\n", op)
					fmt.Fprintf(&src, "\tSTD; REPN; %s\n", op)
					fmt.Fprintln(&src, "\tCLD")
				}
			}
			src.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs:         map[string]FuncSig{"stringforms": {Name: "stringforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, stem := range []string{"movs", "rep_stos", "rep_scas"} {
				for _, width := range target.widths {
					want := "@__plan9asm_" + stem + strings.ToLower(width)
					if !strings.Contains(ll, want) {
						t.Fatalf("%s string translation missing %q:\n%s", target.goarch, want, ll)
					}
				}
			}
			compileLLVMToObject(t, llc, target.triple, "string-forms-"+target.goarch+".ll", "string-forms-"+target.goarch+".o", ll)
		})
	}
}

func TestTranslate386RejectsQwordStringInstructions(t *testing.T) {
	for _, op := range []string{"MOVSQ", "STOSQ", "SCASQ"} {
		t.Run(op, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+op+"\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("386 %s unexpectedly translated", op)
			}
		})
	}
}

func TestTranslate386UsesUniqueFPResultNamesForLegacyOffsets(t *testing.T) {
	src := `TEXT legacyresults(SB),NOSPLIT,$0-56
	MOVL AX, retax+28(FP)
	MOVL BX, retbx+32(FP)
	MOVL CX, retcx+40(FP)
	MOVL DX, retdx+44(FP)
	MOVL SI, retsi+48(FP)
	MOVL DI, retdi+52(FP)
	MOVL BP, retbp+56(FP)
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	results := make([]FrameSlot, 0, 7)
	names := []string{"retax", "retbx", "retcx", "retdx", "retsi", "retdi", "retbp"}
	for i, name := range names {
		results = append(results, FrameSlot{Offset: int64(28 + 4*i), Type: I32, Index: i, Field: -1, Name: name})
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"legacyresults": {
				Name:  "legacyresults",
				Args:  []LLVMType{I32, I32, I32, I32, I32, I32, I32},
				Ret:   LLVMType("{ i32, i32, i32, i32, i32, i32, i32 }"),
				Frame: FrameLayout{Results: results},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "legacy-named-results.ll", "legacy-named-results.o", ll)
}

func TestTranslateX86MOVLScalarResultMemoryForms(t *testing.T) {
	file, err := Parse(ArchAMD64, `TEXT movlresults(SB),NOSPLIT,$0-8
	MOVL $-1, first+0(FP)
	MOVL AX, second+4(FP)
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{goarch: "386", triple: "i386-unknown-linux-gnu"},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{"movlresults": {
					Name: "movlresults",
					Ret:  LLVMType("{ i32, i32 }"),
					Frame: FrameLayout{Results: []FrameSlot{
						{Offset: 0, Type: I32, Index: 0, Field: -1, Name: "first"},
						{Offset: 4, Type: I32, Index: 1, Field: -1, Name: "second"},
					}},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "movl-result-forms-"+target.goarch+".ll", "movl-result-forms-"+target.goarch+".o", ll)
		})
	}
}

func TestTranslateX86MOVLRejectsMemoryToResultMemory(t *testing.T) {
	for _, source := range []string{"arg+0(FP)", "(AX)", "global(SB)"} {
		t.Run(strings.NewReplacer("(", "_", ")", "_", "+", "_").Replace(source), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-4\n\tMOVL "+source+", result+0(FP)\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{"bad": {
					Name:  "bad",
					Ret:   I32,
					Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1, Name: "result"}}},
				}},
			}); err == nil {
				t.Fatalf("MOVL %s, result(FP) unexpectedly translated", source)
			}
		})
	}
}

func TestTranslateX86ImplicitMultiplyDivideCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27's ydivb/ydivl tables give MUL, IMUL, DIV, and IDIV one
	// GP-or-memory operand. IMUL W/L/Q additionally uses yimul/yimul3 for
	// the two- and three-operand signed multiply forms.
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		goarch string
		triple string
		widths []string
	}{
		{goarch: "386", triple: "i386-unknown-linux-gnu", widths: []string{"B", "W", "L"}},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", widths: []string{"B", "W", "L", "Q"}},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			var src strings.Builder
			src.WriteString("TEXT muldivforms(SB),NOSPLIT,$0-0\n")
			for _, width := range target.widths {
				reg := "BX"
				for _, stem := range []string{"MUL", "IMUL", "DIV", "IDIV"} {
					fmt.Fprintf(&src, "\t%s%s %s\n", stem, width, reg)
					fmt.Fprintf(&src, "\t%s%s (SI)\n", stem, width)
				}
				if width != "B" {
					fmt.Fprintf(&src, "\tIMUL%s $-128, CX\n", width)
					fmt.Fprintf(&src, "\tIMUL%s $4294967295, DI\n", width)
					fmt.Fprintf(&src, "\tIMUL%s BX, CX\n", width)
					fmt.Fprintf(&src, "\tIMUL%s (SI), DI\n", width)
					fmt.Fprintf(&src, "\tIMUL3%s $-128, BX, CX\n", width)
					fmt.Fprintf(&src, "\tIMUL3%s $4294967295, (SI), DI\n", width)
				}
			}
			src.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs:         map[string]FuncSig{"muldivforms": {Name: "muldivforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "mul-div-forms-"+target.goarch+".ll", "mul-div-forms-"+target.goarch+".o", ll)
		})
	}
}

func TestTranslateX86ImplicitMultiplyDivideRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	common := []string{
		"MULB $1",
		"DIVW AX, BX",
		"IDIVL AX, BX",
		"IMULB AX, BX",
		"IMUL3B $1, AX, BX",
		"IMULW (AX), (BX)",
		"IMUL3W AX, BX, CX",
		"IMUL3L $1, AX, (BX)",
		"IMULL X0",
	}
	for _, target := range []struct {
		goarch       string
		triple       string
		instructions []string
	}{
		{goarch: "386", triple: "i386-unknown-linux-gnu", instructions: append(append([]string{}, common...), "MULQ AX", "IMULQ AX", "DIVQ AX", "IDIVQ AX", "IMUL3Q $1, AX, BX")},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instructions: append(append([]string{}, common...), "IMULQ $4294967296, AX", "IMUL3Q $-2147483649, AX, BX")},
	} {
		for _, instruction := range target.instructions {
			name := target.goarch + "/" + strings.NewReplacer(" ", "_", ",", "_", "(", "_", ")", "_").Replace(instruction)
			t.Run(name, func(t *testing.T) {
				file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
				if err != nil {
					return
				}
				if _, err := Translate(file, Options{
					TargetTriple: target.triple,
					Goarch:       target.goarch,
					Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
				}); err == nil {
					t.Fatalf("%s accepted %q outside Go 1.27's multiply/divide tables", target.goarch, instruction)
				}
			})
		}
	}
}

func TestTranslateAMD64ScalarShiftRotateRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"SHRB $-1, AL",
		"SHLB $256, AL",
		"SARW AX, BX",
		"SALL (AX), BX",
		"ROLL $1, X1",
		"RORB $1, X1",
		"RORQ.Z $1, AX, AX",
		"SHLB $1, AL, BL",
		"SARL $1, AX, BX",
		"SALW $1, AX, BX",
		"ROLQ $1, AX, BX",
		"SHLL $128, AX, BX",
		"SHRL DX, AX, BX",
		"SHLW $1, (AX), BX",
		"SHRQ $1, AX, $2",
		"SHLB $1, AX, BX",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidscalarshiftrotate(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidscalarshiftrotate": {Name: "invalidscalarshiftrotate", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's shift/rotate tables", instruction)
			}
		})
	}
}

func TestTranslate386ScalarShiftRotateRejectsArchitectureRestrictedForms(t *testing.T) {
	for _, instruction := range []string{
		"SHRQ $1, AX",
		"ROLQ CL, (BX)",
		"SHRB $1, SP",
		"SARL $1, R8",
		"SHLL $1, R8, AX",
		"SHLQ $1, AX, BX",
		"SHRQ CL, AX, (BX)",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidscalarshiftrotate386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"invalidscalarshiftrotate386": {Name: "invalidscalarshiftrotate386", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which Go 1.27 rejects for 386", instruction)
			}
		})
	}
}

func TestTranslateAMD64IncDecCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT incdecforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"INCB", "DECB"} {
		fmt.Fprintf(&src, "\t%s AL\n", op)
		fmt.Fprintf(&src, "\t%s AH\n", op)
		fmt.Fprintf(&src, "\t%s BPB\n", op)
		fmt.Fprintf(&src, "\t%s R15B\n", op)
		fmt.Fprintf(&src, "\t%s R11\n", op)
		fmt.Fprintf(&src, "\t%s (BX)\n", op)
	}
	for _, op := range []string{"INCW", "DECW", "INCL", "DECL", "INCQ", "DECQ"} {
		fmt.Fprintf(&src, "\t%s AX\n", op)
		fmt.Fprintf(&src, "\t%s R11\n", op)
		fmt.Fprintf(&src, "\t%s (BX)\n", op)
	}
	src.WriteString("\tRET\n")
	ll := translateAMD64EcosystemCase(t, src.String(), "incdecforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "inc-dec-forms.ll", "inc-dec-forms.o", ll)
}

func TestTranslate386IncDecCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT incdecforms386(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"INCB", "DECB"} {
		fmt.Fprintf(&src, "\t%s AL\n", op)
		fmt.Fprintf(&src, "\t%s AH\n", op)
		fmt.Fprintf(&src, "\t%s DX\n", op)
		fmt.Fprintf(&src, "\t%s BP\n", op)
		fmt.Fprintf(&src, "\t%s SI\n", op)
		fmt.Fprintf(&src, "\t%s DI\n", op)
		fmt.Fprintf(&src, "\t%s (BX)\n", op)
	}
	for _, op := range []string{"INCW", "DECW", "INCL", "DECL"} {
		fmt.Fprintf(&src, "\t%s AX\n", op)
		fmt.Fprintf(&src, "\t%s SI\n", op)
		fmt.Fprintf(&src, "\t%s (BX)\n", op)
		fmt.Fprintf(&src, "\t%s SP\n", op)
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"incdecforms386": {Name: "incdecforms386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "inc-dec-386-forms.ll", "inc-dec-386-forms.o", ll)
}

func TestTranslateAMD64IncDecRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"INCB",
		"INCW AX, BX",
		"DECL $1",
		"DECQ X0",
		"INCQ.Z AX",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidincdec(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidincdec": {Name: "invalidincdec", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's INC/DEC tables", instruction)
			}
		})
	}
}

func TestTranslate386IncDecRejectsArchitectureRestrictedForms(t *testing.T) {
	for _, instruction := range []string{
		"INCB SP",
		"INCW R8",
		"DECL R11",
		"INCQ AX",
		"DECQ (BX)",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidincdec386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"invalidincdec386": {Name: "invalidincdec386", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which Go 1.27 rejects for 386", instruction)
			}
		})
	}
}

func TestTranslateAMD64PackedWordMultiplyCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT packedwordmulforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"PMULLW", "PMULHW", "PMULHUW"} {
		fmt.Fprintf(&src, "\t%s M0, M1\n", op)
		fmt.Fprintf(&src, "\t%s (AX), M1\n", op)
		fmt.Fprintf(&src, "\t%s X0, X1\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X1\n", op)
	}
	src.WriteString("\tPMULHRSW X0, X1\n\tPMULHRSW (AX), X1\n")
	for _, op := range []string{"VPMULLW", "VPMULHW", "VPMULHUW", "VPMULHRSW"} {
		fmt.Fprintf(&src, "\t%s X0, X1, X2\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X1, X2\n", op)
		fmt.Fprintf(&src, "\t%s Y0, Y1, Y2\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Y1, Y2\n", op)
		fmt.Fprintf(&src, "\t%s Z0, Z1, Z2\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Z1, Z2\n", op)
		fmt.Fprintf(&src, "\t%s X20, X21, X22\n", op)
		fmt.Fprintf(&src, "\t%s X0, X1, K1, X2\n", op)
		fmt.Fprintf(&src, "\t%s.Z Y0, Y1, K2, Y2\n", op)
		fmt.Fprintf(&src, "\t%s.Z Z0, Z1, K3, Z2\n", op)
	}
	src.WriteString("\tRET\n")
	ll := translateAMD64EcosystemCase(t, src.String(), "packedwordmulforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "packed-word-multiply-forms.ll", "packed-word-multiply-forms.o", ll)
}

func TestTranslate386PackedWordMultiplyCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT packedwordmulforms386(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"PMULLW", "PMULHW", "PMULHUW", "PMULHRSW"} {
		fmt.Fprintf(&src, "\t%s X0, X1\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X1\n", op)
	}
	for _, op := range []string{"VPMULLW", "VPMULHW", "VPMULHUW", "VPMULHRSW"} {
		fmt.Fprintf(&src, "\t%s X0, X1, X2\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X1, X2\n", op)
		fmt.Fprintf(&src, "\t%s Y0, Y1, Y2\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Y1, Y2\n", op)
		fmt.Fprintf(&src, "\t%s X20, X21, X22\n", op)
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"packedwordmulforms386": {Name: "packedwordmulforms386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "packed-word-multiply-386-forms.ll", "packed-word-multiply-386-forms.o", ll)
}

func TestTranslateAMD64PackedWordMultiplyRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PMULLW Y0, Y1",
		"PMULHRSW M0, M1",
		"PMULHW.Z X0, X1",
		"VPMULLW.BCST (AX), X1, X2",
		"VPMULHW.SAE X0, X1, X2",
		"VPMULHUW.Z X0, X1, X2",
		"VPMULLW X0, Y1, Y2",
		"VPMULHW X0, X1, K0, X2",
		"VPMULHUW X0, X1, AX, X2",
		"VPMULHRSW X0, X1, K1, Y2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidpackedwordmul(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedwordmul": {Name: "invalidpackedwordmul", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's packed-word multiply tables", instruction)
			}
		})
	}
}

func TestTranslate386PackedWordMultiplyRejectsArchitectureRestrictedForms(t *testing.T) {
	for _, instruction := range []string{
		"PMULLW M0, M1",
		"PMULHW (AX), M1",
		"PMULHUW X8, X0",
		"PMULHRSW X0, X8",
		"VPMULLW Z0, Z1, Z2",
		"VPMULHW X0, X1, K1, X2",
		"VPMULHUW.Z X0, X1, K1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidpackedwordmul386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"invalidpackedwordmul386": {Name: "invalidpackedwordmul386", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which Go 1.27 rejects for 386", instruction)
			}
		})
	}
}

func TestTranslateAMD64PackedWordMultiplyAddCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 uses ymm for PMADDWL and _yvandnpd for VPMADDWD.
	src := `TEXT packedwordmaddforms(SB),NOSPLIT,$0-0
	PMADDWL M0, M1
	PMADDWL (AX), M2
	PMADDWL X0, X1
	PMADDWL (AX), X15
	VPMADDWD X0, X1, X2
	VPMADDWD (AX), X1, X2
	VPMADDWD Y0, Y1, Y2
	VPMADDWD (AX), Y1, Y2
	VPMADDWD Z0, Z1, Z2
	VPMADDWD (AX), Z1, Z2
	VPMADDWD X20, X21, X22
	VPMADDWD Y20, Y21, Y22
	VPMADDWD Z20, Z21, Z22
	VPMADDWD X20, X21, K1, X22
	VPMADDWD.Z (AX), X21, K2, X22
	VPMADDWD Y20, Y21, K3, Y22
	VPMADDWD.Z (AX), Y21, K4, Y22
	VPMADDWD Z20, Z21, K5, Z22
	VPMADDWD.Z (AX), Z21, K6, Z22
	RET
`
	ll := translateAMD64EcosystemCase(t, src, "packedwordmaddforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "packed-word-multiply-add-forms.ll", "packed-word-multiply-add-forms.o", ll)
}

func TestTranslate386PackedWordMultiplyAddCompleteGoAssemblerForms(t *testing.T) {
	src := `TEXT packedwordmaddforms386(SB),NOSPLIT,$0-0
	PMADDWL X0, X1
	PMADDWL (AX), X7
	VPMADDWD X0, X1, X2
	VPMADDWD (AX), X1, X2
	VPMADDWD Y0, Y1, Y2
	VPMADDWD (AX), Y1, Y2
	VPMADDWD Z0, Z1, Z7
	VPMADDWD (AX), Z6, Z7
	VPMADDWD X20, X21, X22
	VPMADDWD Y20, Y21, Y22
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"packedwordmaddforms386": {Name: "packedwordmaddforms386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "packed-word-multiply-add-386-forms.ll", "packed-word-multiply-add-386-forms.o", ll)
}

func TestTranslateAMD64PackedWordMultiplyAddRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PMADDWL.Z X0, X1",
		"PMADDWL X0",
		"PMADDWL Y0, Y1",
		"PMADDWL X0, M1",
		"PMADDWL X16, X1",
		"PMADDWL X0, (AX)",
		"VPMADDWD X0, X1",
		"VPMADDWD M0, M1, M2",
		"VPMADDWD X0, Y1, Y2",
		"VPMADDWD X0, X1, (AX)",
		"VPMADDWD.BCST (AX), X1, X2",
		"VPMADDWD.Z X0, X1, X2",
		"VPMADDWD X0, X1, K0, X2",
		"VPMADDWD X0, X1, AX, X2",
		"VPMADDWD X0, X1, K1, Y2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT invalidpackedwordmadd(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedwordmadd": {Name: "invalidpackedwordmadd", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's PMADDWL/VPMADDWD tables", instruction)
			}
		})
	}
}

func TestTranslate386PackedWordMultiplyAddRejectsArchitectureRestrictedForms(t *testing.T) {
	for _, instruction := range []string{
		"PMADDWL M0, M1",
		"PMADDWL (AX), M1",
		"PMADDWL X8, X0",
		"PMADDWL X0, X8",
		"VPMADDWD Z8, Z1, Z2",
		"VPMADDWD Z0, Z1, Z8",
		"VPMADDWD X0, X1, K1, X2",
		"VPMADDWD.Z X0, X1, K1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT invalidpackedwordmadd386(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"invalidpackedwordmadd386": {Name: "invalidpackedwordmadd386", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which Go 1.27 rejects for 386", instruction)
			}
		})
	}
}

func TestTranslateAMD64PackedFloatShuffleCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT packedfloatshuffleforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"SHUFPS", "SHUFPD"} {
		fmt.Fprintf(&src, "\t%s $0, X0, X1\n", op)
		fmt.Fprintf(&src, "\t%s $255, (AX), X15\n", op)
	}
	for _, op := range []string{"VSHUFPS", "VSHUFPD"} {
		fmt.Fprintf(&src, "\t%s $0, X0, X1, X2\n", op)
		fmt.Fprintf(&src, "\t%s $255, (AX), X1, X2\n", op)
		fmt.Fprintf(&src, "\t%s $1, Y0, Y1, Y2\n", op)
		fmt.Fprintf(&src, "\t%s $2, (AX), Y1, Y2\n", op)
		fmt.Fprintf(&src, "\t%s $3, Z0, Z1, Z2\n", op)
		fmt.Fprintf(&src, "\t%s $4, (AX), Z1, Z2\n", op)
		fmt.Fprintf(&src, "\t%s $5, X20, X21, X22\n", op)
		fmt.Fprintf(&src, "\t%s $6, X0, X1, K1, X2\n", op)
		fmt.Fprintf(&src, "\t%s.Z $7, Y0, Y1, K2, Y2\n", op)
		fmt.Fprintf(&src, "\t%s.BCST $8, (AX), Z1, Z2\n", op)
		fmt.Fprintf(&src, "\t%s.BCST.Z $9, (AX), Z1, K3, Z2\n", op)
	}
	src.WriteString("\tRET\n")
	ll := translateAMD64EcosystemCase(t, src.String(), "packedfloatshuffleforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "packed-float-shuffle-forms.ll", "packed-float-shuffle-forms.o", ll)
}

func TestTranslate386PackedFloatShuffleCompleteGoAssemblerForms(t *testing.T) {
	src := `
TEXT packedfloatshuffleforms386(SB),NOSPLIT,$0-0
	SHUFPS $0, X0, X1
	SHUFPS $255, (AX), X7
	SHUFPD $0, X0, X1
	SHUFPD $255, (AX), X7
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"packedfloatshuffleforms386": {Name: "packedfloatshuffleforms386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "packed-float-shuffle-386-forms.ll", "packed-float-shuffle-386-forms.o", ll)
}

func TestTranslateAMD64PackedFloatShuffleRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"SHUFPS $-1, X0, X1",
		"SHUFPD $256, X0, X1",
		"SHUFPS.Z $0, X0, X1",
		"VSHUFPS $0, X0, X1",
		"VSHUFPD.SAE $0, X0, X1, X2",
		"VSHUFPS.Z $0, X0, X1, X2",
		"VSHUFPD $0, X0, Y1, Y2",
		"VSHUFPS $0, X0, X1, K0, X2",
		"VSHUFPD $0, X0, X1, AX, X2",
		"VSHUFPS.BCST $0, X0, X1, X2",
		"VSHUFPD.BCST $0, (AX), X1, Y2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidpackedfloatshuffle(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedfloatshuffle": {Name: "invalidpackedfloatshuffle", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's packed-float shuffle tables", instruction)
			}
		})
	}
}

func TestTranslate386PackedFloatShuffleRejectsArchitectureRestrictedForms(t *testing.T) {
	for _, instruction := range []string{
		"SHUFPS $0, X8, X0",
		"SHUFPD $0, X0, X8",
		"VSHUFPS $0, X0, X1, X2",
		"VSHUFPD $0, Y0, Y1, Y2",
		"VSHUFPS.BCST $0, (AX), X1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidpackedfloatshuffle386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"invalidpackedfloatshuffle386": {Name: "invalidpackedfloatshuffle386", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which Go 1.27 rejects for 386", instruction)
			}
		})
	}
}

func TestTranslateAMD64ImmediatePackedBlendCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT immediatepackedblendforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"PBLENDW", "BLENDPS", "BLENDPD"} {
		fmt.Fprintf(&src, "\t%s $0, X0, X1\n", op)
		fmt.Fprintf(&src, "\t%s $255, (AX), X15\n", op)
	}
	for _, op := range []string{"VPBLENDW", "VPBLENDD", "VBLENDPS", "VBLENDPD"} {
		fmt.Fprintf(&src, "\t%s $0, X0, X1, X2\n", op)
		fmt.Fprintf(&src, "\t%s $255, (AX), X1, X15\n", op)
		fmt.Fprintf(&src, "\t%s $1, Y0, Y1, Y2\n", op)
		fmt.Fprintf(&src, "\t%s $254, (AX), Y1, Y15\n", op)
	}
	src.WriteString("\tRET\n")
	ll := translateAMD64EcosystemCase(t, src.String(), "immediatepackedblendforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "immediate-packed-blend-forms.ll", "immediate-packed-blend-forms.o", ll)
}

func TestTranslate386ImmediatePackedBlendCompleteGoAssemblerForms(t *testing.T) {
	src := `
TEXT immediatepackedblendforms386(SB),NOSPLIT,$0-0
	PBLENDW $0, X0, X1
	PBLENDW $255, (AX), X7
	BLENDPS $0, X0, X1
	BLENDPS $255, (AX), X7
	BLENDPD $0, X0, X1
	BLENDPD $255, (AX), X7
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"immediatepackedblendforms386": {Name: "immediatepackedblendforms386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "immediate-packed-blend-386-forms.ll", "immediate-packed-blend-386-forms.o", ll)
}

func TestTranslateAMD64ImmediatePackedBlendRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PBLENDW $-1, X0, X1",
		"BLENDPS $256, X0, X1",
		"BLENDPD.Z $0, X0, X1",
		"PBLENDW $0, X20, X1",
		"BLENDPS $0, X0, X20",
		"VPBLENDW $-1, X0, X1, X2",
		"VPBLENDD $256, X0, X1, X2",
		"VBLENDPS $0, X0, X1",
		"VBLENDPD $0, X0, Y1, Y2",
		"VPBLENDW $0, X20, X1, X2",
		"VPBLENDD $0, Y0, Y20, Y2",
		"VBLENDPS $0, Z0, Z1, Z2",
		"VBLENDPD.Z $0, X0, X1, X2",
		"VPBLENDW.BCST $0, (AX), X1, X2",
		"VPBLENDD $0, X0, X1, K1, X2",
		"VBLENDPS $0, X0, (AX), X2",
		"VBLENDPD $0, X0, X1, (AX)",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidimmediatepackedblend(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidimmediatepackedblend": {Name: "invalidimmediatepackedblend", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's immediate packed-blend tables", instruction)
			}
		})
	}
}

func TestTranslate386ImmediatePackedBlendRejectsArchitectureRestrictedForms(t *testing.T) {
	for _, instruction := range []string{
		"PBLENDW $0, X8, X0",
		"BLENDPS $0, X0, X8",
		"BLENDPD.Z $0, X0, X1",
		"VPBLENDW $0, X0, X1, X2",
		"VPBLENDD $0, Y0, Y1, Y2",
		"VBLENDPS $0, X0, X1, X2",
		"VBLENDPD $0, Y0, Y1, Y2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidimmediatepackedblend386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"invalidimmediatepackedblend386": {Name: "invalidimmediatepackedblend386", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which Go 1.27 rejects for 386", instruction)
			}
		})
	}
}

func TestTranslateAMD64PackedUnpackCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT packedunpackforms(SB),NOSPLIT,$0-0\n")
	legacyMMX := []string{"PUNPCKLBW", "PUNPCKHBW", "PUNPCKLWL", "PUNPCKHWL", "PUNPCKLLQ", "PUNPCKHLQ"}
	for _, op := range legacyMMX {
		fmt.Fprintf(&src, "\t%s M0, M1\n", op)
		fmt.Fprintf(&src, "\t%s (AX), M7\n", op)
		fmt.Fprintf(&src, "\t%s X0, X1\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X15\n", op)
	}
	for _, op := range []string{"PUNPCKLQDQ", "PUNPCKHQDQ"} {
		fmt.Fprintf(&src, "\t%s X0, X1\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X15\n", op)
	}
	vectorOps := []string{
		"VPUNPCKLBW", "VPUNPCKHBW", "VPUNPCKLWD", "VPUNPCKHWD",
		"VPUNPCKLDQ", "VPUNPCKHDQ", "VPUNPCKLQDQ", "VPUNPCKHQDQ",
	}
	for _, op := range vectorOps {
		fmt.Fprintf(&src, "\t%s X0, X1, X2\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X1, X15\n", op)
		fmt.Fprintf(&src, "\t%s Y0, Y1, Y2\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Y1, Y15\n", op)
		fmt.Fprintf(&src, "\t%s Z0, Z1, Z2\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Z1, Z31\n", op)
		fmt.Fprintf(&src, "\t%s X20, X21, X22\n", op)
		fmt.Fprintf(&src, "\t%s Y20, Y21, K1, Y22\n", op)
		fmt.Fprintf(&src, "\t%s.Z (AX), Z21, K2, Z22\n", op)
		if strings.Contains(op, "DQ") {
			fmt.Fprintf(&src, "\t%s.BCST (AX), X21, X22\n", op)
			fmt.Fprintf(&src, "\t%s.BCST (AX), Y21, Y22\n", op)
			fmt.Fprintf(&src, "\t%s.BCST (AX), Z21, Z22\n", op)
			fmt.Fprintf(&src, "\t%s.BCST.Z (AX), Z21, K3, Z22\n", op)
		}
	}
	src.WriteString("\tRET\n")
	ll := translateAMD64EcosystemCase(t, src.String(), "packedunpackforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "packed-unpack-forms.ll", "packed-unpack-forms.o", ll)
}

func TestTranslate386PackedUnpackCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT packedunpackforms386(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{
		"PUNPCKLBW", "PUNPCKHBW", "PUNPCKLWL", "PUNPCKHWL",
		"PUNPCKLLQ", "PUNPCKHLQ", "PUNPCKLQDQ", "PUNPCKHQDQ",
	} {
		fmt.Fprintf(&src, "\t%s X0, X1\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X7\n", op)
	}
	for _, op := range []string{
		"VPUNPCKLBW", "VPUNPCKHBW", "VPUNPCKLWD", "VPUNPCKHWD",
		"VPUNPCKLDQ", "VPUNPCKHDQ", "VPUNPCKLQDQ", "VPUNPCKHQDQ",
	} {
		fmt.Fprintf(&src, "\t%s X0, X1, X2\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Y1, Y2\n", op)
		fmt.Fprintf(&src, "\t%s X8, X9, X10\n", op)
		fmt.Fprintf(&src, "\t%s Z0, Z1, Z2\n", op)
		if strings.Contains(op, "DQ") {
			fmt.Fprintf(&src, "\t%s.BCST (AX), Y1, Y2\n", op)
		}
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"packedunpackforms386": {Name: "packedunpackforms386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "packed-unpack-386-forms.ll", "packed-unpack-386-forms.o", ll)
}

func TestTranslateAMD64PackedUnpackRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PUNPCKLBW.Z X0, X1",
		"PUNPCKLWL X20, X1",
		"PUNPCKHWL X0, X20",
		"PUNPCKLLQ M0, X1",
		"PUNPCKHLQ X0, M1",
		"PUNPCKLQDQ M0, M1",
		"PUNPCKHQDQ Y0, X1",
		"VPUNPCKLBW X0, X1",
		"VPUNPCKHWD X0, Y1, Y2",
		"VPUNPCKLDQ X0, (AX), X2",
		"VPUNPCKHQDQ X0, X1, (AX)",
		"VPUNPCKLBW X32, X1, X2",
		"VPUNPCKHWD Z0, Z1, K0, Z2",
		"VPUNPCKLWD.Z Z0, Z1, Z2",
		"VPUNPCKHBW.BCST (AX), X1, X2",
		"VPUNPCKLWD.BCST (AX), Y1, Y2",
		"VPUNPCKLDQ.BCST X0, X1, X2",
		"VPUNPCKHQDQ.BCST (AX), X1, Y2",
		"VPUNPCKHDQ.SAE X0, X1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidpackedunpack(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedunpack": {Name: "invalidpackedunpack", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's packed-unpack tables", instruction)
			}
		})
	}
}

func TestTranslate386PackedUnpackRejectsArchitectureRestrictedForms(t *testing.T) {
	for _, instruction := range []string{
		"PUNPCKLBW M0, M1",
		"PUNPCKHWL (AX), M1",
		"PUNPCKLQDQ M0, M1",
		"PUNPCKHBW X8, X0",
		"PUNPCKHLQ X0, X8",
		"VPUNPCKLWD Z8, Z1, Z2",
		"VPUNPCKHWD Z0, Z8, Z2",
		"VPUNPCKLDQ Z0, Z1, Z8",
		"VPUNPCKLBW X0, X1, K1, X2",
		"VPUNPCKLDQ.Z Z0, Z1, K1, Z2",
		"VPUNPCKHQDQ.BCST.Z (AX), Y1, K1, Y2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidpackedunpack386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"invalidpackedunpack386": {Name: "invalidpackedunpack386", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which Go 1.27 rejects for 386", instruction)
			}
		})
	}
}

func TestTranslateAMD64QwordPermuteCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT qwordpermuteforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"VPERMQ", "VPERMPD"} {
		fmt.Fprintf(&src, "\t%s $-128, Y0, Y1\n", op)
		fmt.Fprintf(&src, "\t%s $255, (AX), Y15\n", op)
		fmt.Fprintf(&src, "\t%s $0, Y20, Y21\n", op)
		fmt.Fprintf(&src, "\t%s $1, Z20, Z21\n", op)
		fmt.Fprintf(&src, "\t%s $2, Y20, K1, Y21\n", op)
		fmt.Fprintf(&src, "\t%s.Z $3, Z20, K2, Z21\n", op)
		fmt.Fprintf(&src, "\t%s.BCST $4, (AX), Y21\n", op)
		fmt.Fprintf(&src, "\t%s.BCST.Z $5, (AX), K3, Z21\n", op)
		fmt.Fprintf(&src, "\t%s Y0, Y1, Y2\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Y1, Y2\n", op)
		fmt.Fprintf(&src, "\t%s Z0, Z1, Z2\n", op)
		fmt.Fprintf(&src, "\t%s Y20, Y21, Y22\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Y21, K1, Y22\n", op)
		fmt.Fprintf(&src, "\t%s.Z Z20, Z21, K2, Z22\n", op)
		fmt.Fprintf(&src, "\t%s.BCST (AX), Y21, Y22\n", op)
		fmt.Fprintf(&src, "\t%s.BCST.Z (AX), Z21, K3, Z22\n", op)
	}
	src.WriteString("\tRET\n")
	ll := translateAMD64EcosystemCase(t, src.String(), "qwordpermuteforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "qword-permute-forms.ll", "qword-permute-forms.o", ll)
}

func TestTranslate386QwordPermuteCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT qwordpermuteforms386(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"VPERMQ", "VPERMPD"} {
		fmt.Fprintf(&src, "\t%s $-128, Y0, Y1\n", op)
		fmt.Fprintf(&src, "\t%s $255, (AX), Y7\n", op)
		fmt.Fprintf(&src, "\t%s $0, Y20, Y21\n", op)
		fmt.Fprintf(&src, "\t%s $1, Z0, Z1\n", op)
		fmt.Fprintf(&src, "\t%s.BCST $2, (AX), Y21\n", op)
		fmt.Fprintf(&src, "\t%s.BCST $3, (AX), Z7\n", op)
		fmt.Fprintf(&src, "\t%s Y0, Y1, Y2\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Y1, Y2\n", op)
		fmt.Fprintf(&src, "\t%s Z0, Z1, Z2\n", op)
		fmt.Fprintf(&src, "\t%s Y20, Y21, Y22\n", op)
		fmt.Fprintf(&src, "\t%s.BCST (AX), Z1, Z7\n", op)
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"qwordpermuteforms386": {Name: "qwordpermuteforms386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "qword-permute-386-forms.ll", "qword-permute-386-forms.o", ll)
}

func TestTranslateAMD64QwordPermuteRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"VPERMQ $-129, Y0, Y1",
		"VPERMPD $256, Y0, Y1",
		"VPERMQ $-1, Y20, Y21",
		"VPERMPD $-1, Z0, Z1",
		"VPERMQ.BCST $-1, (AX), Y1",
		"VPERMQ $0, X0, X1",
		"VPERMPD X0, X1, X2",
		"VPERMQ $0, Y0, Z1",
		"VPERMPD Y0, Z1, Z2",
		"VPERMQ Y0, (AX), Y2",
		"VPERMPD Y0, Y1, (AX)",
		"VPERMQ $0, Y0, K0, Y1",
		"VPERMPD Z0, Z1, K0, Z2",
		"VPERMQ.Z $0, Y0, Y1",
		"VPERMPD.Z Y0, Y1, Y2",
		"VPERMQ.BCST $0, Y0, Y1",
		"VPERMPD.BCST Y0, Y1, Y2",
		"VPERMQ.SAE $0, Y0, Y1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidqwordpermute(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidqwordpermute": {Name: "invalidqwordpermute", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's _yvpermq table", instruction)
			}
		})
	}
}

func TestTranslate386QwordPermuteRejectsArchitectureRestrictedForms(t *testing.T) {
	for _, instruction := range []string{
		"VPERMQ $-1, Y20, Y21",
		"VPERMPD $0, Z8, Z1",
		"VPERMQ $0, Z0, Z8",
		"VPERMPD Z8, Z1, Z2",
		"VPERMQ Z0, Z8, Z2",
		"VPERMPD Z0, Z1, Z8",
		"VPERMQ $0, Y0, K1, Y1",
		"VPERMPD Z0, Z1, K1, Z2",
		"VPERMQ.BCST.Z (AX), Z1, K1, Z2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidqwordpermute386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"invalidqwordpermute386": {Name: "invalidqwordpermute386", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which Go 1.27 rejects for 386", instruction)
			}
		})
	}
}

func TestTranslateAMD64PackedFloatMoveCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 assigns VMOVAPD/APS/UPD/UPS the same 16-row _yvmovapd
	// table: bidirectional X/Y/Z register-or-memory moves, EVEX high
	// registers, and K1-K7 merge/zero masking for every width and direction.
	var src strings.Builder
	src.WriteString("TEXT packedfloatmoveforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"VMOVAPD", "VMOVAPS", "VMOVUPD", "VMOVUPS"} {
		for _, width := range []string{"X", "Y"} {
			fmt.Fprintf(&src, "\t%s %s0, %s1\n", op, width, width)
			fmt.Fprintf(&src, "\t%s %s1, (AX)\n", op, width)
			fmt.Fprintf(&src, "\t%s (AX), %s2\n", op, width)
			fmt.Fprintf(&src, "\t%s %s20, %s21\n", op, width, width)
			fmt.Fprintf(&src, "\t%s %s20, (AX)\n", op, width)
			fmt.Fprintf(&src, "\t%s (AX), %s21\n", op, width)
		}
		fmt.Fprintf(&src, "\t%s Z0, Z1\n", op)
		fmt.Fprintf(&src, "\t%s Z1, (AX)\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Z2\n", op)
		fmt.Fprintf(&src, "\t%s Z20, Z21\n", op)
		fmt.Fprintf(&src, "\t%s Z20, (AX)\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Z21\n", op)
		for _, width := range []string{"X", "Y", "Z"} {
			fmt.Fprintf(&src, "\t%s %s1, K1, %s2\n", op, width, width)
			fmt.Fprintf(&src, "\t%s %s1, K2, (AX)\n", op, width)
			fmt.Fprintf(&src, "\t%s (AX), K3, %s2\n", op, width)
			fmt.Fprintf(&src, "\t%s.Z %s1, K4, %s2\n", op, width, width)
			// The Go assembler accepts .Z on masked memory stores. The EVEX
			// zeroing bit has no effect on inactive memory lanes.
			fmt.Fprintf(&src, "\t%s.Z %s1, K5, (AX)\n", op, width)
			fmt.Fprintf(&src, "\t%s.Z (AX), K6, %s2\n", op, width)
		}
	}
	src.WriteString("\tRET\n")
	ll := translateAMD64EcosystemCase(t, src.String(), "packedfloatmoveforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "packed-float-move-forms.ll", "packed-float-move-forms.o", ll)
}

func TestTranslate386PackedFloatMoveCompleteGoAssemblerForms(t *testing.T) {
	// The 386 encoder exposes X/Y registers 0-31, Z registers 0-7, and all
	// three-operand mask rows (unlike EVEX families that need four operands).
	var src strings.Builder
	src.WriteString("TEXT packedfloatmoveforms386(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"VMOVAPD", "VMOVAPS", "VMOVUPD", "VMOVUPS"} {
		for _, width := range []string{"X", "Y"} {
			fmt.Fprintf(&src, "\t%s %s0, %s1\n", op, width, width)
			fmt.Fprintf(&src, "\t%s %s20, %s21\n", op, width, width)
			fmt.Fprintf(&src, "\t%s %s20, (AX)\n", op, width)
			fmt.Fprintf(&src, "\t%s (AX), %s21\n", op, width)
			fmt.Fprintf(&src, "\t%s %s20, K1, %s21\n", op, width, width)
			fmt.Fprintf(&src, "\t%s.Z %s20, K2, (AX)\n", op, width)
			fmt.Fprintf(&src, "\t%s.Z (AX), K3, %s21\n", op, width)
		}
		fmt.Fprintf(&src, "\t%s Z0, Z7\n", op)
		fmt.Fprintf(&src, "\t%s Z7, (AX)\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Z7\n", op)
		fmt.Fprintf(&src, "\t%s Z0, K1, Z7\n", op)
		fmt.Fprintf(&src, "\t%s.Z Z0, K2, (AX)\n", op)
		fmt.Fprintf(&src, "\t%s.Z (AX), K3, Z7\n", op)
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"packedfloatmoveforms386": {Name: "packedfloatmoveforms386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "packed-float-move-386-forms.ll", "packed-float-move-386-forms.o", ll)
}

func TestTranslateAMD64PackedFloatMoveRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VMOVAPD X1, Y2",
		"VMOVAPS Y1, Z2",
		"VMOVUPD Z1, X2",
		"VMOVUPS (AX), (BX)",
		"VMOVAPD K1, X2",
		"VMOVAPS X1, K0, X2",
		"VMOVUPD (AX), K0, X2",
		"VMOVUPS.Z X1, X2",
		"VMOVAPD.BCST (AX), X2",
		"VMOVAPS.SAE X1, X2",
		"VMOVUPD.RN_SAE X1, X2",
		"VMOVUPS X1, K1, Y2",
		"VMOVAPD X1, X2, K1",
		"VMOVAPS X1",
		"VMOVUPD X1, K1, X2, X3",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidpackedfloatmove(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedfloatmove": {Name: "invalidpackedfloatmove", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's _yvmovapd table", instruction)
			}
		})
	}
}

func TestTranslate386PackedFloatMoveRejectsArchitectureRestrictedForms(t *testing.T) {
	for _, instruction := range []string{
		"VMOVAPD Z8, Z1",
		"VMOVAPS Z0, Z8",
		"VMOVUPD Z8, (AX)",
		"VMOVUPS (AX), Z8",
		"VMOVAPD Z0, K1, Z8",
		"VMOVAPS.Z Z8, K1, (AX)",
		"VMOVUPD.Z (AX), K1, Z8",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidpackedfloatmove386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"invalidpackedfloatmove386": {Name: "invalidpackedfloatmove386", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which Go 1.27 rejects for 386", instruction)
			}
		})
	}
}

func TestTranslateX86EVEXPackedIntegerMoveCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 assigns this complete family the same 12-row _yvmovdqa32
	// table. Each opcode accepts bidirectional X/Y/Z register-or-memory
	// moves plus K1-K7 merge/zero masking for every width and direction.
	for _, target := range []struct {
		goarch string
		triple string
		zregs  []int
	}{
		{goarch: "386", triple: "i386-unknown-linux-gnu", zregs: []int{0, 7}},
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu", zregs: []int{0, 21}},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			var src strings.Builder
			src.WriteString("TEXT evexpackedintegermoveforms(SB),NOSPLIT,$0-0\n")
			for _, op := range []string{"VMOVDQA32", "VMOVDQA64", "VMOVDQU8", "VMOVDQU16", "VMOVDQU32", "VMOVDQU64"} {
				for _, width := range []string{"X", "Y"} {
					fmt.Fprintf(&src, "\t%s %s0, %s1\n", op, width, width)
					fmt.Fprintf(&src, "\t%s %s20, (AX)\n", op, width)
					fmt.Fprintf(&src, "\t%s (AX), %s21\n", op, width)
					fmt.Fprintf(&src, "\t%s %s1, K1, %s2\n", op, width, width)
					fmt.Fprintf(&src, "\t%s %s1, K2, (AX)\n", op, width)
					fmt.Fprintf(&src, "\t%s (AX), K3, %s2\n", op, width)
					fmt.Fprintf(&src, "\t%s.Z %s1, K4, %s2\n", op, width, width)
					fmt.Fprintf(&src, "\t%s.Z %s1, K5, (AX)\n", op, width)
					fmt.Fprintf(&src, "\t%s.Z (AX), K6, %s2\n", op, width)
				}
				fmt.Fprintf(&src, "\t%s Z%d, Z%d\n", op, target.zregs[0], target.zregs[1])
				fmt.Fprintf(&src, "\t%s Z%d, (AX)\n", op, target.zregs[0])
				fmt.Fprintf(&src, "\t%s (AX), Z%d\n", op, target.zregs[1])
				fmt.Fprintf(&src, "\t%s Z%d, K1, Z%d\n", op, target.zregs[0], target.zregs[1])
				fmt.Fprintf(&src, "\t%s.Z Z%d, K2, (AX)\n", op, target.zregs[0])
				fmt.Fprintf(&src, "\t%s.Z (AX), K3, Z%d\n", op, target.zregs[1])
			}
			src.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"evexpackedintegermoveforms": {Name: "evexpackedintegermoveforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "evex-packed-integer-move-"+target.goarch+".ll", "evex-packed-integer-move-"+target.goarch+".o", ll)
		})
	}
}

func TestTranslateX86EVEXPackedIntegerMoveRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VMOVDQA32 X1, Y2",
		"VMOVDQA64 Y1, Z2",
		"VMOVDQU8 (AX), (BX)",
		"VMOVDQU16 X1, K0, X2",
		"VMOVDQU32.Z X1, X2",
		"VMOVDQU64.BCST (AX), Z2",
		"VMOVDQU8.SAE X1, X2",
		"VMOVDQU16 X1, K1, Y2",
		"VMOVDQU32 X1",
		"VMOVDQA64 X1, K1, X2, X3",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT bad(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's _yvmovdqa32 table", instruction)
			}
		})
	}
	for _, instruction := range []string{
		"VMOVDQA32 Z8, Z0",
		"VMOVDQA64 Z0, Z8",
		"VMOVDQU8 Z8, (AX)",
		"VMOVDQU16 (AX), Z8",
		"VMOVDQU32 Z0, K1, Z8",
		"VMOVDQU64.Z (AX), K1, Z8",
	} {
		file, err := Parse(ArchAMD64, "TEXT bad386(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
		if err != nil {
			return
		}
		if _, err := Translate(file, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs:         map[string]FuncSig{"bad386": {Name: "bad386", Ret: Void}},
		}); err == nil {
			t.Fatalf("386 Translate accepted architecture-restricted %q", instruction)
		}
	}
}

func TestTranslateAMD64PackedSignExtendMoveCompleteGoAssemblerForms(t *testing.T) {
	// The complete signed widening family consists of six legacy yxm_q4
	// instructions plus six V instructions. BW/WD/DQ use _yvcvtdq2pd
	// (X source for X/Y destinations and Y source for Z); BD/BQ/WQ use
	// _yvbroadcastss (X source for every destination width).
	var src strings.Builder
	src.WriteString("TEXT packedsignextendmoveforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"PMOVSXBW", "PMOVSXBD", "PMOVSXBQ", "PMOVSXWD", "PMOVSXWQ", "PMOVSXDQ"} {
		fmt.Fprintf(&src, "\t%s X0, X1\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X2\n", op)
		fmt.Fprintf(&src, "\t%s X15, X14\n", op)
	}
	for _, op := range []string{"VPMOVSXBW", "VPMOVSXWD", "VPMOVSXDQ"} {
		fmt.Fprintf(&src, "\t%s X0, X1\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X2\n", op)
		fmt.Fprintf(&src, "\t%s X0, Y1\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Y2\n", op)
		fmt.Fprintf(&src, "\t%s Y0, Z1\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Z2\n", op)
		fmt.Fprintf(&src, "\t%s X20, X21\n", op)
		fmt.Fprintf(&src, "\t%s X20, Y21\n", op)
		fmt.Fprintf(&src, "\t%s Y20, Z21\n", op)
		fmt.Fprintf(&src, "\t%s X20, K1, X21\n", op)
		fmt.Fprintf(&src, "\t%s.Z (AX), K2, X21\n", op)
		fmt.Fprintf(&src, "\t%s X20, K3, Y21\n", op)
		fmt.Fprintf(&src, "\t%s.Z (AX), K4, Y21\n", op)
		fmt.Fprintf(&src, "\t%s Y20, K5, Z21\n", op)
		fmt.Fprintf(&src, "\t%s.Z (AX), K6, Z21\n", op)
	}
	for _, op := range []string{"VPMOVSXBD", "VPMOVSXBQ", "VPMOVSXWQ"} {
		for _, width := range []string{"X", "Y", "Z"} {
			fmt.Fprintf(&src, "\t%s X0, %s1\n", op, width)
			fmt.Fprintf(&src, "\t%s (AX), %s2\n", op, width)
			fmt.Fprintf(&src, "\t%s X20, %s21\n", op, width)
			fmt.Fprintf(&src, "\t%s X20, K1, %s21\n", op, width)
			fmt.Fprintf(&src, "\t%s.Z (AX), K2, %s21\n", op, width)
		}
	}
	src.WriteString("\tRET\n")
	ll := translateAMD64EcosystemCase(t, src.String(), "packedsignextendmoveforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "packed-sign-extend-move-forms.ll", "packed-sign-extend-move-forms.o", ll)
}

func TestTranslate386PackedSignExtendMoveCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT packedsignextendmoveforms386(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"PMOVSXBW", "PMOVSXBD", "PMOVSXBQ", "PMOVSXWD", "PMOVSXWQ", "PMOVSXDQ"} {
		fmt.Fprintf(&src, "\t%s X0, X7\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X7\n", op)
	}
	for _, op := range []string{"VPMOVSXBW", "VPMOVSXWD", "VPMOVSXDQ"} {
		fmt.Fprintf(&src, "\t%s X20, X21\n", op)
		fmt.Fprintf(&src, "\t%s X20, Y21\n", op)
		fmt.Fprintf(&src, "\t%s Y20, Z7\n", op)
		fmt.Fprintf(&src, "\t%s X20, K1, Y21\n", op)
		fmt.Fprintf(&src, "\t%s.Z (AX), K2, Z7\n", op)
	}
	for _, op := range []string{"VPMOVSXBD", "VPMOVSXBQ", "VPMOVSXWQ"} {
		fmt.Fprintf(&src, "\t%s X20, X21\n", op)
		fmt.Fprintf(&src, "\t%s X20, Y21\n", op)
		fmt.Fprintf(&src, "\t%s X20, Z7\n", op)
		fmt.Fprintf(&src, "\t%s X20, K1, Y21\n", op)
		fmt.Fprintf(&src, "\t%s.Z (AX), K2, Z7\n", op)
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"packedsignextendmoveforms386": {Name: "packedsignextendmoveforms386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "packed-sign-extend-move-386-forms.ll", "packed-sign-extend-move-386-forms.o", ll)
}

func TestTranslateAMD64PackedSignExtendMoveRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"PMOVSXBW X16, X1",
		"PMOVSXBD X1, X16",
		"PMOVSXBQ Y1, X2",
		"PMOVSXWD X1, Y2",
		"PMOVSXWQ X1, (AX)",
		"PMOVSXDQ.Z X1, X2",
		"PMOVSXBW X1, K1, X2",
		"VPMOVSXBW Y1, Y2",
		"VPMOVSXWD X1, Z2",
		"VPMOVSXDQ Z1, Z2",
		"VPMOVSXBD Y1, Z2",
		"VPMOVSXBQ Y1, Y2",
		"VPMOVSXWQ Z1, X2",
		"VPMOVSXBW X1, (AX)",
		"VPMOVSXBD (AX), (BX)",
		"VPMOVSXBQ X1, K0, Y2",
		"VPMOVSXWD.Z X1, Y2",
		"VPMOVSXDQ.BCST (AX), Y2",
		"VPMOVSXWQ.SAE X1, Z2",
		"VPMOVSXBW.RN_SAE X1, Y2",
		"VPMOVSXBD X1",
		"VPMOVSXBQ X1, K1, Y2, Y3",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidpackedsignextendmove(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedsignextendmove": {Name: "invalidpackedsignextendmove", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's signed-extension move tables", instruction)
			}
		})
	}
}

func TestTranslate386PackedSignExtendMoveRejectsArchitectureRestrictedForms(t *testing.T) {
	for _, instruction := range []string{
		"PMOVSXBW X8, X1",
		"PMOVSXBD X1, X8",
		"PMOVSXBQ X15, X7",
		"VPMOVSXBW Y1, Z8",
		"VPMOVSXWD (AX), Z8",
		"VPMOVSXDQ Y20, K1, Z8",
		"VPMOVSXBD X20, Z8",
		"VPMOVSXBQ.Z (AX), K1, Z8",
		"VPMOVSXWQ X20, K1, Z8",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidpackedsignextendmove386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"invalidpackedsignextendmove386": {Name: "invalidpackedsignextendmove386", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which Go 1.27 rejects for 386", instruction)
			}
		})
	}
}

func TestTranslateAMD64MOVDFromXRegister(t *testing.T) {
	src := `
TEXT movdfromx(SB),NOSPLIT,$0-0
	PXOR X12, X12
	MOVD X12, DX
	RET
`
	translateAMD64EcosystemCase(t, src, "movdfromx")
}

func TestTranslateAMD64MOVDAliasCompleteGo127Forms(t *testing.T) {
	// cmd/asm aliases MOVD to AMOVQ on x86. These cover every ymovq operand
	// class that the alias can select in 64-bit mode: GP/immediate/memory,
	// MMX/memory/GP/XMM, and XMM/memory/GP/XMM.
	src := `
TEXT movdaliasforms(SB),NOSPLIT,$0-0
	MOVD AX, BX
	MOVD $1, AX
	MOVD AX, 8(BX)
	MOVD 8(BX), AX
	MOVD (BX), M0
	MOVD M0, 8(BX)
	MOVD AX, M1
	MOVD M1, AX
	MOVD X0, M2
	MOVD M2, M3
	MOVD AX, X1
	MOVD 24(SP), X9
	MOVD X1, AX
	MOVD X9, 32(SP)
	MOVD X1, X2
	RET
`
	ll := translateAMD64EcosystemCase(t, src, "movdaliasforms")
	if !strings.Contains(ll, "load i64") || !strings.Contains(ll, "store i64") {
		t.Fatalf("MOVD alias did not preserve MOVQ-width memory semantics:\n%s", ll)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "movd-alias-forms.ll", "movd-alias-forms.o", ll)
}

func TestTranslateAMD64MOVDAliasRejectsFormsOutsideGo127Ymovq(t *testing.T) {
	for _, instruction := range []string{
		"MOVD $1, X0",
		"MOVD M0, X0",
		"MOVD X0, X1, X2",
		"MOVD.Z X0, X1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT badmovd(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs:         map[string]FuncSig{"badmovd": {Name: "badmovd", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's MOVD/ymovq forms", instruction)
			}
		})
	}
}

func TestTranslateAMD64LegacyPrefetchFamilyCompleteGo127Forms(t *testing.T) {
	src := `
TEXT prefetchforms(SB),NOSPLIT,$0-0
	PREFETCHNTA (AX)
	PREFETCHT0 8(BX)
	PREFETCHT1 source(SB)
	PREFETCHT2 16(SP)
	RET
`
	ll := translateAMD64EcosystemCase(t, src, "prefetchforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "prefetch-forms.ll", "prefetch-forms.o", ll)
}

func TestTranslateAMD64LegacyPrefetchFamilyRejectsNonMemoryForms(t *testing.T) {
	for _, instruction := range []string{
		"PREFETCHNTA",
		"PREFETCHT0 AX",
		"PREFETCHT1 $1",
		"PREFETCHT2 (AX), (BX)",
		"PREFETCHT0.Z (AX)",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT badprefetch(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs:         map[string]FuncSig{"badprefetch": {Name: "badprefetch", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's yprefetch table", instruction)
			}
		})
	}
}

func TestTranslateAMD64ArithmeticDisplacementExpression(t *testing.T) {
	ll := translateAMD64EcosystemCase(t, `
TEXT arithmeticdisplacement(SB),NOSPLIT,$32-0
	ADDQ 0+(1*16)(BP), R10
	MOVQ (-16+8)(SP), AX
	RET
`, "arithmeticdisplacement")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "arithmetic-displacement.ll", "arithmetic-displacement.o", ll)
}

func TestTranslateAMD64GoTLSPseudoRegisterForms(t *testing.T) {
	ll := translateAMD64EcosystemCase(t, `
TEXT tlsforms(SB),NOSPLIT,$0-0
	MOVQ TLS, CX
	MOVQ 0(CX)(TLS*1), BX
	MOVQ 8(TLS), DX
	RET
`, "tlsforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "tls-forms.ll", "tls-forms.o", ll)
}

func TestTranslateAMD64LegacyIntegerToFloatConversionFamilyCompleteGo127Forms(t *testing.T) {
	ll := translateAMD64EcosystemCase(t, `
TEXT integerfloatconversions(SB),NOSPLIT,$0-0
	CVTSL2SS AX, X0
	CVTSL2SS 4(BX), X1
	CVTSL2SD CX, X2
	CVTSL2SD 8(BX), X3
	CVTSQ2SS SI, X4
	CVTSQ2SS 16(BX), X5
	CVTSQ2SD DI, X6
	CVTSQ2SD 24(BX), X7
	CVTPL2PS X0, X1
	CVTPL2PS 32(BX), X2
	CVTPL2PS M0, X3
	CVTPL2PD X4, X5
	CVTPL2PD 48(BX), X6
	CVTPL2PD M1, X7
	RET
`, "integerfloatconversions")
	for _, want := range []string{"sitofp i32", "sitofp i64", "sitofp <4 x i32>", "sitofp <2 x i32>"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in integer-to-float conversion IR:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "integer-float-conversions.ll", "integer-float-conversions.o", ll)
}

func TestTranslateAMD64LegacyIntegerToFloatConversionFamilyRejectsNonGoForms(t *testing.T) {
	for _, instruction := range []string{
		"CVTSL2SS $1, X0",
		"CVTSQ2SS X0, X1",
		"CVTSQ2SD AX, Y0",
		"CVTPL2PS AX, X0",
		"CVTPL2PD X0, Y0",
		"CVTPL2PS.Z X0, X1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT badconversion(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs:         map[string]FuncSig{"badconversion": {Name: "badconversion", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's legacy integer-to-float tables", instruction)
			}
		})
	}
}

func TestTranslateAMD64ScalarFloatBroadcastFamilyCompleteGo127Forms(t *testing.T) {
	ll := translateAMD64EcosystemCase(t, `
TEXT scalarfloatbroadcasts(SB),NOSPLIT,$0-0
	VBROADCASTSS X0, X1
	VBROADCASTSS 4(AX), Y1
	VBROADCASTSS X16, Z17
	VBROADCASTSS X16, K1, X17
	VBROADCASTSS.Z 8(AX), K2, Y18
	VBROADCASTSS 12(AX), K3, Z19
	VBROADCASTSD X0, Y1
	VBROADCASTSD 8(AX), Z1
	VBROADCASTSD X16, K1, Y17
	VBROADCASTSD.Z 16(AX), K2, Z18
	RET
`, "scalarfloatbroadcasts")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "scalar-float-broadcasts.ll", "scalar-float-broadcasts.o", ll)
}

func TestTranslateAMD64ScalarFloatBroadcastFamilyRejectsNonGoForms(t *testing.T) {
	for _, instruction := range []string{
		"VBROADCASTSS AX, X0",
		"VBROADCASTSD X0, X1",
		"VBROADCASTSS.Z X0, Y1",
		"VBROADCASTSD X0, K0, Y1",
		"VBROADCASTSS.BCST 4(AX), Y1",
		"VBROADCASTSD X0, K1, K2, Y1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT badbroadcast(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs:         map[string]FuncSig{"badbroadcast": {Name: "badbroadcast", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's scalar broadcast tables", instruction)
			}
		})
	}
}

func TestTranslateAMD64DwordToQwordMultiplyFamilyCompleteGo127Forms(t *testing.T) {
	ll := translateAMD64EcosystemCase(t, `
TEXT dwordqwordmultiply(SB),NOSPLIT,$0-0
	PMULDQ X0, X1
	PMULDQ 16(AX), X2
	PMULULQ M0, M1
	PMULULQ 24(AX), M2
	PMULULQ X0, X1
	PMULULQ 32(AX), X2
	VPMULDQ X0, X1, X2
	VPMULDQ Y0, Y1, Y2
	VPMULDQ Z0, Z1, Z2
	VPMULDQ Z0, Z1, K1, Z2
	VPMULDQ.Z Z0, Z1, K2, Z2
	VPMULDQ.BCST 40(AX), Z1, Z2
	VPMULDQ.BCST.Z 48(AX), Z1, K3, Z2
	VPMULUDQ X0, X1, X2
	VPMULUDQ Y0, Y1, Y2
	VPMULUDQ Z0, Z1, Z2
	VPMULUDQ Z0, Z1, K1, Z2
	VPMULUDQ.Z Z0, Z1, K2, Z2
	VPMULUDQ.BCST 56(AX), Z1, Z2
	VPMULUDQ.BCST.Z 64(AX), Z1, K3, Z2
	RET
`, "dwordqwordmultiply")
	for _, want := range []string{"sext <", "zext <", "mul <2 x i64>", "mul <4 x i64>", "mul <8 x i64>"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in dword-to-qword multiply IR:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "dword-qword-multiply.ll", "dword-qword-multiply.o", ll)
}

func TestTranslateAMD64DwordToQwordMultiplyFamilyRejectsNonGoForms(t *testing.T) {
	for _, instruction := range []string{
		"PMULDQ M0, M1",
		"PMULULQ Y0, Y1",
		"VPMULUDQ X0, Y1, X2",
		"VPMULDQ Z0, Z1, K0, Z2",
		"VPMULUDQ.Z Z0, Z1, Z2",
		"VPMULDQ.BCST Z0, Z1, Z2",
		"VPMULUDQ.Z.BCST 8(AX), Z1, K1, Z2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT badmultiply(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs:         map[string]FuncSig{"badmultiply": {Name: "badmultiply", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's dword-to-qword multiply tables", instruction)
			}
		})
	}
}

func TestTranslate386NewlyDiscoveredX86FamiliesCompleteGo127Forms(t *testing.T) {
	// Keep the 386 matrix explicit: x86 opcode names are shared with amd64, but
	// cmd/asm's operand tables and available registers differ in 32-bit mode.
	src := `
TEXT discoveredx86forms386(SB),NOSPLIT,$0-0
	MOVD (AX), X0
	MOVD X0, 8(AX)
	MOVD X0, X1
	MOVD 16(AX), M0
	MOVD M0, 24(AX)
	MOVD X0, M1
	CVTSL2SS AX, X0
	CVTSL2SS 4(BX), X1
	CVTSL2SD CX, X2
	CVTSL2SD 8(BX), X3
	CVTPL2PS X0, X1
	CVTPL2PS 16(BX), X2
	CVTPL2PS M0, X3
	CVTPL2PD X4, X5
	CVTPL2PD 24(BX), X6
	CVTPL2PD M1, X7
	VBROADCASTSS X0, X1
	VBROADCASTSS 4(AX), Y1
	VBROADCASTSS 8(AX), Z1
	VBROADCASTSD X0, Y2
	VBROADCASTSD 16(AX), Z2
	PMULDQ X0, X1
	PMULDQ 16(AX), X2
	PMULULQ X0, X1
	PMULULQ 24(AX), X2
	VPMULDQ X0, X1, X2
	VPMULDQ Y0, Y1, Y2
	VPMULDQ Z0, Z1, Z2
	VPMULUDQ X0, X1, X2
	VPMULUDQ Y0, Y1, Y2
	VPMULUDQ Z0, Z1, Z2
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"discoveredx86forms386": {Name: "discoveredx86forms386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "discovered-x86-386-forms.ll", "discovered-x86-386-forms.o", ll)
}

func TestTranslate386NewlyDiscoveredX86FamiliesRejectArchitectureRestrictedForms(t *testing.T) {
	for _, instruction := range []string{
		"MOVD AX, BX",
		"MOVD M0, M1",
		"MOVD M0, X0",
		"CVTSQ2SS AX, X0",
		"CVTSQ2SD 8(AX), X0",
		"PMULULQ M0, M1",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT bad386discovered(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"bad386discovered": {Name: "bad386discovered", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which Go 1.27 rejects for GOARCH=386", instruction)
			}
		})
	}
}

func TestTranslateAMD64MOVQFromXRegisterToFrameResult(t *testing.T) {
	src := `
TEXT vectorret(SB),NOSPLIT,$0-8
	PXOR X0, X0
	MOVQ X0, vectorGlobal<>(SB)
	MOVQ X0, ret+0(FP)
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{"vectorret": {
			Name: "vectorret",
			Ret:  I64,
			Frame: FrameLayout{Results: []FrameSlot{{
				Offset: 0,
				Type:   I64,
				Index:  0,
				Field:  -1,
			}}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTranslateAMD64X87Arithmetic(t *testing.T) {
	src := `
TEXT x87amd64(SB),NOSPLIT,$0-0
	FLDZ
	FLD1
	FADDD F1, F0
	FSUBD F1, F0
	FLDCW 0(SP)
	RET
`
	translateAMD64EcosystemCase(t, src, "x87amd64")
}

func TestTranslateAMD64FuzzerBitTestAndVectorSubtract(t *testing.T) {
	src := `
TEXT fuzzops(SB),NOSPLIT,$0-0
	BTL $16, CX
	JCS done
	VPSUBB Y0, Y1, Y2
done:
	RET
`
	translateAMD64EcosystemCase(t, src, "fuzzops")
}

func TestTranslateX86DivisionAndFrameArithmetic(t *testing.T) {
	amd64Source := `
TEXT divmod(SB),NOSPLIT,$0-32
	MOVQ $0, DX
	MOVQ a+0(FP), AX
	DIVQ b+8(FP)
	MOVQ AX, quo+16(FP)
	MOVQ DX, rem+24(FP)
	RET
`
	translateX86FrameCase(t, amd64Source, "amd64", "x86_64-unknown-linux-gnu", "divmod")

	x86Source := `
TEXT mulparts(SB),NOSPLIT,$0-32
	MOVL a+0(FP), AX
	MULL b+8(FP)
	MOVL AX, hi+16(FP)
	ADDL DX, hi+16(FP)
	RET
`
	translateX86FrameCase(t, x86Source, "386", "i386-unknown-linux-gnu", "mulparts")
}

func TestTranslateAMD64LegacyBranchHintAndSignedDivision(t *testing.T) {
	src := `
TEXT signeddivmod(SB),NOSPLIT,$0-32
	MOVQ a+0(FP), AX
	MOVQ b+8(FP), CX
	CMPQ CX, $-1
	JEQ $1, special
	CQO
	IDIVQ CX
	JMP done
special:
	NEGQ AX
	MOVQ $0, DX
done:
	MOVQ AX, quo+16(FP)
	MOVQ DX, rem+24(FP)
	RET
`
	translateX86FrameCase(t, src, "amd64", "x86_64-unknown-linux-gnu", "signeddivmod")
}

func TestTranslateAMD64LoopBranch(t *testing.T) {
	src := `
TEXT countedloop(SB),NOSPLIT,$0-0
	MOVQ $2, CX
loop:
	LOOP loop
	RET
`
	translateAMD64EcosystemCase(t, src, "countedloop")
}

func TestTranslateAMD64RawDataDirectives(t *testing.T) {
	src := `
TEXT rawencoding(SB),NOSPLIT,$0-0
	LONG $0xe77da1c4
	QUAD $0x4109048d47d18941
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawencoding": {Name: "rawencoding", Ret: Void}}}); err == nil || !strings.Contains(err.Error(), "decode raw x86 directive group") {
		t.Fatalf("reachable opaque data directives must fail closed, got %v", err)
	}
}

func TestTranslateAMD64HighQuadwordInterleave(t *testing.T) {
	src := `
TEXT highquadword(SB),NOSPLIT,$0-0
	PUNPCKHQDQ X1, X0
	VPUNPCKHQDQ Y0, Y1, Y2
	RET
`
	translateAMD64EcosystemCase(t, src, "highquadword")
}

func TestTranslateAMD64AdditionalAVXUnpackAndBroadcastFamilies(t *testing.T) {
	src := `
TEXT avxunpackbroadcast(SB),NOSPLIT,$0-0
	VPUNPCKLQDQ X0, X1, X2
	VPUNPCKLQDQ Y0, Y1, Y2
	VPUNPCKLDQ X0, X1, X2
	VPUNPCKLDQ Y0, Y1, Y2
	VPUNPCKHDQ X0, X1, X2
	VPUNPCKHDQ Y0, Y1, Y2
	VPBROADCASTD (AX), X3
	VPBROADCASTD (AX), Y3
	VPSHUFD $0x4e, (AX), X4
	VPSHUFD $0x4e, X0, X4
	VPSHUFD $0x4e, (AX), Z4
	VPSLLD $12, X5, X13
	VPSRLD $7, (AX), X13
	VPSLLD $12, Y5, Y13
	VPSLLD $12, Z5, Z13
	RET
`
	translateAMD64EcosystemCase(t, src, "avxunpackbroadcast")
}

func TestTranslateAMD64DwordShuffleCompleteGoAssemblerForms(t *testing.T) {
	src := `
TEXT dwordshuffleforms(SB),NOSPLIT,$0-0
	PSHUFD $1, X1, X2
	PSHUFD $1, (AX), X2
	PSHUFL $1, X1, X2
	VPSHUFD $1, X1, X2
	VPSHUFD $1, (AX), X2
	VPSHUFD $1, Y1, Y2
	VPSHUFD $1, (AX), Y2
	VPSHUFD $1, Z1, Z2
	VPSHUFD $1, (AX), Z2
	VPSHUFD $1, X1, K1, X2
	VPSHUFD.Z $1, (AX), K1, X2
	VPSHUFD $1, Y1, K1, Y2
	VPSHUFD.Z $1, (AX), K1, Y2
	VPSHUFD $1, Z1, K1, Z2
	VPSHUFD.Z $1, (AX), K1, Z2
	RET
`
	translateAMD64EcosystemCase(t, src, "dwordshuffleforms")
}

func TestTranslateAMD64CanonicalPackedByteShiftAliases(t *testing.T) {
	src := `
TEXT packedbyteshifts(SB),NOSPLIT,$0-0
	PSLLO $4, X0
	PSRLO $4, X0
	RET
`
	translateAMD64EcosystemCase(t, src, "packedbyteshifts")
}

func TestTranslateAMD64PackedUniformShiftCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27's x86 assembler assigns all of these instructions the same
	// _yvpslld operand-format table. Keep this test in lockstep with that
	// family instead of adding only the form first observed in a dependency.
	for _, op := range []string{
		"VPSLLD", "VPSLLQ", "VPSLLW",
		"VPSRAD", "VPSRAW",
		"VPSRLD", "VPSRLQ", "VPSRLW",
	} {
		var src strings.Builder
		fmt.Fprintf(&src, "TEXT uniformshift%s(SB),NOSPLIT,$0-0\n", op)
		for _, operands := range []string{
			"$3, X1, X2", "$-1, X1, X2", "$3, (AX), X2",
			"$3, Y1, Y2", "$-1, Y1, Y2", "$3, (AX), Y2",
			"$3, Z1, Z2", "$3, (AX), Z2",
			"X0, X1, X2", "(AX), X1, X2",
			"X0, Y1, Y2", "(AX), Y1, Y2",
			"X0, Z1, Z2", "(AX), Z1, Z2",
			"$3, X1, K1, X2", "$3, (AX), K1, X2",
			"$3, Y1, K1, Y2", "$3, (AX), K1, Y2",
			"$3, Z1, K1, Z2", "$3, (AX), K1, Z2",
			"X0, X1, K1, X2", "(AX), X1, K1, X2",
			"X0, Y1, K1, Y2", "(AX), Y1, K1, Y2",
			"X0, Z1, K1, Z2", "(AX), Z1, K1, Z2",
		} {
			fmt.Fprintf(&src, "\t%s %s\n", op, operands)
		}
		for _, operands := range []string{
			"$3, X1, K1, X2", "$3, (AX), K1, X2",
			"$3, Y1, K1, Y2", "$3, (AX), K1, Y2",
			"$3, Z1, K1, Z2", "$3, (AX), K1, Z2",
			"X0, X1, K1, X2", "(AX), X1, K1, X2",
			"X0, Y1, K1, Y2", "(AX), Y1, K1, Y2",
			"X0, Z1, K1, Z2", "(AX), Z1, K1, Z2",
		} {
			fmt.Fprintf(&src, "\t%s.Z %s\n", op, operands)
		}
		src.WriteString("\tRET\n")
		translateAMD64EcosystemCase(t, src.String(), "uniformshift"+op)
	}
}

func TestTranslateAMD64PackedIntegerCompareCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 assigns all eight equality/greater-than variants the shared
	// _yvpcmpeqb table. VEX writes X/Y vectors; EVEX compares X/Y/Z lanes into
	// K registers, optionally masked by K1-K7. D/Q also permit memory broadcast.
	ops := []string{
		"VPCMPEQB", "VPCMPEQW", "VPCMPEQD", "VPCMPEQQ",
		"VPCMPGTB", "VPCMPGTW", "VPCMPGTD", "VPCMPGTQ",
	}
	forms := []string{
		"X1, X2, X3", "(AX), X2, X3",
		"Y1, Y2, Y3", "(AX), Y2, Y3",
		"X1, X2, K3", "(AX), X2, K3",
		"X1, X2, K1, K3", "(AX), X2, K1, K3",
		"Y1, Y2, K3", "(AX), Y2, K3",
		"Y1, Y2, K1, K3", "(AX), Y2, K1, K3",
		"Z1, Z2, K3", "(AX), Z2, K3",
		"Z1, Z2, K1, K3", "(AX), Z2, K1, K3",
	}
	var src strings.Builder
	src.WriteString("TEXT packedintegercompareforms(SB),NOSPLIT,$0-0\n")
	for _, op := range ops {
		for _, form := range forms {
			fmt.Fprintf(&src, "\t%s %s\n", op, form)
		}
		if strings.HasSuffix(op, "D") || strings.HasSuffix(op, "Q") {
			for _, form := range []string{
				"(AX), X2, K3", "(AX), X2, K1, K3",
				"(AX), Y2, K3", "(AX), Y2, K1, K3",
				"(AX), Z2, K3", "(AX), Z2, K1, K3",
			} {
				fmt.Fprintf(&src, "\t%s.BCST %s\n", op, form)
			}
		}
	}
	src.WriteString("\tRET\n")
	ll := translateAMD64EcosystemCase(t, src.String(), "packedintegercompareforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "packed-integer-compare-forms.ll", "packed-integer-compare-forms.o", ll)
}

func TestTranslateAMD64PackedIntegerCompareRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VPCMPEQB Z1, Z2, Z3",
		"VPCMPEQW X1, Y2, Y3",
		"VPCMPEQD X1, X2, K0, K3",
		"VPCMPEQQ.Z X1, X2, K1, K3",
		"VPCMPGTB.BCST (AX), X2, K3",
		"VPCMPGTW.SAE X1, X2, K3",
		"VPCMPGTD.BCST X1, X2, K3",
		"VPCMPGTQ.BCST (AX), X2, X3",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidpackedintegercompare(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedintegercompare": {Name: "invalidpackedintegercompare", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's _yvpcmpeqb table", instruction)
			}
		})
	}
}

func TestTranslateAMD64PackedAndNotCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 defines the whole AND-NOT family across three operand tables:
	// PANDN's ymm table (MMX/XMM), VPANDN's _yvaddsubpd table (X/Y VEX),
	// and VPANDND/Q's _yvblendmpd table (X/Y/Z EVEX with optional K1-K7
	// masking and zeroing). Only the D/Q EVEX variants permit memory broadcast.
	src := `
TEXT packedandnotforms(SB),NOSPLIT,$0-0
	PANDN M1, M2
	PANDN (AX), M2
	PANDN X1, X2
	PANDN (AX), X2
	VPANDN X1, X2, X3
	VPANDN (AX), X2, X3
	VPANDN Y1, Y2, Y3
	VPANDN (AX), Y2, Y3
	VPANDND X1, X2, X3
	VPANDND (AX), X2, X3
	VPANDND X1, X2, K1, X3
	VPANDND.Z (AX), X2, K1, X3
	VPANDND Y1, Y2, Y3
	VPANDND (AX), Y2, Y3
	VPANDND Y1, Y2, K1, Y3
	VPANDND.Z (AX), Y2, K1, Y3
	VPANDND Z1, Z2, Z3
	VPANDND (AX), Z2, Z3
	VPANDND Z1, Z2, K1, Z3
	VPANDND.Z (AX), Z2, K1, Z3
	VPANDND.BCST (AX), X2, X3
	VPANDND.BCST (AX), X2, K1, X3
	VPANDND.BCST.Z (AX), X2, K1, X3
	VPANDND.BCST (AX), Y2, Y3
	VPANDND.BCST (AX), Y2, K1, Y3
	VPANDND.BCST.Z (AX), Y2, K1, Y3
	VPANDND.BCST (AX), Z2, Z3
	VPANDND.BCST (AX), Z2, K1, Z3
	VPANDND.BCST.Z (AX), Z2, K1, Z3
	VPANDNQ X1, X2, X3
	VPANDNQ (AX), X2, X3
	VPANDNQ X1, X2, K1, X3
	VPANDNQ.Z (AX), X2, K1, X3
	VPANDNQ Y1, Y2, Y3
	VPANDNQ (AX), Y2, Y3
	VPANDNQ Y1, Y2, K1, Y3
	VPANDNQ.Z (AX), Y2, K1, Y3
	VPANDNQ Z1, Z2, Z3
	VPANDNQ (AX), Z2, Z3
	VPANDNQ Z1, Z2, K1, Z3
	VPANDNQ.Z (AX), Z2, K1, Z3
	VPANDNQ.BCST (AX), X2, X3
	VPANDNQ.BCST (AX), X2, K1, X3
	VPANDNQ.BCST.Z (AX), X2, K1, X3
	VPANDNQ.BCST (AX), Y2, Y3
	VPANDNQ.BCST (AX), Y2, K1, Y3
	VPANDNQ.BCST.Z (AX), Y2, K1, Y3
	VPANDNQ.BCST (AX), Z2, Z3
	VPANDNQ.BCST (AX), Z2, K1, Z3
	VPANDNQ.BCST.Z (AX), Z2, K1, Z3
	RET
`
	ll := translateAMD64EcosystemCase(t, src, "packedandnotforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "packed-and-not-forms.ll", "packed-and-not-forms.o", ll)
}

func TestTranslateAMD64PackedAndNotRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"PANDN Y1, Y2",
		"VPANDN Z1, Z2, Z3",
		"VPANDN.X Z1, Z2, Z3",
		"VPANDND X1, Y2, Y3",
		"VPANDND X1, X2, K0, X3",
		"VPANDND.Z X1, X2, X3",
		"VPANDND.SAE X1, X2, K1, X3",
		"VPANDND.BCST X1, X2, X3",
		"VPANDNQ.BCST (AX), X2, Y3",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidpackedandnot(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedandnot": {Name: "invalidpackedandnot", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's PANDN/VPANDN operand tables", instruction)
			}
		})
	}
}

func TestTranslateAMD64PackedScalarBroadcastCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 assigns VPBROADCASTB/W/D/Q the same _yvpbroadcastb table.
	// VEX broadcasts X/m to X/Y; EVEX adds GP and X/m sources, X/Y/Z
	// destinations, K1-K7 merge masking, and masked .Z zeroing.
	forms := []string{
		"X1, X2", "(AX), X2", "table<>(SB), X2", "0, X2",
		"X1, Y2", "(AX), Y2", "table<>(SB), Y2", "0x1234, Y2",
		"AX, X2", "AX, Y2", "AX, Z2",
		"X1, Z2", "(AX), Z2",
		"AX, K1, X2", "X1, K1, X2", "(AX), K1, X2",
		"AX, K1, Y2", "X1, K1, Y2", "(AX), K1, Y2",
		"AX, K1, Z2", "X1, K1, Z2", "(AX), K1, Z2",
	}
	zeroForms := []string{
		"AX, K1, X2", "X1, K1, X2", "(AX), K1, X2",
		"AX, K1, Y2", "X1, K1, Y2", "(AX), K1, Y2",
		"AX, K1, Z2", "X1, K1, Z2", "(AX), K1, Z2",
	}
	var src strings.Builder
	src.WriteString("TEXT packedscalarbroadcastforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"VPBROADCASTB", "VPBROADCASTW", "VPBROADCASTD", "VPBROADCASTQ"} {
		for _, form := range forms {
			fmt.Fprintf(&src, "\t%s %s\n", op, form)
		}
		for _, form := range zeroForms {
			fmt.Fprintf(&src, "\t%s.Z %s\n", op, form)
		}
	}
	src.WriteString("\tRET\n")
	requireX86GoAssemblerResult(t, "amd64", strings.Replace(src.String(), ",NOSPLIT", "", 1), true)
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "darwin-amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", triple: "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"packedscalarbroadcastforms": {Name: "packedscalarbroadcastforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "packed-scalar-broadcast-forms-"+target.name+".ll", "packed-scalar-broadcast-forms-"+target.name+".o", ll)
		})
	}
}

func TestTranslateAMD64PackedScalarBroadcastRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VPBROADCASTB $1, X2",
		"VPBROADCASTW Y1, Y2",
		"VPBROADCASTD X1, K0, X2",
		"VPBROADCASTQ X1, AX",
		"VPBROADCASTB.Z X1, X2",
		"VPBROADCASTW.BCST (AX), X2",
		"VPBROADCASTD.SAE X1, K1, X2",
		"VPBROADCASTQ X1, K1, Y2, Z3",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidpackedscalarbroadcast(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedscalarbroadcast": {Name: "invalidpackedscalarbroadcast", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's _yvpbroadcastb table", instruction)
			}
		})
	}
}

func TestTranslateAMD64PackedIntegerAddCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27's legacy ymm table gives these instructions MMX and XMM forms.
	for _, op := range []string{"PADDB", "PADDL", "PADDSB", "PADDSW", "PADDUSB", "PADDUSW", "PADDW"} {
		src := fmt.Sprintf(`
TEXT legacy%sforms(SB),NOSPLIT,$0-0
	%s M1, M2
	%s (AX), M2
	%s X1, X2
	%s (AX), X2
	RET
`, op, op, op, op, op)
		translateAMD64EcosystemCase(t, src, "legacy"+op+"forms")
	}
	// PADDQ is deliberately narrower in Go's legacy yxm table: XMM only.
	translateAMD64EcosystemCase(t, `
TEXT legacyPADDQforms(SB),NOSPLIT,$0-0
	PADDQ X1, X2
	PADDQ (AX), X2
	RET
`, "legacyPADDQforms")

	// Every AVX variant shares _yvandnpd: X/Y/Z register-or-memory inputs,
	// optional K1-K7 merge/zero masks. D/Q additionally enable broadcast.
	commonForms := []string{
		"X1, X2, X3", "(AX), X2, X3",
		"X1, X2, K1, X3", "(AX), X2, K1, X3",
		"Y1, Y2, Y3", "(AX), Y2, Y3",
		"Y1, Y2, K1, Y3", "(AX), Y2, K1, Y3",
		"Z1, Z2, Z3", "(AX), Z2, Z3",
		"Z1, Z2, K1, Z3", "(AX), Z2, K1, Z3",
	}
	maskedForms := []string{
		"X1, X2, K1, X3", "(AX), X2, K1, X3",
		"Y1, Y2, K1, Y3", "(AX), Y2, K1, Y3",
		"Z1, Z2, K1, Z3", "(AX), Z2, K1, Z3",
	}
	var src strings.Builder
	src.WriteString("TEXT packedintegeraddforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{
		"VPADDB", "VPADDW", "VPADDD", "VPADDQ",
		"VPADDSB", "VPADDSW", "VPADDUSB", "VPADDUSW",
	} {
		for _, form := range commonForms {
			fmt.Fprintf(&src, "\t%s %s\n", op, form)
		}
		for _, form := range maskedForms {
			fmt.Fprintf(&src, "\t%s.Z %s\n", op, form)
		}
		if op == "VPADDD" || op == "VPADDQ" {
			for _, form := range []string{
				"(AX), X2, X3", "(AX), X2, K1, X3",
				"(AX), Y2, Y3", "(AX), Y2, K1, Y3",
				"(AX), Z2, Z3", "(AX), Z2, K1, Z3",
			} {
				fmt.Fprintf(&src, "\t%s.BCST %s\n", op, form)
			}
			for _, form := range []string{
				"(AX), X2, K1, X3", "(AX), Y2, K1, Y3", "(AX), Z2, K1, Z3",
			} {
				fmt.Fprintf(&src, "\t%s.BCST.Z %s\n", op, form)
			}
		}
	}
	src.WriteString("\tRET\n")
	ll := translateAMD64EcosystemCase(t, src.String(), "packedintegeraddforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "packed-integer-add-forms.ll", "packed-integer-add-forms.o", ll)
}

func TestTranslateAMD64PackedIntegerAddRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"PADDQ M1, M2",
		"PADDB Y1, Y2",
		"VPADDB X1, Y2, Y3",
		"VPADDW X1, X2, K0, X3",
		"VPADDD.Z X1, X2, X3",
		"VPADDQ.BCST X1, X2, X3",
		"VPADDSB.BCST (AX), X2, X3",
		"VPADDSW.SAE X1, X2, K1, X3",
		"VPADDUSB X1, X2, K1, X3, X4",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidpackedintegeradd(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedintegeradd": {Name: "invalidpackedintegeradd", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's packed-add tables", instruction)
			}
		})
	}
}

func TestTranslateAMD64PackedIntegerSubtractCompleteGoAssemblerForms(t *testing.T) {
	// All eight legacy instructions use yxm: X/m128, X. Unlike the packed-add
	// family, none of these legacy subtract spellings has an MMX row.
	var src strings.Builder
	src.WriteString("TEXT packedintegersubtractforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"PSUBB", "PSUBL", "PSUBQ", "PSUBSB", "PSUBSW", "PSUBUSB", "PSUBUSW", "PSUBW"} {
		fmt.Fprintf(&src, "\t%s X1, X15\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X15\n", op)
	}

	// All eight V spellings share _yvandnpd. Exercise every VEX/EVEX width,
	// both register and memory members of each rm class, high EVEX registers,
	// K merge/zero masks, and the D/Q-only broadcast rows.
	commonForms := []string{
		"X1, X2, X3", "(AX), X2, X3",
		"Y1, Y2, Y3", "(AX), Y2, Y3",
		"Z1, Z2, Z3", "(AX), Z2, Z3",
		"X20, X21, X22", "Y20, Y21, Y22", "Z20, Z21, Z22",
	}
	maskedForms := []string{
		"X20, X21, K1, X22", "(AX), X21, K1, X22",
		"Y20, Y21, K1, Y22", "(AX), Y21, K1, Y22",
		"Z20, Z21, K1, Z22", "(AX), Z21, K1, Z22",
	}
	for _, op := range []string{
		"VPSUBB", "VPSUBD", "VPSUBQ", "VPSUBSB",
		"VPSUBSW", "VPSUBUSB", "VPSUBUSW", "VPSUBW",
	} {
		for _, form := range commonForms {
			fmt.Fprintf(&src, "\t%s %s\n", op, form)
		}
		for _, form := range maskedForms {
			fmt.Fprintf(&src, "\t%s %s\n", op, form)
			fmt.Fprintf(&src, "\t%s.Z %s\n", op, form)
		}
		if op == "VPSUBD" || op == "VPSUBQ" {
			for _, width := range []string{"X", "Y", "Z"} {
				fmt.Fprintf(&src, "\t%s.BCST (AX), %s21, %s22\n", op, width, width)
				fmt.Fprintf(&src, "\t%s.BCST (AX), %s21, K1, %s22\n", op, width, width)
				fmt.Fprintf(&src, "\t%s.BCST.Z (AX), %s21, K1, %s22\n", op, width, width)
			}
		}
	}
	src.WriteString("\tRET\n")
	ll := translateAMD64EcosystemCase(t, src.String(), "packedintegersubtractforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "packed-integer-subtract-forms.ll", "packed-integer-subtract-forms.o", ll)
}

func TestTranslate386PackedIntegerSubtractCompleteGoAssemblerForms(t *testing.T) {
	// In 386 mode the legacy encoder limits X registers to X0-X7. VEX and
	// unmasked EVEX X/Y rows remain available (including X/Y16-X/Y31), while
	// the assembler frontend rejects Z width and the four-operand mask rows.
	var src strings.Builder
	src.WriteString("TEXT packedintegersubtractforms386(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"PSUBB", "PSUBL", "PSUBQ", "PSUBSB", "PSUBSW", "PSUBUSB", "PSUBUSW", "PSUBW"} {
		fmt.Fprintf(&src, "\t%s X1, X7\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X7\n", op)
	}
	for _, op := range []string{
		"VPSUBB", "VPSUBD", "VPSUBQ", "VPSUBSB",
		"VPSUBSW", "VPSUBUSB", "VPSUBUSW", "VPSUBW",
	} {
		for _, form := range []string{
			"X1, X2, X3", "(AX), X2, X3", "X20, X21, X22",
			"Y1, Y2, Y3", "(AX), Y2, Y3", "Y20, Y21, Y22",
		} {
			fmt.Fprintf(&src, "\t%s %s\n", op, form)
		}
		if op == "VPSUBD" || op == "VPSUBQ" {
			fmt.Fprintf(&src, "\t%s.BCST (AX), X21, X22\n", op)
			fmt.Fprintf(&src, "\t%s.BCST (AX), Y21, Y22\n", op)
		}
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"packedintegersubtractforms386": {Name: "packedintegersubtractforms386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "packed-integer-subtract-386-forms.ll", "packed-integer-subtract-386-forms.o", ll)
}

func TestTranslateAMD64PackedIntegerSubtractRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"PSUBB M1, M2",
		"PSUBQ Y1, Y2",
		"VPSUBB X1, Y2, Y3",
		"VPSUBW X1, X2, K0, X3",
		"VPSUBD.Z X1, X2, X3",
		"VPSUBQ.BCST X1, X2, X3",
		"VPSUBSB.BCST (AX), X2, X3",
		"VPSUBSW.SAE X1, X2, K1, X3",
		"VPSUBUSB X1, X2, K1, X3, X4",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidpackedintegersubtract(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedintegersubtract": {Name: "invalidpackedintegersubtract", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's packed-subtract tables", instruction)
			}
		})
	}
}

func TestTranslate386PackedIntegerSubtractRejectsArchitectureRestrictedForms(t *testing.T) {
	for _, instruction := range []string{
		"PSUBB X1, X8",
		"VPSUBQ Z1, Z2, Z3",
		"VPSUBD X1, X2, K1, X3",
		"VPSUBQ.Z X1, X2, K1, X3",
		"VPSUBD.BCST.Z (AX), X2, K1, X3",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidpackedintegersubtract386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"invalidpackedintegersubtract386": {Name: "invalidpackedintegersubtract386", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which Go 1.27 rejects for 386", instruction)
			}
		})
	}
}

func TestTranslateAMD64PackedSumAbsoluteDifferencesCompleteGoAssemblerForms(t *testing.T) {
	src := `
TEXT packedsadforms(SB),NOSPLIT,$0-0
	PSADBW X1, X2
	PSADBW (AX), X2
	VPSADBW X1, X2, X3
	VPSADBW (AX), X2, X3
	VPSADBW Y1, Y2, Y3
	VPSADBW (AX), Y2, Y3
	VPSADBW Z1, Z2, Z3
	VPSADBW (AX), Z2, Z3
	RET
`
	ll := translateAMD64EcosystemCase(t, src, "packedsadforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "packed-sad-forms.ll", "packed-sad-forms.o", ll)
}

func TestTranslateAMD64PackedSumAbsoluteDifferencesRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"PSADBW Y1, Y2",
		"VPSADBW X1, Y2, Y3",
		"VPSADBW X1, X2, K1, X3",
		"VPSADBW.Z X1, X2, X3",
		"VPSADBW.BCST (AX), X2, X3",
		"VPSADBW $1, X2, X3",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidpackedsad(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedsad": {Name: "invalidpackedsad", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's PSADBW/VPSADBW tables", instruction)
			}
		})
	}
}

func TestTranslateAMD64VectorLaneExtractCompleteGoAssemblerForms(t *testing.T) {
	// VEXTRACTF128/I128 share Go 1.27's _yvextractf128 table.
	var src strings.Builder
	src.WriteString("TEXT vectorlaneextractforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"VEXTRACTF128", "VEXTRACTI128"} {
		fmt.Fprintf(&src, "\t%s $1, Y1, X2\n", op)
		fmt.Fprintf(&src, "\t%s $-1, Y1, (AX)\n", op)
	}
	// These four produce 128 bits from either Y or Z and share
	// _yvextractf32x4, including masked register/memory destinations.
	for _, op := range []string{"VEXTRACTF32X4", "VEXTRACTF64X2", "VEXTRACTI32X4", "VEXTRACTI64X2"} {
		for _, form := range []string{
			"$1, Y1, X2", "$1, Y1, (AX)",
			"$1, Y1, K1, X2", "$1, Y1, K1, (AX)",
			"$3, Z1, X2", "$3, Z1, (AX)",
			"$3, Z1, K1, X2", "$3, Z1, K1, (AX)",
		} {
			fmt.Fprintf(&src, "\t%s %s\n", op, form)
		}
		fmt.Fprintf(&src, "\t%s.Z $1, Y1, K1, X2\n", op)
		fmt.Fprintf(&src, "\t%s.Z $3, Z1, K1, X2\n", op)
	}
	// These four produce 256 bits from Z and share _yvextractf32x8.
	for _, op := range []string{"VEXTRACTF32X8", "VEXTRACTF64X4", "VEXTRACTI32X8", "VEXTRACTI64X4"} {
		for _, form := range []string{
			"$1, Z1, Y2", "$1, Z1, (AX)",
			"$1, Z1, K1, Y2", "$1, Z1, K1, (AX)",
		} {
			fmt.Fprintf(&src, "\t%s %s\n", op, form)
		}
		fmt.Fprintf(&src, "\t%s.Z $1, Z1, K1, Y2\n", op)
	}
	src.WriteString("\tRET\n")
	ll := translateAMD64EcosystemCase(t, src.String(), "vectorlaneextractforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "vector-lane-extract-forms.ll", "vector-lane-extract-forms.o", ll)
}

func TestTranslateAMD64VectorLaneExtractRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VEXTRACTI128 $1, Z1, X2",
		"VEXTRACTF128 $1, Y1, K1, X2",
		"VEXTRACTI32X4 $1, X1, X2",
		"VEXTRACTF64X2 $1, Y1, Y2",
		"VEXTRACTI32X8 $1, Y1, Y2",
		"VEXTRACTF64X4 $1, Z1, K0, Y2",
		"VEXTRACTF32X4.Z $1, Y1, X2",
		"VEXTRACTI64X2.Z $1, Z1, K1, (AX)",
		"VEXTRACTI64X4.SAE $1, Z1, Y2",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidvectorlaneextract(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidvectorlaneextract": {Name: "invalidvectorlaneextract", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's vector-lane extract tables", instruction)
			}
		})
	}
}

func TestTranslateAMD64PackedScalarExtractCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27's legacy yextr/yextrw tables accept an unsigned imm8, an
	// X0-X15 source, and a GP-or-memory destination. The yextr table used by
	// B/D/Q also (unusually) classifies M0-M7 as destinations; those names
	// encode the correspondingly numbered GP registers.
	var src strings.Builder
	src.WriteString("TEXT packedscalarextractforms(SB),NOSPLIT,$0-0\n")
	for _, spec := range []struct {
		op       string
		maxIndex int
		mmxDst   bool
	}{
		{op: "PEXTRB", maxIndex: 15, mmxDst: true},
		{op: "PEXTRW", maxIndex: 7},
		{op: "PEXTRD", maxIndex: 3, mmxDst: true},
		{op: "PEXTRQ", maxIndex: 1, mmxDst: true},
	} {
		fmt.Fprintf(&src, "\t%s $%d, X15, AX\n", spec.op, spec.maxIndex)
		fmt.Fprintf(&src, "\t%s $255, X15, (AX)\n", spec.op)
		if spec.mmxDst {
			fmt.Fprintf(&src, "\t%s $%d, X15, M2\n", spec.op, spec.maxIndex)
		}
	}

	// Go 1.27's _yvextractps/_yvpextrw tables add signed-imm8 VEX forms
	// for X0-X15 and unsigned-imm8 EVEX forms for X16-X31. They do not add
	// mask or instruction-suffix forms.
	for _, spec := range []struct {
		op       string
		maxIndex int
	}{
		{op: "VPEXTRB", maxIndex: 15},
		{op: "VPEXTRW", maxIndex: 7},
		{op: "VPEXTRD", maxIndex: 3},
		{op: "VPEXTRQ", maxIndex: 1},
	} {
		fmt.Fprintf(&src, "\t%s $%d, X1, R8\n", spec.op, spec.maxIndex)
		fmt.Fprintf(&src, "\t%s $255, X1, (AX)\n", spec.op)
		fmt.Fprintf(&src, "\t%s $-128, X1, R8\n", spec.op)
		fmt.Fprintf(&src, "\t%s $%d, X31, R15\n", spec.op, spec.maxIndex)
		fmt.Fprintf(&src, "\t%s $255, X31, (AX)\n", spec.op)
	}
	src.WriteString("\tRET\n")

	ll := translateAMD64EcosystemCase(t, src.String(), "packedscalarextractforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "packed-scalar-extract-forms.ll", "packed-scalar-extract-forms.o", ll)
}

func TestTranslateAMD64PackedScalarExtractRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"PEXTRB $-1, X1, AX",
		"PEXTRD $256, X1, AX",
		"PEXTRW $1, X1, M2",
		"PEXTRQ $1, X16, AX",
		"PEXTRB $1, Y1, AX",
		"VPEXTRB $-129, X1, AX",
		"VPEXTRW $256, X1, AX",
		"VPEXTRD $-1, X20, AX",
		"VPEXTRQ $1, X1, M2",
		"VPEXTRB $1, X1, K1, AX",
		"VPEXTRW.Z $1, X1, AX",
		"VPEXTRD.BCST $1, X1, (AX)",
		"VPEXTRQ.SAE $1, X1, AX",
		"VPEXTRB $1, X1, X2",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidpackedscalarextract(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedscalarextract": {Name: "invalidpackedscalarextract", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's PEXTR/VPEXTR tables", instruction)
			}
		})
	}
}

func TestTranslateAMD64MoveHighLowPackedSingleCompleteGoAssemblerForms(t *testing.T) {
	// MOVHLPS/MOVLHPS use Go 1.27's yxr table (X0-X15, two operands).
	// VMOVHLPS/VMOVLHPS share _yvmovhlps: three X operands, with both the
	// X0-X15 VEX entry and the X0-X31 EVEX entry.
	src := `
TEXT movehighlowpackedsingleforms(SB),NOSPLIT,$0-0
	MOVHLPS X1, X2
	MOVLHPS X15, X0
	VMOVHLPS X1, X2, X3
	VMOVLHPS X15, X14, X13
	VMOVHLPS X20, X2, X3
	VMOVHLPS X1, X20, X3
	VMOVLHPS X1, X2, X31
	RET
`
	ll := translateAMD64EcosystemCase(t, src, "movehighlowpackedsingleforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "move-high-low-packed-single-forms.ll", "move-high-low-packed-single-forms.o", ll)
}

func TestTranslateAMD64MoveHighLowPackedSingleRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"MOVHLPS X16, X1",
		"MOVLHPS X1, X16",
		"MOVHLPS (AX), X1",
		"MOVLHPS X1, X2, X3",
		"VMOVHLPS X1, X2",
		"VMOVLHPS (AX), X2, X3",
		"VMOVHLPS Y1, Y2, Y3",
		"VMOVLHPS X1, X2, K1, X3",
		"VMOVHLPS.Z X1, X2, X3",
		"VMOVLHPS.BCST X1, X2, X3",
		"VMOVHLPS.SAE X1, X2, X3",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidmovehighlowpackedsingle(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidmovehighlowpackedsingle": {Name: "invalidmovehighlowpackedsingle", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's MOVHLPS/MOVLHPS tables", instruction)
			}
		})
	}
}

func TestTranslateAMD64PopulationCountCompleteGoAssemblerForms(t *testing.T) {
	// POPCNTW/L/Q all use Go 1.27's yml_rl table: a Yml GP-or-memory
	// source followed by a Yrl GP destination.
	src := `
TEXT populationcountforms(SB),NOSPLIT,$0-0
	POPCNTW AX, BX
	POPCNTW (AX), R8
	POPCNTW R15, R14
	POPCNTL AX, BX
	POPCNTL (AX), R8
	POPCNTL R15, R14
	POPCNTQ AX, BX
	POPCNTQ (AX), R8
	POPCNTQ R15, R14
	RET
`
	ll := translateAMD64EcosystemCase(t, src, "populationcountforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "population-count-forms.ll", "population-count-forms.o", ll)
}

func TestTranslate386PopulationCountCompleteGoAssemblerForms(t *testing.T) {
	src := `
TEXT populationcount386forms(SB),NOSPLIT,$0-0
	POPCNTW AX, BX
	POPCNTW (AX), CX
	POPCNTL AX, BX
	POPCNTL (AX), CX
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"populationcount386forms": {Name: "populationcount386forms", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "population-count-386-forms.ll", "population-count-386-forms.o", ll)

	invalid, err := Parse(ArchAMD64, "TEXT invalidpopulationcount386(SB),NOSPLIT,$0-0\n\tPOPCNTQ AX, BX\n\tRET\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(invalid, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"invalidpopulationcount386": {Name: "invalidpopulationcount386", Ret: Void},
		},
	}); err == nil {
		t.Fatal("Translate accepted POPCNTQ for GOARCH=386")
	}
}

func TestTranslateAMD64PopulationCountRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"POPCNTW AL, BX",
		"POPCNTL AX, AH",
		"POPCNTQ M1, AX",
		"POPCNTW X1, AX",
		"POPCNTL AX, (BX)",
		"POPCNTQ $1, AX",
		"POPCNTW.Z AX, BX",
		"POPCNTL AX, BX, CX",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidpopulationcount(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpopulationcount": {Name: "invalidpopulationcount", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's POPCNT tables", instruction)
			}
		})
	}
}

func TestTranslateAMD64PackedMoveMaskCompleteGoAssemblerForms(t *testing.T) {
	// PMOVMSKB's ymskb table has X and M source rows. VPMOVMSKB's
	// _yvmovmskpd table has X and Y source rows. Every row writes Yrl and
	// every vector register is limited to 0-15; neither table has EVEX rows.
	src := `
TEXT packedmovemaskforms(SB),NOSPLIT,$0-0
	PMOVMSKB X0, AX
	PMOVMSKB X15, R8
	PMOVMSKB M0, BX
	PMOVMSKB M7, R15
	VPMOVMSKB X0, AX
	VPMOVMSKB X15, R8
	VPMOVMSKB Y0, BX
	VPMOVMSKB Y15, R15
	RET
`
	ll := translateAMD64EcosystemCase(t, src, "packedmovemaskforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "packed-move-mask-forms.ll", "packed-move-mask-forms.o", ll)
}

func TestTranslateAMD64PackedMoveMaskRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"PMOVMSKB Y1, AX",
		"PMOVMSKB X16, AX",
		"PMOVMSKB (AX), BX",
		"PMOVMSKB X1, M2",
		"VPMOVMSKB M1, AX",
		"VPMOVMSKB X16, AX",
		"VPMOVMSKB Y16, AX",
		"VPMOVMSKB X1, AL",
		"VPMOVMSKB X1, X2",
		"VPMOVMSKB X1, K1, AX",
		"PMOVMSKB.Z X1, AX",
		"VPMOVMSKB.BCST Y1, AX",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidpackedmovemask(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedmovemask": {Name: "invalidpackedmovemask", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's PMOVMSKB/VPMOVMSKB tables", instruction)
			}
		})
	}
}

func TestTranslateAMD64BitwiseNotCompleteGoAssemblerForms(t *testing.T) {
	// NOTB/W/L/Q all use Go 1.27's yscond table, whose sole row is Ymb.
	// Besides memory and full GP spellings, Ymb admits low/high byte register
	// spellings; for wider operations Go encodes those spellings by ModRM
	// number (for example, NOTW AH encodes NOTW SP).
	var src strings.Builder
	src.WriteString("TEXT bitwisenotforms(SB),NOSPLIT,$0-0\n")
	operands := []string{
		"AX", "BX", "CX", "DX", "SP", "BP", "SI", "DI",
		"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
		"AL", "AH", "BL", "BH", "CL", "CH", "DL", "DH",
		"BPB", "SIB", "DIB", "R8B", "R9B", "R10B", "R11B", "R12B", "R13B", "R14B", "R15B",
		"(BX)",
	}
	for _, op := range []string{"NOTB", "NOTW", "NOTL", "NOTQ"} {
		for _, operand := range operands {
			fmt.Fprintf(&src, "\t%s %s\n", op, operand)
		}
	}
	src.WriteString("\tRET\n")
	ll := translateAMD64EcosystemCase(t, src.String(), "bitwisenotforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "bitwise-not-forms.ll", "bitwise-not-forms.o", ll)
}

func TestTranslate386BitwiseNotCompleteGoAssemblerForms(t *testing.T) {
	// In 386 mode Go classifies SP as Yrl32, which does not cover Ymb, but
	// accepts BP/SI/DI by synthesizing an equivalent instruction sequence.
	// Exercise every accepted GP spelling, both byte aliases, and memory.
	var src strings.Builder
	src.WriteString("TEXT bitwisenot386forms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"NOTB", "NOTW", "NOTL"} {
		for _, operand := range []string{
			"AX", "BX", "CX", "DX", "BP", "SI", "DI",
			"AL", "AH", "BL", "BH", "CL", "CH", "DL", "DH",
			"(BX)",
		} {
			fmt.Fprintf(&src, "\t%s %s\n", op, operand)
		}
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"bitwisenot386forms": {Name: "bitwisenot386forms", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "bitwise-not-386-forms.ll", "bitwise-not-386-forms.o", ll)

	for _, instruction := range []string{"NOTB SP", "NOTW SP", "NOTL SP", "NOTQ AX", "NOTB R8"} {
		t.Run("reject_"+strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			invalid, err := Parse(ArchAMD64, "TEXT invalidbitwisenot386(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(invalid, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"invalidbitwisenot386": {Name: "invalidbitwisenot386", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which Go 1.27 rejects for GOARCH=386", instruction)
			}
		})
	}
}

func TestTranslateAMD64BitwiseNotRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"NOTB M1",
		"NOTW X1",
		"NOTL K1",
		"NOTQ $1",
		"NOTB AX, BX",
		"NOTW.Z AX",
		"NOTL.BCST (AX)",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidbitwisenot(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidbitwisenot": {Name: "invalidbitwisenot", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's NOT tables", instruction)
			}
		})
	}
}

func TestTranslateAMD64ParallelBitDepositExtractCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 uses one _yandnl row for the whole family:
	// Yml source/mask, Yrl source value, and Yrl destination. This gives each
	// L/Q instruction both register and memory first-operand forms.
	var src strings.Builder
	src.WriteString("TEXT parallelbitforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"PDEPL", "PDEPQ", "PEXTL", "PEXTQ"} {
		fmt.Fprintf(&src, "\t%s AX, BX, CX\n", op)
		fmt.Fprintf(&src, "\t%s (SI), R8, R15\n", op)
		fmt.Fprintf(&src, "\t%s parallelBitMask(SB), R9, R10\n", op)
	}
	src.WriteString("\tRET\n")
	ll := translateAMD64EcosystemCase(t, src.String(), "parallelbitforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "parallel-bit-forms.ll", "parallel-bit-forms.o", ll)
}

func TestTranslate386ParallelBitDepositExtractCompleteGoAssemblerForms(t *testing.T) {
	// The Go 1.27 assembler accepts the same four instruction names in 386
	// mode. Yml/Yrl admit all eight 386 GP registers, including SP in any
	// register position; only the first operand can instead be memory.
	var src strings.Builder
	src.WriteString("TEXT parallelbitforms386(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"PDEPL", "PDEPQ", "PEXTL", "PEXTQ"} {
		fmt.Fprintf(&src, "\t%s AX, BX, CX\n", op)
		fmt.Fprintf(&src, "\t%s (SI), BP, DI\n", op)
		fmt.Fprintf(&src, "\t%s SP, AX, BX\n", op)
		fmt.Fprintf(&src, "\t%s AX, SP, BX\n", op)
		fmt.Fprintf(&src, "\t%s AX, BX, SP\n", op)
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"parallelbitforms386": {Name: "parallelbitforms386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "parallel-bit-386-forms.ll", "parallel-bit-386-forms.o", ll)
}

func TestTranslateAMD64ParallelBitDepositExtractRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"PDEPL AX, BX",
		"PDEPQ AX, (BX), CX",
		"PEXTL AX, BX, (CX)",
		"PEXTQ $1, AX, BX",
		"PDEPL AL, BX, CX",
		"PDEPQ AX, X0, BX",
		"PEXTL AX, BX, X0",
		"PEXTQ.Z AX, BX, CX",
		"PDEPL.BCST (AX), BX, CX",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidparallelbit(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidparallelbit": {Name: "invalidparallelbit", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's PDEP/PEXT table", instruction)
			}
		})
	}
}

func TestTranslate386ParallelBitDepositExtractRejectsHighRegisters(t *testing.T) {
	for _, instruction := range []string{
		"PDEPL R8, AX, BX",
		"PDEPQ AX, R8, BX",
		"PEXTL AX, BX, R8",
	} {
		file, err := Parse(ArchAMD64, "TEXT invalidparallelbit386(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs: map[string]FuncSig{
				"invalidparallelbit386": {Name: "invalidparallelbit386", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q, which Go 1.27 rejects for GOARCH=386", instruction)
		}
	}
}

func TestTranslateAMD64BitTestFamilyCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 gives all BT/BTC/BTR/BTS W/L/Q instructions exactly two ybtl
	// rows: signed imm8 + Yml and Yrl + Yml.
	var src strings.Builder
	src.WriteString("TEXT bittestforms(SB),NOSPLIT,$0-0\n")
	for _, stem := range []string{"BT", "BTC", "BTR", "BTS"} {
		for _, width := range []string{"W", "L", "Q"} {
			op := stem + width
			fmt.Fprintf(&src, "\t%s $-128, AX\n", op)
			fmt.Fprintf(&src, "\t%s $127, (BX)\n", op)
			fmt.Fprintf(&src, "\t%s CX, R15\n", op)
			fmt.Fprintf(&src, "\t%s R8, 8(SI)\n", op)
			fmt.Fprintf(&src, "\t%s R9, bitTestGlobal(SB)\n", op)
		}
	}
	src.WriteString("\tRET\n")
	ll := translateAMD64EcosystemCase(t, src.String(), "bittestforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "bit-test-forms.ll", "bit-test-forms.o", ll)
}

func TestTranslate386BitTestFamilyCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT bittestforms386(SB),NOSPLIT,$0-0\n")
	for _, stem := range []string{"BT", "BTC", "BTR", "BTS"} {
		for _, width := range []string{"W", "L"} {
			op := stem + width
			fmt.Fprintf(&src, "\t%s $-128, AX\n", op)
			fmt.Fprintf(&src, "\t%s $127, (BX)\n", op)
			fmt.Fprintf(&src, "\t%s CX, DI\n", op)
			fmt.Fprintf(&src, "\t%s SP, BP\n", op)
			fmt.Fprintf(&src, "\t%s AX, SP\n", op)
		}
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"bittestforms386": {Name: "bittestforms386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "bit-test-386-forms.ll", "bit-test-386-forms.o", ll)
}

func TestTranslateAMD64BitTestFamilyRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"BTB $1, AX",
		"BTRL $128, AX",
		"BTSQ $-129, AX",
		"BTCW AX",
		"BTL (AX), BX",
		"BTRQ AL, AX",
		"BTSW AX, $1",
		"BTQ AX, X0",
		"BTCL.Z AX, BX",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT invalidbittest(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidbittest": {Name: "invalidbittest", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's ybtl table", instruction)
			}
		})
	}
}

func TestTranslate386BitTestFamilyRejectsArchitectureRestrictedForms(t *testing.T) {
	for _, instruction := range []string{
		"BTQ $1, AX",
		"BTCQ AX, BX",
		"BTRQ $1, (BX)",
		"BTSQ AX, SP",
		"BTL R8, AX",
		"BTRW AX, R8",
	} {
		file, err := Parse(ArchAMD64, "TEXT invalidbittest386(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs: map[string]FuncSig{
				"invalidbittest386": {Name: "invalidbittest386", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q, which Go 1.27 rejects for GOARCH=386", instruction)
		}
	}
}

func TestTranslateAMD64ScalarAddSubCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT scalaraddsubforms(SB),NOSPLIT,$0-0\n")
	for _, stem := range []string{"ADD", "SUB"} {
		fmt.Fprintf(&src, "\t%sB $-2147483648, AL\n", stem)
		fmt.Fprintf(&src, "\t%sB $4294967295, bytearg+0(FP)\n", stem)
		fmt.Fprintf(&src, "\t%sB BP, (BX)\n", stem)
		fmt.Fprintf(&src, "\t%sB (BX), R15\n", stem)
		fmt.Fprintf(&src, "\t%sB bytearg+0(FP), R14\n", stem)
		fmt.Fprintf(&src, "\t%sB CL, bytearg+0(FP)\n", stem)
		for _, form := range []struct {
			width  string
			fpName string
			offset int
		}{
			{width: "W", fpName: "wordarg", offset: 8},
			{width: "L", fpName: "longarg", offset: 16},
			{width: "Q", fpName: "quadarg", offset: 24},
		} {
			op := stem + form.width
			fmt.Fprintf(&src, "\t%s $-2147483648, AX\n", op)
			fmt.Fprintf(&src, "\t%s $4294967295, %s+%d(FP)\n", op, form.fpName, form.offset)
			fmt.Fprintf(&src, "\t%s R8, (BX)\n", op)
			fmt.Fprintf(&src, "\t%s (BX), R15\n", op)
			fmt.Fprintf(&src, "\t%s %s+%d(FP), R14\n", op, form.fpName, form.offset)
			fmt.Fprintf(&src, "\t%s CX, %s+%d(FP)\n", op, form.fpName, form.offset)
		}
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"scalaraddsubforms": {
				Name: "scalaraddsubforms",
				Args: []LLVMType{I8, I16, I32, I64},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: I8, Index: 0, Field: -1},
					{Offset: 8, Type: I16, Index: 1, Field: -1},
					{Offset: 16, Type: I32, Index: 2, Field: -1},
					{Offset: 24, Type: I64, Index: 3, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "scalar-add-sub-forms.ll", "scalar-add-sub-forms.o", ll)
}

func TestTranslate386ScalarAddSubCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT scalaraddsubforms386(SB),NOSPLIT,$0-0\n")
	for _, stem := range []string{"ADD", "SUB"} {
		fmt.Fprintf(&src, "\t%sB $4294967296, BP\n", stem)
		fmt.Fprintf(&src, "\t%sB $-2147483649, bytearg+0(FP)\n", stem)
		fmt.Fprintf(&src, "\t%sB SI, (BX)\n", stem)
		fmt.Fprintf(&src, "\t%sB (BX), DI\n", stem)
		for _, form := range []struct {
			width  string
			fpName string
			offset int
		}{
			{width: "W", fpName: "wordarg", offset: 4},
			{width: "L", fpName: "longarg", offset: 8},
		} {
			op := stem + form.width
			fmt.Fprintf(&src, "\t%s $4294967296, AX\n", op)
			fmt.Fprintf(&src, "\t%s $1, SP\n", op)
			fmt.Fprintf(&src, "\t%s $-2147483649, %s+%d(FP)\n", op, form.fpName, form.offset)
			fmt.Fprintf(&src, "\t%s SI, (BX)\n", op)
			fmt.Fprintf(&src, "\t%s (BX), DI\n", op)
		}
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"scalaraddsubforms386": {
				Name: "scalaraddsubforms386",
				Args: []LLVMType{I8, I16, I32},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: I8, Index: 0, Field: -1},
					{Offset: 4, Type: I16, Index: 1, Field: -1},
					{Offset: 8, Type: I32, Index: 2, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "scalar-add-sub-386-forms.ll", "scalar-add-sub-386-forms.o", ll)
}

func TestTranslateAMD64ScalarAddSubRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"ADDB (AX), (BX)",
		"SUBW (AX), (BX)",
		"ADDL $-2147483649, AX",
		"SUBQ $4294967296, AX",
		"ADDQ.Z AX, BX",
		"SUBQ X0, AX",
		"ADDQ AX, X0",
		"SUBQ AX, $1",
		"ADDB SP, (AX)",
		"SUBB (AX), SP",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT invalidscalaraddsub(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidscalaraddsub": {Name: "invalidscalaraddsub", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's ADD/SUB tables", instruction)
			}
		})
	}
}

func TestTranslate386ScalarAddSubRejectsArchitectureRestrictedForms(t *testing.T) {
	for _, instruction := range []string{
		"ADDQ AX, BX",
		"SUBQ $1, (BX)",
		"ADDL R8, AX",
		"SUBW AX, R8",
		"ADDB R8, (AX)",
		"SUBB (AX), R8",
		"ADDB SP, (AX)",
	} {
		file, err := Parse(ArchAMD64, "TEXT invalidscalaraddsub386(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs: map[string]FuncSig{
				"invalidscalaraddsub386": {Name: "invalidscalaraddsub386", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q, which Go 1.27 rejects for 386", instruction)
		}
	}
}

func TestTranslateAMD64CompareExchangeCompleteGoAssemblerForms(t *testing.T) {
	src := `
DATA cmpxchgdata+0(SB)/8, $0
DATA cmpxchgdata+8(SB)/8, $0
GLOBL cmpxchgdata(SB), NOPTR, $16
TEXT cmpxchgforms(SB),NOSPLIT,$0-16
	CMPXCHGB AH, R11
	CMPXCHGB R11, SP
	CMPXCHGB DL, (R12)
	CMPXCHGB DL, 0(FS)
	CMPXCHGB DL, cmpxchgdata(SB)
	CMPXCHGB DL, value+0(FP)
	CMPXCHGW DX, R11
	CMPXCHGW R11, (R12)
	CMPXCHGW DX, 0(GS)
	CMPXCHGW DX, cmpxchgdata(SB)
	CMPXCHGW DX, value+0(FP)
	CMPXCHGL DX, R11
	CMPXCHGL R11, (R12)
	CMPXCHGL DX, 0(FS)
	CMPXCHGL DX, cmpxchgdata(SB)
	CMPXCHGL DX, value+0(FP)
	CMPXCHGQ DX, R11
	CMPXCHGQ R11, (R12)
	CMPXCHGQ DX, 0(GS)
	CMPXCHGQ DX, cmpxchgdata(SB)
	CMPXCHGQ DX, value+0(FP)
	CMPXCHG8B R11
	CMPXCHG8B SP
	CMPXCHG8B (R12)
	CMPXCHG8B 0(FS)
	CMPXCHG8B cmpxchgdata(SB)
	CMPXCHG8B value+0(FP)
	CMPXCHG16B R11
	CMPXCHG16B SP
	CMPXCHG16B (R12)
	CMPXCHG16B 0(GS)
	CMPXCHG16B cmpxchgdata(SB)
	CMPXCHG16B value+0(FP)
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"cmpxchgforms": {
				Name: "cmpxchgforms",
				Args: []LLVMType{LLVMType("i128")},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: LLVMType("i128"), Index: 0, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "cmpxchg-forms.ll", "cmpxchg-forms.o", ll)
}

func TestTranslate386CompareExchangeCompleteGoAssemblerForms(t *testing.T) {
	src := `
DATA cmpxchgdata386+0(SB)/8, $0
GLOBL cmpxchgdata386(SB), NOPTR, $8
TEXT cmpxchgforms386(SB),NOSPLIT,$0-8
	CMPXCHGB BP, (BX)
	CMPXCHGB SI, DI
	CMPXCHGB DL, 0(FS)
	CMPXCHGB DL, cmpxchgdata386(SB)
	CMPXCHGB DL, value+0(FP)
	CMPXCHGW SI, DI
	CMPXCHGW DX, SP
	CMPXCHGW DX, (BX)
	CMPXCHGW DX, 0(FS)
	CMPXCHGW DX, cmpxchgdata386(SB)
	CMPXCHGW DX, value+0(FP)
	CMPXCHGL SI, DI
	CMPXCHGL DX, SP
	CMPXCHGL DX, (BX)
	CMPXCHGL DX, 0(FS)
	CMPXCHGL DX, cmpxchgdata386(SB)
	CMPXCHGL DX, value+0(FP)
	CMPXCHG8B AX
	CMPXCHG8B BP
	CMPXCHG8B SI
	CMPXCHG8B (BX)
	CMPXCHG8B 0(FS)
	CMPXCHG8B cmpxchgdata386(SB)
	CMPXCHG8B value+0(FP)
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"cmpxchgforms386": {
				Name: "cmpxchgforms386",
				Args: []LLVMType{I64},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: I64, Index: 0, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "cmpxchg-386-forms.ll", "cmpxchg-386-forms.o", ll)
}

func TestTranslateAMD64CompareExchangeRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"CMPXCHGB (BX), DL",
		"CMPXCHGW (BX), DX",
		"CMPXCHGL $1, DX",
		"CMPXCHGQ DX, $1",
		"CMPXCHGB X0, DL",
		"CMPXCHGL DX, X0",
		"CMPXCHG8B",
		"CMPXCHG8B (BX), AX",
		"CMPXCHG8B $1",
		"CMPXCHG16B",
		"CMPXCHG16B (BX), AX",
		"CMPXCHG16B.Z (BX)",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT invalidcmpxchg(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidcmpxchg": {Name: "invalidcmpxchg", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's CMPXCHG tables", instruction)
			}
		})
	}
}

func TestTranslate386CompareExchangeRejectsArchitectureRestrictedForms(t *testing.T) {
	for _, instruction := range []string{
		"CMPXCHGQ DX, (BX)",
		"CMPXCHG16B (BX)",
		"CMPXCHGB R8, (BX)",
		"CMPXCHGW R8, (BX)",
		"CMPXCHGL R8, (BX)",
		"CMPXCHGB SP, (BX)",
		"CMPXCHGB DL, SP",
		"CMPXCHG8B SP",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT invalidcmpxchg386(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"invalidcmpxchg386": {Name: "invalidcmpxchg386", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which Go 1.27 rejects for 386", instruction)
			}
		})
	}
}

func TestTranslateAMD64TrailingZeroCountCompleteGoAssemblerForms(t *testing.T) {
	// TZCNTW/L/Q all use Go 1.27's ycrc32l table: Yml source, Yrl
	// destination. The width is selected only by the opcode prefix.
	src := `
TEXT trailingzerocountforms(SB),NOSPLIT,$0-0
	TZCNTW AX, BX
	TZCNTW (AX), R8
	TZCNTW R15, R14
	TZCNTL AX, BX
	TZCNTL (AX), R8
	TZCNTL R15, R14
	TZCNTQ AX, BX
	TZCNTQ (AX), R8
	TZCNTQ R15, R14
	RET
`
	ll := translateAMD64EcosystemCase(t, src, "trailingzerocountforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "trailing-zero-count-forms.ll", "trailing-zero-count-forms.o", ll)
}

func TestTranslate386TrailingZeroCountCompleteGoAssemblerForms(t *testing.T) {
	src := `
TEXT trailingzerocount386forms(SB),NOSPLIT,$0-0
	TZCNTW AX, BX
	TZCNTW (AX), CX
	TZCNTL AX, BX
	TZCNTL (AX), CX
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"trailingzerocount386forms": {Name: "trailingzerocount386forms", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "trailing-zero-count-386-forms.ll", "trailing-zero-count-386-forms.o", ll)

	invalid, err := Parse(ArchAMD64, "TEXT invalidtrailingzerocount386(SB),NOSPLIT,$0-0\n\tTZCNTQ AX, BX\n\tRET\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(invalid, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"invalidtrailingzerocount386": {Name: "invalidtrailingzerocount386", Ret: Void},
		},
	}); err == nil {
		t.Fatal("Translate accepted TZCNTQ for GOARCH=386")
	}
}

func TestTranslateAMD64TrailingZeroCountRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"TZCNTW AL, BX",
		"TZCNTL AX, AH",
		"TZCNTQ M1, AX",
		"TZCNTW X1, AX",
		"TZCNTL AX, (BX)",
		"TZCNTQ $1, AX",
		"TZCNTW.Z AX, BX",
		"TZCNTL AX, BX, CX",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidtrailingzerocount(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidtrailingzerocount": {Name: "invalidtrailingzerocount", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's TZCNT tables", instruction)
			}
		})
	}
}

func TestTranslateAMD64FloatingCompareCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27's legacy yxcmpi table accepts X/m, X0-X15, signed imm8.
	// The packed AVX _yvcmppd table adds X/Y vector-result VEX forms and
	// X/Y/Z K-result EVEX forms. EVEX memory sources may use .BCST; only
	// the Z-register source form may use .SAE. The scalar _yvcmpsd table
	// has X vector-result VEX forms and X K-result EVEX forms; only the
	// EVEX register-source form may use .SAE.
	var src strings.Builder
	src.WriteString("TEXT floatingcompareforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"CMPPD", "CMPPS", "CMPSD", "CMPSS"} {
		fmt.Fprintf(&src, "\t%s X1, X15, $-128\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X15, $127\n", op)
	}
	for _, op := range []string{"VCMPPD", "VCMPPS"} {
		fmt.Fprintf(&src, "\t%s $255, X1, X2, X3\n", op)
		fmt.Fprintf(&src, "\t%s $0, (AX), X2, X3\n", op)
		fmt.Fprintf(&src, "\t%s $255, Y1, Y2, Y3\n", op)
		fmt.Fprintf(&src, "\t%s $0, (AX), Y2, Y3\n", op)
		for _, width := range []string{"X", "Y", "Z"} {
			fmt.Fprintf(&src, "\t%s $255, %s20, %s21, K0\n", op, width, width)
			fmt.Fprintf(&src, "\t%s $0, (AX), %s21, K1, K7\n", op, width)
			fmt.Fprintf(&src, "\t%s.BCST $255, (AX), %s21, K7\n", op, width)
		}
		fmt.Fprintf(&src, "\t%s.SAE $255, Z20, Z21, K1, K7\n", op)
	}
	for _, op := range []string{"VCMPSD", "VCMPSS"} {
		fmt.Fprintf(&src, "\t%s $255, X1, X2, X3\n", op)
		fmt.Fprintf(&src, "\t%s $0, (AX), X2, X3\n", op)
		fmt.Fprintf(&src, "\t%s $255, X20, X21, K0\n", op)
		fmt.Fprintf(&src, "\t%s $0, (AX), X21, K1, K7\n", op)
		fmt.Fprintf(&src, "\t%s.SAE $255, X20, X21, K1, K7\n", op)
	}
	src.WriteString("\tRET\n")

	ll := translateAMD64EcosystemCase(t, src.String(), "floatingcompareforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "floating-compare-forms.ll", "floating-compare-forms.o", ll)
}

func TestTranslate386FloatingCompareCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT floatingcompareforms386(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"CMPPD", "CMPPS", "CMPSD", "CMPSS"} {
		fmt.Fprintf(&src, "\t%s X1, X7, $-128\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X7, $127\n", op)
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"floatingcompareforms386": {Name: "floatingcompareforms386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "floating-compare-forms-386.ll", "floating-compare-forms-386.o", ll)
}

func TestTranslateAMD64FloatingCompareRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"CMPPD X1, X2, $-129",
		"CMPPS X1, X2, $128",
		"CMPSD X16, X2, $0",
		"CMPSS X1, X16, $0",
		"CMPPD Y1, X2, $0",
		"CMPPS.BCST (AX), X2, $0",
		"VCMPPD $-1, X1, X2, X3",
		"VCMPPS $256, X1, X2, X3",
		"VCMPSD $0, Y1, X2, X3",
		"VCMPSS $0, X1, Y2, X3",
		"VCMPPD $0, X1, X2, Y3",
		"VCMPPS $0, Y1, Y2, X3",
		"VCMPPD $0, X20, X21, X22",
		"VCMPSD $0, X20, X21, X22",
		"VCMPSS $0, X1, X2, K0, K1",
		"VCMPPD $0, X1, X2, K0, K1",
		"VCMPPS.Z $0, Z1, Z2, K1, K2",
		"VCMPPD.BCST $0, Z1, Z2, K1",
		"VCMPPS.BCST $0, (AX), X2, X3",
		"VCMPSD.BCST $0, (AX), X2, K1",
		"VCMPSS.BCST $0, (AX), X2, K1",
		"VCMPPD.SAE $0, X1, X2, K1",
		"VCMPPS.SAE $0, Y1, Y2, K1",
		"VCMPPD.SAE $0, (AX), Z2, K1",
		"VCMPSD.SAE $0, (AX), X2, K1",
		"VCMPSS.SAE $0, X1, X2, X3",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidfloatingcompare(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidfloatingcompare": {Name: "invalidfloatingcompare", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's CMP/VCMP floating-point tables", instruction)
			}
		})
	}
}

func TestTranslate386FloatingCompareRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"CMPPD X8, X1, $0",
		"CMPSD X1, X8, $0",
		"VCMPPD $0, X1, X2, X3",
		"VCMPSD $0, X1, X2, X3",
	} {
		src := "TEXT invalidfloatingcompare386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
		file, err := Parse(ArchAMD64, src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs: map[string]FuncSig{
				"invalidfloatingcompare386": {Name: "invalidfloatingcompare386", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q for GOARCH=386", instruction)
		}
	}
}

func TestTranslateAMD64PackedSaturatingNarrowCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 names the legacy signed dword-to-word instruction PACKSSLW.
	// PACKSSLW/PACKSSWB/PACKUSWB use ymm (MMX/m64 and X/m128 forms), while
	// PACKUSDW uses yxm_q4 (X/m128 only). All four V instructions share
	// _yvandnpd: X/Y VEX plus X/Y/Z EVEX, optional K1-K7 and .Z. Only the
	// dword-to-word forms enable EVEX 32-bit memory broadcast.
	var src strings.Builder
	src.WriteString("TEXT packedsaturatingnarrowforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"PACKSSLW", "PACKSSWB", "PACKUSWB"} {
		fmt.Fprintf(&src, "\t%s M1, M7\n", op)
		fmt.Fprintf(&src, "\t%s (AX), M7\n", op)
		fmt.Fprintf(&src, "\t%s X1, X15\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X15\n", op)
	}
	src.WriteString("\tPACKUSDW X1, X15\n\tPACKUSDW (AX), X15\n")
	for _, op := range []string{"VPACKSSDW", "VPACKSSWB", "VPACKUSDW", "VPACKUSWB"} {
		fmt.Fprintf(&src, "\t%s X1, X2, X3\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X2, X3\n", op)
		fmt.Fprintf(&src, "\t%s Y1, Y2, Y3\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Y2, Y3\n", op)
		for _, width := range []string{"X", "Y", "Z"} {
			fmt.Fprintf(&src, "\t%s %s20, %s21, %s22\n", op, width, width, width)
			fmt.Fprintf(&src, "\t%s (AX), %s21, K1, %s22\n", op, width, width)
			fmt.Fprintf(&src, "\t%s.Z %s20, %s21, K7, %s22\n", op, width, width, width)
		}
	}
	for _, op := range []string{"VPACKSSDW", "VPACKUSDW"} {
		for _, width := range []string{"X", "Y", "Z"} {
			fmt.Fprintf(&src, "\t%s.BCST (AX), %s21, %s22\n", op, width, width)
			fmt.Fprintf(&src, "\t%s.BCST (AX), %s21, K1, %s22\n", op, width, width)
			fmt.Fprintf(&src, "\t%s.BCST.Z (AX), %s21, K7, %s22\n", op, width, width)
		}
	}
	src.WriteString("\tRET\n")

	ll := translateAMD64EcosystemCase(t, src.String(), "packedsaturatingnarrowforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "packed-saturating-narrow-forms.ll", "packed-saturating-narrow-forms.o", ll)
}

func TestTranslate386PackedSaturatingNarrowCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT packedsaturatingnarrowforms386(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"PACKSSLW", "PACKSSWB", "PACKUSWB"} {
		fmt.Fprintf(&src, "\t%s M1, M7\n", op)
		fmt.Fprintf(&src, "\t%s (AX), M7\n", op)
		fmt.Fprintf(&src, "\t%s X1, X7\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X7\n", op)
	}
	src.WriteString("\tPACKUSDW X1, X7\n\tPACKUSDW (AX), X7\n\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"packedsaturatingnarrowforms386": {Name: "packedsaturatingnarrowforms386", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "packed-saturating-narrow-forms-386.ll", "packed-saturating-narrow-forms-386.o", ll)
}

func TestTranslateAMD64PackedSaturatingNarrowRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"PACKSSLW M1, X2",
		"PACKSSWB X1, M2",
		"PACKUSDW M1, M2",
		"PACKUSWB X16, X1",
		"PACKSSLW X1, X16",
		"PACKSSWB.Z X1, X2",
		"PACKUSWB X1, X2, X3",
		"VPACKSSDW X1, X2",
		"VPACKSSWB X1, Y2, Y3",
		"VPACKUSDW Y1, Y2, X3",
		"VPACKUSWB Z1, Z2, Y3",
		"VPACKSSDW X1, X2, K0, X3",
		"VPACKSSWB.Z X1, X2, X3",
		"VPACKUSDW.BCST X1, X2, X3",
		"VPACKUSWB.BCST (AX), X2, X3",
		"VPACKSSWB.BCST.Z (AX), X2, K1, X3",
		"VPACKSSDW.SAE X1, X2, X3",
		"VPACKUSWB X1, X2, K1",
		"VPACKUSDW X1, (AX), X3",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidpackedsaturatingnarrow(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedsaturatingnarrow": {Name: "invalidpackedsaturatingnarrow", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's PACK/VPACK tables", instruction)
			}
		})
	}
}

func TestTranslate386PackedSaturatingNarrowRejectsVectorForms(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT invalidpackedsaturatingnarrow386(SB),NOSPLIT,$0-0\n\tVPACKSSDW X1, X2, X3\n\tRET\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"invalidpackedsaturatingnarrow386": {Name: "invalidpackedsaturatingnarrow386", Ret: Void},
		},
	}); err == nil {
		t.Fatal("Translate accepted VPACKSSDW for GOARCH=386")
	}
}

func TestTranslateAMD64VariableDwordPermuteCompleteGoAssemblerForms(t *testing.T) {
	// VPERMD and VPERMPS share Go 1.27's _yvpermd table: Y-only VEX,
	// Y/Z EVEX, optional K1-K7 and .Z, plus 32-bit memory broadcast.
	var src strings.Builder
	src.WriteString("TEXT variabledwordpermuteforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"VPERMD", "VPERMPS"} {
		fmt.Fprintf(&src, "\t%s Y1, Y2, Y3\n", op)
		fmt.Fprintf(&src, "\t%s (AX), Y2, Y3\n", op)
		for _, width := range []string{"Y", "Z"} {
			fmt.Fprintf(&src, "\t%s %s20, %s21, %s22\n", op, width, width, width)
			fmt.Fprintf(&src, "\t%s (AX), %s21, K1, %s22\n", op, width, width)
			fmt.Fprintf(&src, "\t%s.Z %s20, %s21, K7, %s22\n", op, width, width, width)
			fmt.Fprintf(&src, "\t%s.BCST (AX), %s21, %s22\n", op, width, width)
			fmt.Fprintf(&src, "\t%s.BCST.Z (AX), %s21, K7, %s22\n", op, width, width)
		}
	}
	src.WriteString("\tRET\n")

	ll := translateAMD64EcosystemCase(t, src.String(), "variabledwordpermuteforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "variable-dword-permute-forms.ll", "variable-dword-permute-forms.o", ll)
}

func TestTranslateAMD64VariableDwordPermuteRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VPERMD X1, X2, X3",
		"VPERMPS Y1, Z2, Z3",
		"VPERMD Z1, Z2, Y3",
		"VPERMPS Y1, (AX), Y3",
		"VPERMD Y1, Y2, K0, Y3",
		"VPERMPS.Z Y1, Y2, Y3",
		"VPERMD.BCST Y1, Y2, Y3",
		"VPERMPS.BCST.Z (AX), Z2, Z3",
		"VPERMD.SAE Y1, Y2, Y3",
		"VPERMPS Y1, Y2, K1",
		"VPERMD Y1, Y2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidvariabledwordpermute(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidvariabledwordpermute": {Name: "invalidvariabledwordpermute", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's VPERMD/VPERMPS table", instruction)
			}
		})
	}
}

func TestTranslate386VariableDwordPermuteCompleteGoAssemblerForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT variabledwordpermuteforms386(SB),$0-0\n")
	for _, op := range []string{"VPERMD", "VPERMPS"} {
		fmt.Fprintf(&source, "\t%s Y1, Y2, Y3\n", op)
		fmt.Fprintf(&source, "\t%s (AX), Y2, Y3\n", op)
		fmt.Fprintf(&source, "\t%s Y31, Y30, Y29\n", op)
		fmt.Fprintf(&source, "\t%s Z7, Z6, Z5\n", op)
		fmt.Fprintf(&source, "\t%s.BCST (AX), Y30, Y29\n", op)
		fmt.Fprintf(&source, "\t%s.BCST (AX), Z6, Z5\n", op)
	}
	source.WriteString("\tRET\n")
	requireX86GoAssemblerResult(t, "386", source.String(), true)

	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "linux", triple: "i386-unknown-linux-gnu"},
		{name: "windows", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"variabledwordpermuteforms386": {Name: "variabledwordpermuteforms386", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "variable-dword-permute-forms-386-"+target.name+".ll", "variable-dword-permute-forms-386-"+target.name+".o", ll)
		})
	}
}

func TestTranslate386VariableDwordPermuteRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VPERMD Z8, Z0, Z1",
		"VPERMPS Z0, Z8, Z1",
		"VPERMD Z0, Z1, Z8",
		"VPERMD Y1, Y2, K1, Y3",
		"VPERMPS.Z Y1, Y2, K1, Y3",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, "386", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's 386 VPERMD/VPERMPS table", instruction)
			}
		})
	}
}

func TestTranslateAMD64ConditionalSetCompleteGoAssemblerForms(t *testing.T) {
	conditions := []string{"CC", "CS", "EQ", "GE", "GT", "HI", "LE", "LS", "LT", "MI", "NE", "OC", "OS", "PC", "PL", "PS"}
	var src strings.Builder
	src.WriteString("TEXT conditionalsetforms(SB),NOSPLIT,$0-1\n")
	for _, condition := range conditions {
		op := "SET" + condition
		fmt.Fprintf(&src, "\t%s R15\n", op)
		fmt.Fprintf(&src, "\t%s AH\n", op)
		fmt.Fprintf(&src, "\t%s BPB\n", op)
		fmt.Fprintf(&src, "\t%s R15B\n", op)
		fmt.Fprintf(&src, "\t%s (AX)\n", op)
		fmt.Fprintf(&src, "\t%s conditionalSetGlobal(SB)\n", op)
		fmt.Fprintf(&src, "\t%s ret+0(FP)\n", op)
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"conditionalsetforms": {
				Name: "conditionalsetforms",
				Ret:  I8,
				Frame: FrameLayout{Results: []FrameSlot{{
					Offset: 0,
					Type:   I8,
					Index:  0,
					Field:  -1,
				}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "conditional-set-forms.ll", "conditional-set-forms.o", ll)
}

func TestTranslate386ConditionalSetCompleteGoAssemblerForms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT conditionalsetforms386(SB),NOSPLIT,$0-1\n")
	for _, condition := range []string{"CC", "CS", "EQ", "GE", "GT", "HI", "LE", "LS", "LT", "MI", "NE", "OC", "OS", "PC", "PL", "PS"} {
		op := "SET" + condition
		fmt.Fprintf(&src, "\t%s DX\n", op)
		fmt.Fprintf(&src, "\t%s AH\n", op)
		fmt.Fprintf(&src, "\t%s BP\n", op)
		fmt.Fprintf(&src, "\t%s SI\n", op)
		fmt.Fprintf(&src, "\t%s DI\n", op)
		fmt.Fprintf(&src, "\t%s (AX)\n", op)
		fmt.Fprintf(&src, "\t%s ret+0(FP)\n", op)
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		Sigs: map[string]FuncSig{
			"conditionalsetforms386": {
				Name: "conditionalsetforms386",
				Ret:  I8,
				Frame: FrameLayout{Results: []FrameSlot{{
					Offset: 0,
					Type:   I8,
					Index:  0,
					Field:  -1,
				}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "i386-unknown-linux-gnu", "conditional-set-forms-386.ll", "conditional-set-forms-386.o", ll)
}

func TestTranslateAMD64ConditionalSetRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"SETNE X1",
		"SETLE M1",
		"SETEQ K1",
		"SETCC $1",
		"SETGT",
		"SETGE AX, BX",
		"SETHI.Z AX",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidconditionalset(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidconditionalset": {Name: "invalidconditionalset", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's SETcc tables", instruction)
			}
		})
	}
}

func TestTranslate386ConditionalSetRejectsArchitectureRestrictedRegisters(t *testing.T) {
	for _, register := range []string{"SP", "R8"} {
		file, err := Parse(ArchAMD64, "TEXT invalidconditionalset386(SB),NOSPLIT,$0-0\n\tSETNE "+register+"\n\tRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs: map[string]FuncSig{
				"invalidconditionalset386": {Name: "invalidconditionalset386", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted SETNE %s for GOARCH=386", register)
		}
	}
}

func TestTranslateAMD64VectorScalarMoveCompleteGoAssemblerForms(t *testing.T) {
	// VMOVSD and VMOVSS share Go 1.27's _yvmovsd table. It contains VEX
	// scalar register-to-memory, memory-to-register, and three-register merge
	// forms plus their EVEX high-register and optional K-mask counterparts.
	// Zeroing is valid only for masked register destinations.
	var src strings.Builder
	src.WriteString("TEXT vectorscalarmoveforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"VMOVSD", "VMOVSS"} {
		fmt.Fprintf(&src, "\t%s X1, (AX)\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X1\n", op)
		fmt.Fprintf(&src, "\t%s X1, X2, X3\n", op)
		fmt.Fprintf(&src, "\t%s X20, (AX)\n", op)
		fmt.Fprintf(&src, "\t%s X20, K1, (AX)\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X20\n", op)
		fmt.Fprintf(&src, "\t%s (AX), K1, X20\n", op)
		fmt.Fprintf(&src, "\t%s.Z (AX), K7, X20\n", op)
		fmt.Fprintf(&src, "\t%s X20, X21, X22\n", op)
		fmt.Fprintf(&src, "\t%s X20, X21, K1, X22\n", op)
		fmt.Fprintf(&src, "\t%s.Z X20, X21, K7, X22\n", op)
	}
	src.WriteString("\tRET\n")

	ll := translateAMD64EcosystemCase(t, src.String(), "vectorscalarmoveforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "vector-scalar-move-forms.ll", "vector-scalar-move-forms.o", ll)
}

func TestTranslateAMD64VectorScalarMoveFrameSources(t *testing.T) {
	src := `
TEXT vmovsdframe(SB),NOSPLIT,$0-8
	VMOVSD value+0(FP), X0
	RET
TEXT vmovssframe(SB),NOSPLIT,$0-4
	VMOVSS value+0(FP), X0
	RET
TEXT vmovsdframeresult(SB),NOSPLIT,$0-8
	VMOVSD X0, value+0(FP)
	RET
TEXT vmovssframeresult(SB),NOSPLIT,$0-4
	VMOVSS X0, value+0(FP)
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"vmovsdframe": {
				Name: "vmovsdframe",
				Args: []LLVMType{LLVMType("double")},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{{
					Offset: 0,
					Type:   LLVMType("double"),
					Index:  0,
					Field:  -1,
				}}},
			},
			"vmovssframe": {
				Name: "vmovssframe",
				Args: []LLVMType{LLVMType("float")},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{{
					Offset: 0,
					Type:   LLVMType("float"),
					Index:  0,
					Field:  -1,
				}}},
			},
			"vmovsdframeresult": {
				Name: "vmovsdframeresult",
				Ret:  LLVMType("double"),
				Frame: FrameLayout{Results: []FrameSlot{{
					Offset: 0,
					Type:   LLVMType("double"),
					Index:  0,
					Field:  -1,
				}}},
			},
			"vmovssframeresult": {
				Name: "vmovssframeresult",
				Ret:  LLVMType("float"),
				Frame: FrameLayout{Results: []FrameSlot{{
					Offset: 0,
					Type:   LLVMType("float"),
					Index:  0,
					Field:  -1,
				}}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "vector-scalar-move-frame.ll", "vector-scalar-move-frame.o", ll)
}

func TestTranslateAMD64VectorScalarMoveRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VMOVSD X1, X2",
		"VMOVSS (AX), (BX)",
		"VMOVSD Y1, X2, X3",
		"VMOVSS X1, Y2, X3",
		"VMOVSD X1, X2, Y3",
		"VMOVSS X1, X2, (AX)",
		"VMOVSD (AX), K0, X1",
		"VMOVSS X1, K0, (AX)",
		"VMOVSD X1, X2, K0, X3",
		"VMOVSS.Z (AX), X1",
		"VMOVSD.Z X1, K1, (AX)",
		"VMOVSS.Z X1, X2, X3",
		"VMOVSD.BCST (AX), X1",
		"VMOVSS.SAE X1, X2, X3",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalidvectorscalarmove(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, "amd64", strings.ReplaceAll(src, "NOSPLIT", "4"), false)
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidvectorscalarmove": {Name: "invalidvectorscalarmove", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's VMOVSD/VMOVSS table", instruction)
			}
		})
	}
}

func TestTranslate386VectorScalarMoveRejectsForms(t *testing.T) {
	for _, op := range []string{"VMOVSD", "VMOVSS"} {
		requireX86GoAssemblerResult(t, "386", "TEXT bad(SB),4,$0-0\n"+op+" X0, X1, K1, X2\nRET\n", false)
		file, err := Parse(ArchAMD64, "TEXT invalidvectorscalarmove386(SB),NOSPLIT,$0-0\n\t"+op+" X0, X1, K1, X2\n\tRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs: map[string]FuncSig{
				"invalidvectorscalarmove386": {Name: "invalidvectorscalarmove386", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %s for GOARCH=386", op)
		}
	}
}

func TestTranslateX86VectorScalarFlagCompareCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 gives VCOMISD/VCOMISS/VUCOMISD/VUCOMISS the shared
	// _yvcomisd table. It has exactly two rows: VEX X/m,X and EVEX X/m,X.
	// EVEX permits X0-X31 and .SAE for register sources; it does not permit
	// masks, zeroing, broadcast, or vector widths other than X. Go's 386
	// assembler exposes the same two rows, including the EVEX register class.
	var src strings.Builder
	src.WriteString("TEXT vectorscalarflagcompareforms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"VCOMISD", "VCOMISS", "VUCOMISD", "VUCOMISS"} {
		fmt.Fprintf(&src, "\t%s X1, X2\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X2\n", op)
		fmt.Fprintf(&src, "\t%s X20, X2\n", op)
		fmt.Fprintf(&src, "\t%s X1, X21\n", op)
		fmt.Fprintf(&src, "\t%s (AX), X21\n", op)
		fmt.Fprintf(&src, "\t%s.SAE X1, X2\n", op)
		fmt.Fprintf(&src, "\t%s.SAE X20, X21\n", op)
	}
	src.WriteString("\tRET\n")
	// Named Go frontend compatibility includes high X registers even on
	// 386; raw architectural 32-bit decoding has stricter register limits.
	for _, arch := range []string{"386", "amd64"} {
		assembleX87ControlBytes(t, arch, strings.ReplaceAll(src.String(), "NOSPLIT", "4"))
	}

	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-macosx"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"vectorscalarflagcompareforms": {Name: "vectorscalarflagcompareforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "vector-scalar-flag-compare-"+target.goarch+".ll", "vector-scalar-flag-compare-"+target.goarch+".o", ll)
		})
	}
}

func TestTranslateX86VectorScalarFlagCompareRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{goarch: "386", triple: "i386-unknown-linux-gnu"},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			for _, instruction := range []string{
				"VCOMISD",
				"VCOMISS X1",
				"VUCOMISD X1, X2, X3",
				"VUCOMISS Y1, X2",
				"VCOMISD X1, Y2",
				"VCOMISS Z1, X2",
				"VUCOMISD K1, X2",
				"VUCOMISS X1, (AX)",
				"VCOMISD $1, X2",
				"VCOMISS.SAE (AX), X2",
				"VUCOMISD.BCST (AX), X2",
				"VUCOMISS.Z X1, X2",
				"VCOMISD X1, K1, X2",
			} {
				t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
					src := "TEXT invalidvectorscalarflagcompare(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
					file, err := Parse(ArchAMD64, src)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := Translate(file, Options{
						TargetTriple: target.triple,
						Goarch:       target.goarch,
						Sigs: map[string]FuncSig{
							"invalidvectorscalarflagcompare": {Name: "invalidvectorscalarflagcompare", Ret: Void},
						},
					}); err == nil {
						t.Fatalf("Translate accepted %q for %s, which is absent from Go 1.27's _yvcomisd table", instruction, target.goarch)
					}
				})
			}
		})
	}
}

func TestTranslateAMD64AdditionalPackedIntegerFamilies(t *testing.T) {
	src := `
TEXT packedintegerfamilies(SB),NOSPLIT,$0-0
	PADDB X0, X1
	PCMPEQW X0, X1
	PMULLW X0, X1
	PABSD X0, X1
	PSUBUSB X0, X1
	PTEST X0, X1
	RET
`
	translateAMD64EcosystemCase(t, src, "packedintegerfamilies")
}

func TestTranslateAMD64AdditionalConditionalMoveWidths(t *testing.T) {
	src := `
TEXT conditionalmoves(SB),NOSPLIT,$0-0
	CMPQ AX, BX
	CMOVQLE CX, DX
	CMOVLGT CX, DX
	CMOVWCC CX, DX
	RET
`
	translateAMD64EcosystemCase(t, src, "conditionalmoves")
}

func TestTranslateAMD64LegacyScalarAndPackedFloatingPointFamilies(t *testing.T) {
	src := `
TEXT floatfamilies(SB),NOSPLIT,$0-0
	MOVSS (AX), X0
	SQRTSS X0, X1
	ADDSS X0, X1
	SUBSS X0, X1
	MULSS X0, X1
	DIVSS X0, X1
	MINSS X0, X1
	MAXSS X0, X1
	MOVSS X1, (BX)
	MOVUPD (AX), X2
	MOVAPD X2, (BX)
	MOVUPD X2, 16(BX)
	XORPD X2, X3
	ANDPS X2, X3
	ADDPS X2, X3
	SUBPS X2, X3
	MULPS X2, X3
	DIVPS X2, X3
	MINPS X2, X3
	MAXPS X2, X3
	SQRTPS X2, X3
	ADDPD X2, X3
	SUBPD X2, X3
	MULPD X2, X3
	DIVPD X2, X3
	MINPD X2, X3
	MAXPD X2, X3
	SQRTPD X2, X3
	MOVLHPS X2, X3
	MOVHLPS X2, X3
	MOVLPD (AX), X3
	MOVLPD X3, (BX)
	MOVHPD (AX), X3
	MOVHPD X3, (BX)
	SHUFPD $1, X2, X3
	UNPCKLPS X2, X3
	UNPCKHPD X2, X3
	MOVDDUP X2, X3
	HADDPD X2, X3
	HADDPD (AX), X3
	HADDPS X2, X3
	HADDPS (AX), X3
	CVTSS2SD X2, X3
	CVTSS2SD (AX), X3
	CVTSD2SS X2, X3
	CVTSD2SS (AX), X3
	UCOMISS X2, X3
	UCOMISD X2, X3
	RET
`
	translateAMD64EcosystemCase(t, src, "floatfamilies")
}

func TestTranslateAMD64DuplicateMoveFamilyCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27's legacy yxm table accepts X/m -> X for MOVDDUP,
	// MOVSHDUP, and MOVSLDUP. Its shared _yvmovddup table accepts
	// X/m -> X, Y/m -> Y, and Z/m -> Z for all three V-prefixed forms,
	// with optional K masking (and .Z zero masking) on EVEX forms.
	src := `
TEXT duplicatemoveforms(SB),NOSPLIT,$0-8
	MOVDDUP X1, X2
	MOVDDUP (AX), X2
	MOVDDUP source(SB), X2
	MOVDDUP alpha+0(FP), X2
	MOVSHDUP X1, X2
	MOVSHDUP (AX), X2
	MOVSHDUP source(SB), X2
	MOVSLDUP X1, X2
	MOVSLDUP (AX), X2
	MOVSLDUP source(SB), X2
	VMOVDDUP X1, X2
	VMOVDDUP (AX), X2
	VMOVDDUP Y1, Y2
	VMOVDDUP (AX), Y2
	VMOVDDUP X16, X17
	VMOVDDUP X16, K1, X17
	VMOVDDUP.Z (AX), K1, X17
	VMOVDDUP Y16, Y17
	VMOVDDUP Y16, K1, Y17
	VMOVDDUP.Z (AX), K1, Y17
	VMOVDDUP Z1, Z2
	VMOVDDUP Z1, K1, Z2
	VMOVDDUP.Z source(SB), K1, Z2
	VMOVSHDUP X1, X2
	VMOVSHDUP (AX), X2
	VMOVSHDUP Y1, Y2
	VMOVSHDUP (AX), Y2
	VMOVSHDUP X16, X17
	VMOVSHDUP X16, K1, X17
	VMOVSHDUP.Z (AX), K1, X17
	VMOVSHDUP Y16, Y17
	VMOVSHDUP Y16, K1, Y17
	VMOVSHDUP.Z (AX), K1, Y17
	VMOVSHDUP Z1, Z2
	VMOVSHDUP Z1, K1, Z2
	VMOVSHDUP.Z source(SB), K1, Z2
	VMOVSLDUP X1, X2
	VMOVSLDUP (AX), X2
	VMOVSLDUP Y1, Y2
	VMOVSLDUP (AX), Y2
	VMOVSLDUP X16, X17
	VMOVSLDUP X16, K1, X17
	VMOVSLDUP.Z (AX), K1, X17
	VMOVSLDUP Y16, Y17
	VMOVSLDUP Y16, K1, Y17
	VMOVSLDUP.Z (AX), K1, Y17
	VMOVSLDUP Z1, Z2
	VMOVSLDUP Z1, K1, Z2
	VMOVSLDUP.Z source(SB), K1, Z2
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{"duplicatemoveforms": {
			Name: "duplicatemoveforms",
			Args: []LLVMType{LLVMType("double")},
			Ret:  Void,
			Frame: FrameLayout{Params: []FrameSlot{{
				Offset: 0,
				Type:   LLVMType("double"),
				Index:  0,
				Field:  -1,
			}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTranslateAMD64DuplicateMoveFamilyRejectsFormsOutsideGoOptabs(t *testing.T) {
	for _, instruction := range []string{
		"MOVSHDUP Y1, Y2",
		"MOVSLDUP.Z X1, X2",
		"VMOVSHDUP X1, Y2",
		"VMOVSLDUP.Z X1, X2",
		"VMOVDDUP.Z.Z X1, K1, X2",
		"VMOVDDUP X1, K0, X2",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidduplicatemove(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidduplicatemove": {Name: "invalidduplicatemove", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's yxm/_yvmovddup tables", instruction)
			}
		})
	}
}

func TestTranslateAMD64PackedDwordMultiplyFamilyCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 uses yxm_q4 for PMULLD (X/m, X) and _yvandnpd for
	// VPMULLD. The latter has VEX X/Y forms plus EVEX X/Y/Z forms with
	// optional K1-K7 masking, .Z zero masking, and memory-only .BCST.
	src := `
TEXT packeddwordmultiplyforms(SB),NOSPLIT,$0-0
	PMULLD X1, X2
	PMULLD (AX), X2
	PMULLD source(SB), X2
	VPMULLD X1, X2, X3
	VPMULLD (AX), X2, X3
	VPMULLD Y1, Y2, Y3
	VPMULLD (AX), Y2, Y3
	VPMULLD X16, X17, X18
	VPMULLD X16, X17, K1, X18
	VPMULLD.Z (AX), X17, K1, X18
	VPMULLD Y16, Y17, Y18
	VPMULLD Y16, Y17, K1, Y18
	VPMULLD.Z (AX), Y17, K1, Y18
	VPMULLD Z1, Z2, Z3
	VPMULLD Z1, Z2, K1, Z3
	VPMULLD.Z source(SB), Z2, K1, Z3
	VPMULLD.BCST (AX), X17, X18
	VPMULLD.BCST (AX), Y17, K1, Y18
	VPMULLD.BCST.Z source(SB), Z2, K1, Z3
	RET
`
	translateAMD64EcosystemCase(t, src, "packeddwordmultiplyforms")
}

func TestTranslateAMD64PackedDwordMultiplyFamilyRejectsFormsOutsideGoOptabs(t *testing.T) {
	for _, instruction := range []string{
		"PMULLD Y1, Y2",
		"VPMULLD X1, Y2, Y3",
		"VPMULLD X1, X2, K0, X3",
		"VPMULLD.Z X1, X2, X3",
		"VPMULLD.BCST X1, X2, K1, X3",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidpackeddwordmultiply(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackeddwordmultiply": {Name: "invalidpackeddwordmultiply", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's PMULLD/VPMULLD tables", instruction)
			}
		})
	}
}

func TestTranslateAMD64MXCSRStateFamilyCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27's ysvrs_mo/ysvrs_om and _yvldmxcsr tables give all four
	// instructions exactly one memory operand. Exercise general, SP, SB, and
	// named FP memory; VEX changes only encoding, not the operand shape.
	src := `
TEXT mxcsrstateforms(SB),NOSPLIT,$0-8
	LDMXCSR (AX)
	LDMXCSR -8(SP)
	LDMXCSR control(SB)
	LDMXCSR input+0(FP)
	VLDMXCSR (AX)
	VLDMXCSR control(SB)
	STMXCSR 4(BX)
	STMXCSR -8(SP)
	STMXCSR control(SB)
	STMXCSR output+4(FP)
	VSTMXCSR (AX)
	VSTMXCSR output+4(FP)
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"mxcsrstateforms": {
				Name: "mxcsrstateforms",
				Args: []LLVMType{I32},
				Ret:  I32,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, "%local_stack = alloca") {
		t.Fatal("amd64 SP-relative MXCSR memory did not receive byte-addressable local-stack backing")
	}
	for _, intrinsic := range []string{"@llvm.x86.sse.ldmxcsr", "@llvm.x86.sse.stmxcsr"} {
		if !strings.Contains(ll, intrinsic) {
			t.Fatalf("MXCSR lowering omitted %s", intrinsic)
		}
	}
}

func TestTranslateAMD64MXCSRStateFamilyRejectsNonMemoryForms(t *testing.T) {
	for _, instruction := range []string{
		"LDMXCSR AX",
		"VLDMXCSR $1",
		"STMXCSR X1",
		"VSTMXCSR.Z (AX)",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidmxcsrstate(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidmxcsrstate": {Name: "invalidmxcsrstate", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, but Go's MXCSR tables require one memory operand", instruction)
			}
		})
	}
}

func TestTranslateAMD64PackedFloatToDwordFamilyCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27's yxcvm1 table gives both instructions X/m -> X and X/m -> M.
	// An X destination consumes four float32 lanes; an MMX destination consumes
	// two lanes (and therefore only 64 bits for a memory source).
	src := `
TEXT packedfloattodwordforms(SB),NOSPLIT,$0-0
	CVTPS2PL X1, X2
	CVTPS2PL (AX), X2
	CVTPS2PL source(SB), X2
	CVTPS2PL X1, M2
	CVTPS2PL (AX), M2
	CVTPS2PL source(SB), M2
	CVTTPS2PL X1, X2
	CVTTPS2PL (AX), X2
	CVTTPS2PL source(SB), X2
	CVTTPS2PL X1, M2
	CVTTPS2PL (AX), M2
	CVTTPS2PL source(SB), M2
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"packedfloattodwordforms": {Name: "packedfloattodwordforms", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, intrinsic := range []string{"@llvm.x86.sse2.cvtps2dq", "@llvm.x86.sse2.cvttps2dq"} {
		if !strings.Contains(ll, intrinsic) {
			t.Fatalf("packed float-to-dword lowering omitted %s", intrinsic)
		}
	}
}

func TestTranslateAMD64PackedFloatToDwordFamilyRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"CVTPS2PL Y1, X2",
		"CVTPS2PL X1, Y2",
		"CVTPS2PL $1, X2",
		"CVTTPS2PL.Z X1, X2",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidpackedfloattodword(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedfloattodword": {Name: "invalidpackedfloattodword", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's yxcvm1 table", instruction)
			}
		})
	}
}

func TestTranslateAMD64ConditionalMoveFamilyCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 has 48 entries sharing yml_rl: W/L/Q width crossed with all
	// 16 x86 condition codes. Yml accepts a same-width GP register or memory;
	// Yrl requires a GP register destination. Exercise both source categories
	// and both ordinary and extended registers for every instruction.
	conditions := []string{"CC", "CS", "EQ", "GE", "GT", "HI", "LE", "LS", "LT", "MI", "NE", "OC", "OS", "PC", "PL", "PS"}
	var src strings.Builder
	src.WriteString("TEXT conditionalmoveforms(SB),NOSPLIT,$0-8\n")
	for _, width := range []string{"W", "L", "Q"} {
		for _, condition := range conditions {
			op := "CMOV" + width + condition
			fmt.Fprintf(&src, "\t%s CX, DX\n", op)
			fmt.Fprintf(&src, "\t%s (R10), R11\n", op)
		}
	}
	src.WriteString("\tCMOVQPS source(SB), R10\n")
	src.WriteString("\tCMOVQPS input+0(FP), R9\n")
	src.WriteString("\tRET\n")

	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{"conditionalmoveforms": {
			Name: "conditionalmoveforms",
			Args: []LLVMType{I64},
			Ret:  Void,
			Frame: FrameLayout{Params: []FrameSlot{{
				Offset: 0, Type: I64, Index: 0, Field: -1,
			}}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTranslateAMD64ConditionalMoveFamilyRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"CMOVQPS $1, AX",
		"CMOVQPS AX, (BX)",
		"CMOVQPS X1, AX",
		"CMOVQPS.Z AX, BX",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidconditionalmove(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidconditionalmove": {Name: "invalidconditionalmove", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, but Go 1.27's yml_rl requires register/memory source and register destination", instruction)
			}
		})
	}
}

func TestTranslateAMD64PackedSingleToDoubleFamilyCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27's legacy yxm entry is X/m64 -> X. The VCVTPS2PD
	// _yvcvtph2ps table adds X/m64 -> X, X/m128 -> Y, and Y/m256 -> Z,
	// with EVEX masks/zeroing, memory broadcast, and SAE on the Z form.
	src := `
TEXT packedsingletodoubleforms(SB),NOSPLIT,$0-0
	CVTPS2PD X1, X2
	CVTPS2PD (AX), X2
	CVTPS2PD source(SB), X2
	VCVTPS2PD X1, X2
	VCVTPS2PD (AX), X2
	VCVTPS2PD X16, X17
	VCVTPS2PD X16, K1, X17
	VCVTPS2PD.Z (AX), K7, X17
	VCVTPS2PD.BCST (AX), X17
	VCVTPS2PD.BCST.Z source(SB), K1, X17
	VCVTPS2PD X1, Y2
	VCVTPS2PD (AX), Y2
	VCVTPS2PD X16, Y17
	VCVTPS2PD X16, K1, Y17
	VCVTPS2PD.Z (AX), K7, Y17
	VCVTPS2PD.BCST (AX), Y17
	VCVTPS2PD.BCST.Z source(SB), K1, Y17
	VCVTPS2PD Y1, Z2
	VCVTPS2PD (AX), Z2
	VCVTPS2PD Y16, Z17
	VCVTPS2PD Y16, K1, Z17
	VCVTPS2PD.Z (AX), K7, Z17
	VCVTPS2PD.BCST (AX), Z17
	VCVTPS2PD.BCST.Z source(SB), K1, Z17
	VCVTPS2PD.SAE Y16, Z17
	VCVTPS2PD.SAE.Z Y16, K1, Z17
	RET
`
	ll := translateAMD64EcosystemCase(t, src, "packedsingletodoubleforms")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "packed-single-to-double.ll", "packed-single-to-double.o", ll)
}

func TestTranslateAMD64PackedSingleToDoubleFamilyRejectsFormsOutsideGoOptabs(t *testing.T) {
	for _, instruction := range []string{
		"CVTPS2PD Y1, X2",
		"CVTPS2PD.Z X1, X2",
		"VCVTPS2PD Y1, Y2",
		"VCVTPS2PD X1, Z2",
		"VCVTPS2PD Z1, Z2",
		"VCVTPS2PD X1, K0, X2",
		"VCVTPS2PD.Z X1, X2",
		"VCVTPS2PD.BCST X1, X2",
		"VCVTPS2PD.SAE (AX), Z2",
		"VCVTPS2PD.SAE X1, X2",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidpackedsingletodouble(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalidpackedsingletodouble": {Name: "invalidpackedsingletodouble", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's CVTPS2PD/VCVTPS2PD tables", instruction)
			}
		})
	}
}

func TestTranslateAMD64ComplexFrameBitwiseMoveForms(t *testing.T) {
	// MOVSD and MOVUPS retain their ordinary yxmov X/m<->X formats when the
	// memory operand names a complex64 or complex128 value in the Go FP frame.
	src := `
TEXT complexframemoves(SB),NOSPLIT,$0-48
	MOVSD input64+0(FP), X0
	MOVSD X0, result64+24(FP)
	MOVUPS input128+8(FP), X1
	MOVUPS X1, result128+32(FP)
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"complexframemoves": {
				Name: "complexframemoves",
				Args: []LLVMType{"{ float, float }", "{ double, double }"},
				Ret:  LLVMType("{ float, float, double, double }"),
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: LLVMType("float"), Index: 0, Field: 0},
						{Offset: 4, Type: LLVMType("float"), Index: 0, Field: 1},
						{Offset: 8, Type: LLVMType("double"), Index: 1, Field: 0},
						{Offset: 16, Type: LLVMType("double"), Index: 1, Field: 1},
					},
					Results: []FrameSlot{
						{Offset: 24, Type: LLVMType("float"), Index: 0, Field: -1},
						{Offset: 28, Type: LLVMType("float"), Index: 1, Field: -1},
						{Offset: 32, Type: LLVMType("double"), Index: 2, Field: -1},
						{Offset: 40, Type: LLVMType("double"), Index: 3, Field: -1},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "complex-frame-moves.ll", "complex-frame-moves.o", ll)
}

func TestTranslateAMD64WritableFPParameterSlots(t *testing.T) {
	// Go's assembler gives named FP parameter slots mutable frame semantics.
	// Real assembly such as Gonum's GEMV kernels advances a slice base pointer
	// by writing it back to base+off(FP), then reads the updated value later.
	src := `
TEXT writablefpparam(SB),NOSPLIT,$0-16
body:
	MOVQ input+0(FP), AX
	ADDQ $8, AX
	MOVQ AX, input+0(FP)
	MOVQ input+0(FP), BX
	MOVQ BX, result+8(FP)
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs: map[string]FuncSig{
			"writablefpparam": {
				Name: "writablefpparam",
				Args: []LLVMType{Ptr},
				Ret:  Ptr,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: Ptr, Index: 0, Field: -1}},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, "%fp_arg_0 = alloca ptr") {
		t.Fatalf("writable FP parameter did not receive mutable shadow storage:\n%s", ll)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "writable-fp-param.ll", "writable-fp-param.o", ll)
}

func TestTranslateAMD64ConditionalBranchAliasFamilyCompleteGoAssemblerForms(t *testing.T) {
	// Keep this list aligned with the x86 aliases installed by
	// cmd/asm/internal/arch.archX86 in Go 1.27. Every conditional branch uses
	// yjcond: target, $0+target, and $1+target.
	aliases := []string{
		"JA", "JAE", "JB", "JBE", "JC", "JCC", "JCS",
		"JE", "JEQ", "JG", "JGE", "JGT", "JHI", "JHS",
		"JL", "JLE", "JLO", "JLS", "JLT", "JMI", "JNA",
		"JNAE", "JNB", "JNBE", "JNC", "JNE", "JNG", "JNGE",
		"JNL", "JNLE", "JNO", "JNP", "JNS", "JNZ", "JO",
		"JOC", "JOS", "JP", "JPC", "JPE", "JPL", "JPO",
		"JPS", "JS", "JZ",
	}
	var src strings.Builder
	src.WriteString("TEXT conditionalbranchaliases(SB),NOSPLIT,$0-0\n")
	src.WriteString("\tUCOMISD X0, X1\n")
	for i, alias := range aliases {
		for hint := -1; hint <= 1; hint++ {
			label := fmt.Sprintf("branch_alias_%d_%d", i, hint+1)
			if hint < 0 {
				fmt.Fprintf(&src, "\t%s %s\n", alias, label)
			} else {
				fmt.Fprintf(&src, "\t%s $%d, %s\n", alias, hint, label)
			}
			fmt.Fprintf(&src, "%s:\n", label)
		}
	}
	src.WriteString("\tRET\n")
	translateAMD64EcosystemCase(t, src.String(), "conditionalbranchaliases")
}

func TestTranslateX86MSRAccessFamilyCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 assigns both RDMSR and WRMSR the operand-free ynone table on
	// amd64 and 386. Their inputs/outputs are the architectural CX and DX:AX
	// register tuple.
	src := `
TEXT msraccessforms(SB),NOSPLIT,$0-0
	MOVL $0x10, CX
	RDMSR
	WRMSR
	RET
`
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{goarch: "386", triple: "i386-unknown-linux-gnu"},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"msraccessforms": {Name: "msraccessforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`asm sideeffect "rdmsr"`, `asm sideeffect "wrmsr"`} {
				if !strings.Contains(ll, want) {
					t.Fatalf("MSR access lowering omitted %q:\n%s", want, ll)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "msr-access.ll", "msr-access.o", ll)
		})
	}
}

func TestTranslateX86MSRAccessFamilyRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, target := range []struct {
		goarch string
		triple string
	}{
		{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{goarch: "386", triple: "i386-unknown-linux-gnu"},
	} {
		for _, instruction := range []string{"RDMSR AX", "WRMSR CX", "RDMSR.P", "WRMSR.Z"} {
			name := target.goarch + "_" + strings.NewReplacer(" ", "_", ".", "_").Replace(instruction)
			t.Run(name, func(t *testing.T) {
				src := "TEXT invalidmsraccess(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
				file, err := Parse(ArchAMD64, src)
				if err != nil {
					return
				}
				if _, err := Translate(file, Options{
					TargetTriple: target.triple,
					Goarch:       target.goarch,
					Sigs: map[string]FuncSig{
						"invalidmsraccess": {Name: "invalidmsraccess", Ret: Void},
					},
				}); err == nil {
					t.Fatalf("Translate accepted %q for %s, but Go 1.27 uses ynone", instruction, target.goarch)
				}
			})
		}
	}
}

func TestTranslateX86DescriptorTableFamilyCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 groups the system descriptor instructions into these complete
	// operand tables: LGDT/LIDT and SGDT/SIDT take memory; LLDT/LTR/LMSW take
	// GP-register or memory inputs; SLDT*/SMSW*/STR* write GP registers or
	// memory. Q forms exist only on amd64.
	common := `
TEXT descriptorforms(SB),NOSPLIT,$32-0
	LGDT (BX)
	LIDT 8(SP)
	SGDT (CX)
	SIDT 16(SP)
	LLDT AX
	LLDT (BX)
	LTR DI
	LTR 8(SP)
	LMSW CX
	LMSW (DX)
	SLDTW AX
	SLDTW (BX)
	SLDTL DI
	SLDTL 8(SP)
	SMSWW CX
	SMSWW (DX)
	SMSWL BP
	SMSWL 16(SP)
	STRW SI
	STRW (DI)
	STRL BX
	STRL 24(SP)
	STRL SP
`
	amd64Only := `
	SLDTQ R11
	SLDTQ (R12)
	SMSWQ R13
	SMSWQ (R14)
	STRQ R15
	STRQ (R10)
`
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-macosx"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			src := common
			if target.goarch == "amd64" {
				src += amd64Only
			}
			src += "\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"descriptorforms": {Name: "descriptorforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`asm sideeffect "lgdt`, `asm sideeffect "lidt`,
				`asm sideeffect "sgdt`, `asm sideeffect "sidt`,
				`asm sideeffect "lldt`, `asm sideeffect "ltr`, `asm sideeffect "lmsw`,
				`asm sideeffect "sldt`, `asm sideeffect "smsw`, `asm sideeffect "str`,
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("descriptor-table lowering omitted %q:\n%s", want, ll)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "descriptor-table.ll", "descriptor-table.o", ll)
		})
	}
}

func TestTranslateX86DescriptorTableFamilyRejectsFormsOutsideGoOptab(t *testing.T) {
	tests := []struct {
		name        string
		goarch      string
		triple      string
		instruction string
	}{
		{name: "lgdt-register", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "LGDT AX"},
		{name: "sgdt-register", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "SGDT R11"},
		{name: "lidt-immediate", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "LIDT $1"},
		{name: "sidt-two-operands", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "SIDT (AX), (BX)"},
		{name: "lldt-immediate", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "LLDT $1"},
		{name: "ltr-vector", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "LTR X0"},
		{name: "lmsw-two-operands", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "LMSW AX, BX"},
		{name: "sldtw-immediate", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "SLDTW $1"},
		{name: "smswl-vector", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "SMSWL X0"},
		{name: "strq-two-operands", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "STRQ AX, BX"},
		{name: "lgdt-suffix", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "LGDT.P (AX)"},
		{name: "sldtw-suffix", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "SLDTW.Z AX"},
		{name: "386-sldtq", goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "SLDTQ AX"},
		{name: "386-smswq", goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "SMSWQ AX"},
		{name: "386-strq", goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "STRQ AX"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			src := "TEXT invaliddescriptor(SB),NOSPLIT,$0-0\n\t" + test.instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: test.triple,
				Goarch:       test.goarch,
				Sigs: map[string]FuncSig{
					"invaliddescriptor": {Name: "invaliddescriptor", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q for %s outside the Go 1.27 optab", test.instruction, test.goarch)
			}
		})
	}
}

func TestTranslateX86MachineRegisterMoveFamilyCompleteGoAssemblerForms(t *testing.T) {
	// This is the complete special-register portion of Go 1.27's ymovtab,
	// excluding the independently handled segment and TLS moves. MOVQ special
	// forms are accepted in 386 mode too; CR8 is the sole 64-bit-only register.
	common := `
TEXT machineregistermoves(SB),NOSPLIT,$32-0
	MOVL CR0, AX
	MOVL BX, CR0
	MOVL CR2, CX
	MOVL DX, CR2
	MOVL CR3, BP
	MOVL SI, CR3
	MOVL CR4, DI
	MOVL AX, CR4
	MOVQ CR0, BX
	MOVQ CX, CR0
	MOVQ CR2, DX
	MOVQ BP, CR2
	MOVQ CR3, SI
	MOVQ DI, CR3
	MOVQ CR4, AX
	MOVQ BX, CR4
	MOVL DR0, CX
	MOVL DX, DR0
	MOVL DR6, BP
	MOVL SI, DR6
	MOVL DR7, DI
	MOVL AX, DR7
	MOVQ DR0, BX
	MOVQ CX, DR0
	MOVQ DR2, DX
	MOVQ BP, DR2
	MOVQ DR3, SI
	MOVQ DI, DR3
	MOVQ DR6, AX
	MOVQ BX, DR6
	MOVQ DR7, CX
	MOVQ DX, DR7
	MOVL TR6, AX
	MOVL TR6, 0(SP)
	MOVL BX, TR6
	MOVL 4(SP), TR6
	MOVL TR7, CX
	MOVL TR7, 8(SP)
	MOVL DX, TR7
	MOVL 12(SP), TR7
	MOVL 0(SP), GDTR
	MOVL GDTR, 16(SP)
	MOVL 0(SP), IDTR
	MOVL IDTR, 16(SP)
	MOVQ 0(SP), GDTR
	MOVQ GDTR, 16(SP)
	MOVQ 0(SP), IDTR
	MOVQ IDTR, 16(SP)
	MOVW AX, LDTR
	MOVW 0(SP), LDTR
	MOVW LDTR, BX
	MOVW LDTR, 0(SP)
	MOVW CX, MSW
	MOVW 4(SP), MSW
	MOVW MSW, DX
	MOVW MSW, 4(SP)
	MOVW BP, TASK
	MOVW 8(SP), TASK
	MOVW TASK, SI
	MOVW TASK, 8(SP)
	MOVL CR0, SP
	MOVQ CR0, SP
`
	amd64Only := `
	MOVL CR8, R11
	MOVL R12, CR8
	MOVQ CR8, R13
	MOVQ R14, CR8
`
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-macosx"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			src := common
			if target.goarch == "amd64" {
				src += amd64Only
			}
			src += "\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"machineregistermoves": {Name: "machineregistermoves", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"%cr0", "%dr0", ".byte 0x0f, 0x24", ".byte 0x0f, 0x26"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("machine-register lowering omitted %q:\n%s", want, ll)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "machine-register.ll", "machine-register.o", ll)
		})
	}
}

func TestTranslateX86MachineRegisterMoveFamilyRejectsFormsOutsideGoMovtab(t *testing.T) {
	tests := []struct {
		name        string
		goarch      string
		triple      string
		instruction string
	}{
		{name: "cr1", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVQ CR1, AX"},
		{name: "cr5", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVL AX, CR5"},
		{name: "cr-memory", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVQ CR0, (AX)"},
		{name: "386-cr8-l", goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "MOVL CR8, AX"},
		{name: "386-cr8-q", goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "MOVQ AX, CR8"},
		{name: "movl-dr2", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVL DR2, AX"},
		{name: "movq-dr1", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVQ AX, DR1"},
		{name: "dr-memory", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVQ (AX), DR0"},
		{name: "tr5", goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "MOVL TR5, AX"},
		{name: "tr-q", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVQ TR6, AX"},
		{name: "gdtr-register", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVQ AX, GDTR"},
		{name: "gdtr-width", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVW (AX), GDTR"},
		{name: "ldtr-width", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVL AX, LDTR"},
		{name: "machine-suffix", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVQ.P CR0, AX"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			src := "TEXT invalidmachineregistermove(SB),NOSPLIT,$0-0\n\t" + test.instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: test.triple,
				Goarch:       test.goarch,
				Sigs: map[string]FuncSig{
					"invalidmachineregistermove": {Name: "invalidmachineregistermove", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q for %s outside Go 1.27's ymovtab", test.instruction, test.goarch)
			}
		})
	}
}

func TestTranslateX86ScalarExtensionMoveCompleteGo127Forms(t *testing.T) {
	amd64Ops := []string{
		"MOVBWSX", "MOVBWZX", "MOVBLSX", "MOVBLZX", "MOVBQSX", "MOVBQZX",
		"MOVWLSX", "MOVWLZX", "MOVWQSX", "MOVWQZX", "MOVLQSX", "MOVLQZX",
		"MOVSWW", "MOVZWW",
	}
	ops386 := []string{
		"MOVBWSX", "MOVBWZX", "MOVBLSX", "MOVBLZX",
		"MOVWLSX", "MOVWLZX", "MOVLQZX", "MOVSWW", "MOVZWW",
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
		ops    []string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin", ops: amd64Ops},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", ops: amd64Ops},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc", ops: amd64Ops},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu", ops: ops386},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc", ops: ops386},
	} {
		t.Run(target.name, func(t *testing.T) {
			var src strings.Builder
			src.WriteString("TEXT scalar_extension_forms(SB),NOSPLIT,$0-1\n")
			for _, op := range target.ops {
				source := "AX"
				if strings.HasPrefix(op, "MOVB") {
					source = "AL"
					if target.goarch == "386" {
						source = "BP" // Go rewrites this Yrl32 byte source through BX.
					}
				}
				fmt.Fprintf(&src, "\t%s %s, CX\n", op, source)
				fmt.Fprintf(&src, "\t%s 8(BX), DX\n", op)
			}
			src.WriteString("\tMOVBWZX x+0(FP), SP\n\tRET\n")
			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"scalar_extension_forms": {
						Name: "scalar_extension_forms", Args: []LLVMType{I8}, Ret: Void,
						Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I8, Index: 0, Field: -1}}},
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "scalar-extension-"+target.name+".ll", "scalar-extension-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86ScalarExtensionMoveRejectsFormsOutsideGo127Tables(t *testing.T) {
	tests := []struct {
		name        string
		goarch      string
		triple      string
		instruction string
	}{
		{name: "missing-source", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVBWZX AX"},
		{name: "too-many", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVBLZX AL, AX, BX"},
		{name: "immediate-source", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVBQZX $1, AX"},
		{name: "vector-source", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVBWZX X1, AX"},
		{name: "byte-source-for-word-class", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVWLZX AL, AX"},
		{name: "memory-destination", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVBLSX AL, (AX)"},
		{name: "byte-destination", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVWQZX AX, AL"},
		{name: "suffix", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", instruction: "MOVLQZX.Z AX, BX"},
		{name: "386-byte-to-qword-sign", goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "MOVBQSX AL, AX"},
		{name: "386-byte-to-qword-zero", goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "MOVBQZX AL, AX"},
		{name: "386-word-to-qword-sign", goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "MOVWQSX AX, BX"},
		{name: "386-word-to-qword-zero", goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "MOVWQZX AX, BX"},
		{name: "386-long-to-qword-sign", goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "MOVLQSX AX, BX"},
		{name: "386-r8-source", goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "MOVWLZX R8, AX"},
		{name: "386-r8-destination", goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "MOVBLZX AL, R8"},
		{name: "386-sp-byte-source", goarch: "386", triple: "i386-unknown-linux-gnu", instruction: "MOVBWZX SP, AX"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			src := "TEXT invalid_scalar_extension(SB),NOSPLIT,$0-0\n\t" + test.instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: test.triple,
				Goarch:       test.goarch,
				Sigs: map[string]FuncSig{
					"invalid_scalar_extension": {Name: "invalid_scalar_extension", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q for %s outside Go 1.27's ymb_rl/yml_rl tables", test.instruction, test.goarch)
			}
		})
	}
}

func TestTranslateX86MaskLogicalCompleteGo127Forms(t *testing.T) {
	var src strings.Builder
	src.WriteString("TEXT mask_logical_forms(SB),NOSPLIT,$0-0\n")
	for _, stem := range []string{"KAND", "KANDN", "KOR", "KXNOR", "KXOR"} {
		for _, width := range []string{"B", "W", "D", "Q"} {
			fmt.Fprintf(&src, "\t%s%s K1, K2, K3\n", stem, width)
		}
	}
	for _, stem := range []string{"KNOT", "KTEST", "KORTEST"} {
		for _, width := range []string{"B", "W", "D", "Q"} {
			fmt.Fprintf(&src, "\t%s%s K1, K2\n", stem, width)
		}
	}
	src.WriteString("\tRET\n")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"mask_logical_forms": {Name: "mask_logical_forms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "mask-logical-"+target.name+".ll", "mask-logical-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86MaskLogicalRejectsFormsOutsideGo127Tables(t *testing.T) {
	for _, instruction := range []string{
		"KXNORW K1, K2",
		"KXNORW K1, K2, K3, K4",
		"KANDW K1, K2, AX",
		"KANDNW K1, (AX), K3",
		"KORQ $1, K2, K3",
		"KXORB K1, K2, K8",
		"KNOTD K1",
		"KNOTQ K1, K2, K3",
		"KNOTW AX, K2",
		"KTESTB K1, (AX)",
		"KTESTW K1, K2, K3",
		"KORTESTD K1",
		"KORTESTQ.Z K1, K2",
		"KXORQ.Z K1, K2, K3",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalid_mask_logical(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				return
			}
			for _, target := range []struct {
				goarch string
				triple string
			}{
				{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
				{goarch: "386", triple: "i386-unknown-linux-gnu"},
			} {
				if _, err := Translate(file, Options{
					TargetTriple: target.triple,
					Goarch:       target.goarch,
					Sigs: map[string]FuncSig{
						"invalid_mask_logical": {Name: "invalid_mask_logical", Ret: Void},
					},
				}); err == nil {
					t.Fatalf("Translate accepted %q for %s outside Go 1.27's _ykaddb/_yknotb tables", instruction, target.goarch)
				}
			}
		})
	}
}

func TestTranslateX86MaskMoveCompleteGo127Forms(t *testing.T) {
	// Go 1.27 assigns KMOVB/W/D/Q the same _ykmovb table. Its four rows are:
	// K -> memory, K -> GP, K-or-memory -> K, and GP -> K. Ykm therefore also
	// includes the K -> K form. Exercise every row plus each Plan 9 memory
	// spelling accepted as Ym, on both x86 architectures and all CI object
	// formats.
	var src strings.Builder
	src.WriteString("TEXT mask_move_forms(SB),NOSPLIT,$0-16\n")
	for _, op := range []string{"KMOVB", "KMOVW", "KMOVD", "KMOVQ"} {
		fmt.Fprintf(&src, "\t%s K1, 16(BX)\n", op)
		fmt.Fprintf(&src, "\t%s K1, AX\n", op)
		fmt.Fprintf(&src, "\t%s K1, K2\n", op)
		fmt.Fprintf(&src, "\t%s K0, K7\n", op)
		fmt.Fprintf(&src, "\t%s 16(BX), K2\n", op)
		fmt.Fprintf(&src, "\t%s AX, K2\n", op)
		fmt.Fprintf(&src, "\t%s K5, SP\n", op)
		fmt.Fprintf(&src, "\t%s SP, K5\n", op)
		fmt.Fprintf(&src, "\t%s x+0(FP), K3\n", op)
		fmt.Fprintf(&src, "\t%s K3, ret+8(FP)\n", op)
		fmt.Fprintf(&src, "\t%s mask_move_source(SB), K4\n", op)
		fmt.Fprintf(&src, "\t%s K4, mask_move_destination(SB)\n", op)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			targetSource := src.String()
			if target.goarch == "amd64" {
				var highRegisters strings.Builder
				for _, op := range []string{"KMOVB", "KMOVW", "KMOVD", "KMOVQ"} {
					fmt.Fprintf(&highRegisters, "\t%s K6, R15\n", op)
					fmt.Fprintf(&highRegisters, "\t%s R15, K6\n", op)
				}
				targetSource += highRegisters.String()
			}
			targetSource += "\tRET\n"
			file, err := Parse(ArchAMD64, targetSource)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"mask_move_forms": {
						Name: "mask_move_forms", Args: []LLVMType{I64}, Ret: I64,
						Frame: FrameLayout{
							Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
							Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
						},
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "mask-move-"+target.name+".ll", "mask-move-"+target.name+".o", ll)
		})
	}
}

func TestTranslate386MaskMoveRejectsAMD64OnlyYrlRegisters(t *testing.T) {
	for _, instruction := range []string{"KMOVB K1, R8", "KMOVW R8, K1", "KMOVD K1, R15", "KMOVQ R15, K1"} {
		src := "TEXT invalid_mask_move_386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
		file, err := Parse(ArchAMD64, src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs: map[string]FuncSig{
				"invalid_mask_move_386": {Name: "invalid_mask_move_386", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q for 386 outside Go 1.27's Yrl class", instruction)
		}
	}
}

func TestTranslateX86MaskMoveRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"KMOVB K1",
		"KMOVW K1, K2, K3",
		"KMOVD $1, K1",
		"KMOVQ K1, $1",
		"KMOVB 8(AX), BX",
		"KMOVW AX, 8(BX)",
		"KMOVD AX, BX",
		"KMOVQ 8(AX), 16(BX)",
		"KMOVB X1, K2",
		"KMOVW K1, X2",
		"KMOVD K8, AX",
		"KMOVQ AX, K8",
		"KMOVQ.Z K1, K2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalid_mask_move(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				return
			}
			for _, target := range []struct {
				goarch string
				triple string
			}{
				{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
				{goarch: "386", triple: "i386-unknown-linux-gnu"},
			} {
				if _, err := Translate(file, Options{
					TargetTriple: target.triple,
					Goarch:       target.goarch,
					Sigs: map[string]FuncSig{
						"invalid_mask_move": {Name: "invalid_mask_move", Ret: Void},
					},
				}); err == nil {
					t.Fatalf("Translate accepted %q for %s outside Go 1.27's _ykmovb table", instruction, target.goarch)
				}
			}
		})
	}
}

func TestTranslateX86GatherCompleteGo127Forms(t *testing.T) {
	// Go 1.27 has eight data-gather instructions over three operand tables,
	// plus eight EVEX gather-prefetch instructions over two tables. Generate
	// every row of all five tables for each opcode. The 386 assembler accepts
	// EVEX gather with X/Y/Z0..7 VSIB indices; amd64 additionally accepts the
	// high EVEX register classes.
	dataGroups := []struct {
		ops   []string
		table string
	}{
		{ops: []string{"VGATHERDPS", "VGATHERQPD", "VPGATHERDD", "VPGATHERQQ"}, table: "dps"},
		{ops: []string{"VGATHERDPD", "VPGATHERDQ"}, table: "dpd"},
		{ops: []string{"VGATHERQPS", "VPGATHERQD"}, table: "qps"},
	}
	prefetchGroups := []struct {
		ops        []string
		indexWidth string
	}{
		{ops: []string{"VGATHERPF0DPD", "VGATHERPF1DPD"}, indexWidth: "Y"},
		{ops: []string{
			"VGATHERPF0DPS", "VGATHERPF0QPD", "VGATHERPF0QPS",
			"VGATHERPF1DPS", "VGATHERPF1QPD", "VGATHERPF1QPS",
		}, indexWidth: "Z"},
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var src strings.Builder
			src.WriteString("TEXT gather_forms(SB),NOSPLIT,$0-0\n")
			for _, group := range dataGroups {
				for _, op := range group.ops {
					switch group.table {
					case "dps":
						fmt.Fprintf(&src, "\t%s X1, (BX)(X2*1), X3\n", op)
						fmt.Fprintf(&src, "\t%s Y1, 4(BX)(Y2*2), Y3\n", op)
						fmt.Fprintf(&src, "\t%s 8(X2*4), K1, X3\n", op)
						fmt.Fprintf(&src, "\t%s 12(BX)(Y2*8), K1, Y3\n", op)
						fmt.Fprintf(&src, "\t%s 16(BX)(Z2*4), K1, Z3\n", op)
					case "dpd":
						fmt.Fprintf(&src, "\t%s X1, (BX)(X2*1), X3\n", op)
						fmt.Fprintf(&src, "\t%s Y1, 8(BX)(X2*2), Y3\n", op)
						fmt.Fprintf(&src, "\t%s 16(X2*4), K1, X3\n", op)
						fmt.Fprintf(&src, "\t%s 24(BX)(X2*8), K1, Y3\n", op)
						fmt.Fprintf(&src, "\t%s 32(BX)(Y2*4), K1, Z3\n", op)
					case "qps":
						fmt.Fprintf(&src, "\t%s X1, (BX)(X2*1), X3\n", op)
						fmt.Fprintf(&src, "\t%s X1, 4(BX)(Y2*2), X3\n", op)
						fmt.Fprintf(&src, "\t%s 8(X2*4), K1, X3\n", op)
						fmt.Fprintf(&src, "\t%s 12(BX)(Y2*8), K1, X3\n", op)
						fmt.Fprintf(&src, "\t%s 16(BX)(Z2*4), K1, Y3\n", op)
					}
					// Unlike VSIB indices, Go 1.27 permits high EVEX X/Y
					// destination registers even in 386 mode.
					switch group.table {
					case "dps":
						fmt.Fprintf(&src, "\t%s (BX)(X2*4), K2, X20\n", op)
						fmt.Fprintf(&src, "\t%s (BX)(Y2*4), K2, Y20\n", op)
					case "dpd":
						fmt.Fprintf(&src, "\t%s (BX)(X2*4), K2, X20\n", op)
						fmt.Fprintf(&src, "\t%s (BX)(X2*4), K2, Y20\n", op)
					case "qps":
						fmt.Fprintf(&src, "\t%s (BX)(X2*8), K2, X20\n", op)
						fmt.Fprintf(&src, "\t%s (BX)(Z2*8), K2, Y20\n", op)
					}
					if target.goarch == "amd64" {
						switch group.table {
						case "dps":
							fmt.Fprintf(&src, "\t%s (BX)(X20*4), K2, X21\n", op)
							fmt.Fprintf(&src, "\t%s (BX)(Y20*4), K2, Y21\n", op)
							fmt.Fprintf(&src, "\t%s (BX)(Z20*4), K2, Z21\n", op)
						case "dpd":
							fmt.Fprintf(&src, "\t%s (BX)(X20*4), K2, X21\n", op)
							fmt.Fprintf(&src, "\t%s (BX)(X20*4), K2, Y21\n", op)
							fmt.Fprintf(&src, "\t%s (BX)(Y20*4), K2, Z21\n", op)
						case "qps":
							fmt.Fprintf(&src, "\t%s (BX)(X20*8), K2, X21\n", op)
							fmt.Fprintf(&src, "\t%s (BX)(Y20*8), K2, X21\n", op)
							fmt.Fprintf(&src, "\t%s (BX)(Z20*8), K2, Y21\n", op)
						}
					}
				}
			}
			for _, group := range prefetchGroups {
				for _, op := range group.ops {
					fmt.Fprintf(&src, "\t%s K1, 40(BX)(%s2*4)\n", op, group.indexWidth)
					if target.goarch == "amd64" {
						fmt.Fprintf(&src, "\t%s K7, 48(%s20*8)\n", op, group.indexWidth)
					}
				}
			}
			src.WriteString("\tRET\n")

			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"gather_forms": {Name: "gather_forms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "gather-"+target.name+".ll", "gather-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86GatherRejectsFormsOutsideGo127Tables(t *testing.T) {
	tests := []struct {
		name        string
		instruction string
	}{
		{name: "missing-mask", instruction: "VPGATHERDD (AX)(X2*4), X3"},
		{name: "too-many", instruction: "VGATHERDPS (AX)(X2*4), K1, K2, X3"},
		{name: "plain-memory", instruction: "VPGATHERDD (AX), K1, X3"},
		{name: "gp-index", instruction: "VPGATHERDD (AX)(CX*4), K1, X3"},
		{name: "bad-scale", instruction: "VPGATHERDD (AX)(X2*3), K1, X3"},
		{name: "k0-mask", instruction: "VPGATHERDD (AX)(X2*4), K0, X3"},
		{name: "vector-mask-in-evex", instruction: "VPGATHERDD (AX)(X2*4), X1, X3"},
		{name: "k-mask-in-vex", instruction: "VPGATHERDD K1, (AX)(X2*4), X3"},
		{name: "dps-wrong-index", instruction: "VPGATHERDD (AX)(Y2*4), K1, X3"},
		{name: "dps-wrong-destination", instruction: "VPGATHERDD (AX)(X2*4), K1, Y3"},
		{name: "dpd-wrong-index", instruction: "VPGATHERDQ (AX)(Y2*4), K1, Y3"},
		{name: "dpd-wrong-destination", instruction: "VPGATHERDQ (AX)(Y2*4), K1, X3"},
		{name: "qps-wrong-index", instruction: "VPGATHERQD (AX)(Y2*8), K1, Y3"},
		{name: "qps-wrong-destination", instruction: "VPGATHERQD (AX)(Z2*8), K1, Z3"},
		{name: "vex-mask-index-alias", instruction: "VPGATHERDD X2, (AX)(X2*4), X3"},
		{name: "vex-mask-dest-alias", instruction: "VPGATHERDD X3, (AX)(X2*4), X3"},
		{name: "vex-index-dest-alias", instruction: "VPGATHERDD X1, (AX)(X3*4), X3"},
		{name: "evex-index-dest-alias", instruction: "VPGATHERDD (AX)(X3*4), K1, X3"},
		{name: "zero-suffix", instruction: "VPGATHERDD.Z (AX)(X2*4), K1, X3"},
		{name: "broadcast-suffix", instruction: "VPGATHERQQ.BCST (AX)(X2*8), K1, X3"},
		{name: "prefetch-k0", instruction: "VGATHERPF0DPD K0, (AX)(Y2*8)"},
		{name: "prefetch-wrong-index", instruction: "VGATHERPF0DPD K1, (AX)(Z2*8)"},
		{name: "prefetch-extra-dest", instruction: "VGATHERPF1DPS K1, (AX)(Z2*4), Z3"},
		{name: "prefetch-suffix", instruction: "VGATHERPF1QPS.Z K1, (AX)(Z2*8)"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			src := "TEXT invalid_gather(SB),NOSPLIT,$0-0\n\t" + test.instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				return
			}
			for _, target := range []struct {
				goarch string
				triple string
			}{
				{goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
				{goarch: "386", triple: "i386-unknown-linux-gnu"},
			} {
				if _, err := Translate(file, Options{
					TargetTriple: target.triple,
					Goarch:       target.goarch,
					Sigs: map[string]FuncSig{
						"invalid_gather": {Name: "invalid_gather", Ret: Void},
					},
				}); err == nil {
					t.Fatalf("Translate accepted %q for %s outside Go 1.27's gather tables", test.instruction, target.goarch)
				}
			}
		})
	}
}

func TestTranslate386GatherRejectsHighVSIBAndZRegisters(t *testing.T) {
	for _, instruction := range []string{
		"VPGATHERDD (AX)(X8*4), K1, X3",
		"VPGATHERDQ (AX)(Y8*4), K1, Z3",
		"VPGATHERQD (AX)(Z8*8), K1, Y3",
		"VPGATHERDD (AX)(Z2*4), K1, Z8",
		"VGATHERPF0DPD K1, (AX)(Y8*8)",
		"VGATHERPF1DPS K1, (AX)(Z8*4)",
	} {
		src := "TEXT invalid_gather_386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
		file, err := Parse(ArchAMD64, src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs: map[string]FuncSig{
				"invalid_gather_386": {Name: "invalid_gather_386", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's 386 VSIB/register classes", instruction)
		}
	}
}

func TestTranslateAMD64TernaryLogicCompleteGo127Forms(t *testing.T) {
	// VPTERNLOGD/Q share Go 1.27's six-row _yvalignd table: X/Y/Z,
	// each with an unmasked and K1-K7 masked row. Their EVEX encodings add
	// scalar D/Q broadcast and zeroing. Exercise every row/suffix combination,
	// high EVEX registers, and every value in the unsigned-imm8 truth table.
	var src strings.Builder
	src.WriteString("TEXT ternary_logic_forms(SB),NOSPLIT,$0-0\n")
	for _, op := range []string{"VPTERNLOGD", "VPTERNLOGQ"} {
		for _, width := range []string{"X", "Y", "Z"} {
			fmt.Fprintf(&src, "\t%s $0, %s0, %s1, %s2\n", op, width, width, width)
			fmt.Fprintf(&src, "\t%s $255, 8(BX), %s3, %s4\n", op, width, width)
			fmt.Fprintf(&src, "\t%s $0xd8, %s5, %s6, K1, %s7\n", op, width, width, width)
			fmt.Fprintf(&src, "\t%s.Z $0xaa, 16(BX), %s8, K2, %s9\n", op, width, width)
			fmt.Fprintf(&src, "\t%s.BCST $0xcc, 24(BX), %s10, %s11\n", op, width, width)
			fmt.Fprintf(&src, "\t%s.BCST.Z $0xf0, 32(BX), %s12, K3, %s13\n", op, width, width)
		}
		fmt.Fprintf(&src, "\t%s $0x96, X29, X30, X31\n", op)
		fmt.Fprintf(&src, "\t%s $0x96, Y29, Y30, Y31\n", op)
		fmt.Fprintf(&src, "\t%s $0x96, Z29, Z30, Z31\n", op)
	}
	for immediate := 0; immediate <= 255; immediate++ {
		fmt.Fprintf(&src, "\tVPTERNLOGD $%d, X0, X1, X2\n", immediate)
		fmt.Fprintf(&src, "\tVPTERNLOGQ $%d, X3, X4, X5\n", immediate)
	}
	src.WriteString("\tRET\n")

	file, err := Parse(ArchAMD64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "darwin-amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", triple: "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"ternary_logic_forms": {Name: "ternary_logic_forms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "ternary-logic-"+target.name+".ll", "ternary-logic-"+target.name+".o", ll)
		})
	}
}

func TestAMD64TernaryLogicTruthTableOrderingExhaustive(t *testing.T) {
	for immediate := 0; immediate <= 255; immediate++ {
		for truthIndex := 0; truthIndex < 8; truthIndex++ {
			a := truthIndex&4 != 0
			b := truthIndex&2 != 0
			third := truthIndex&1 != 0
			want := immediate&(1<<truthIndex) != 0
			if got := amd64TernaryLogicBit(uint8(immediate), a, b, third); got != want {
				t.Fatalf("imm=%#02x A=%v B=%v C=%v: got %v, want %v", immediate, a, b, third, got, want)
			}
		}
	}

	c, _ := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.ternaryLogic", Ret: Void}, nil)
	for _, test := range []struct {
		name      string
		immediate uint8
		want      string
	}{
		{name: "A", immediate: 0xf0, want: "%old_destination"},
		{name: "B", immediate: 0xcc, want: "%vvvv_source"},
		{name: "C", immediate: 0xaa, want: "%rm_source"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := c.emitTernaryLogicBytes(16, test.immediate, "%old_destination", "%vvvv_source", "%rm_source")
			if got != test.want {
				t.Fatalf("truth-table selector %#02x = %q, want %q", test.immediate, got, test.want)
			}
		})
	}
}

func TestTranslateAMD64TernaryLogicRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"VPTERNLOGD X0, X1, X2",
		"VPTERNLOGD $0, X0, X1",
		"VPTERNLOGQ $0, X0, X1, X2, X3, X4",
		"VPTERNLOGD $-1, X0, X1, X2",
		"VPTERNLOGQ $256, X0, X1, X2",
		"VPTERNLOGD AX, X0, X1, X2",
		"VPTERNLOGD $0, Y0, X1, X2",
		"VPTERNLOGQ $0, X0, Y1, X2",
		"VPTERNLOGD $0, X0, X1, Y2",
		"VPTERNLOGQ $0, X0, 8(BX), X2",
		"VPTERNLOGD $0, X0, X1, 8(BX)",
		"VPTERNLOGD $0, X0, X1, K0, X2",
		"VPTERNLOGQ $0, X0, X1, K8, X2",
		"VPTERNLOGD.Z $0, X0, X1, X2",
		"VPTERNLOGQ.BCST $0, X0, X1, X2",
		"VPTERNLOGD.BCST.Z $0, 8(BX), X1, X2",
		"VPTERNLOGQ.Z.BCST $0, 8(BX), X1, K1, X2",
		"VPTERNLOGD.SAE $0, X0, X1, X2",
		"VPTERNLOGQ.BCST.BCST $0, 8(BX), X1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalid_ternary_logic(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalid_ternary_logic": {Name: "invalid_ternary_logic", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's _yvalignd table", instruction)
			}
		})
	}
}

func TestTranslate386TernaryLogicMatchesGoAssemblerOperandLimit(t *testing.T) {
	// Go 1.27's 386 assembler frontend rejects the four/five-operand source
	// syntax before optab matching, so this is an asserted compatibility rule,
	// not an unsupported-form skip. Check both 386 CI object formats.
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			for _, instruction := range []string{
				"VPTERNLOGD $0, X0, X1, X2",
				"VPTERNLOGQ $255, 8(BX), Y1, Y2",
				"VPTERNLOGD.Z $0xd8, Z0, Z1, K1, Z2",
				"VPTERNLOGQ.BCST.Z $0x96, 16(BX), X1, K7, X2",
			} {
				src := "TEXT invalid_ternary_logic_386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
				file, err := Parse(ArchAMD64, src)
				if err != nil {
					continue
				}
				if _, err := Translate(file, Options{
					TargetTriple: triple,
					Goarch:       "386",
					Sigs: map[string]FuncSig{
						"invalid_ternary_logic_386": {Name: "invalid_ternary_logic_386", Ret: Void},
					},
				}); err == nil {
					t.Fatalf("Translate accepted %q although Go 1.27's 386 assembler rejects its operand count", instruction)
				}
			}
		})
	}
}

func TestTranslateX86PackedRotateCompleteGo127Forms(t *testing.T) {
	immediateOps := []string{"VPROLD", "VPROLQ", "VPRORD", "VPRORQ"}
	variableOps := []string{"VPROLVD", "VPROLVQ", "VPRORVD", "VPRORVQ"}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var src strings.Builder
			src.WriteString("TEXT packed_rotate_forms(SB),NOSPLIT,$0-0\n")
			for _, op := range immediateOps {
				for _, width := range []string{"X", "Y", "Z"} {
					fmt.Fprintf(&src, "\t%s $0, %s0, %s1\n", op, width, width)
					fmt.Fprintf(&src, "\t%s $255, 8(BX), %s2\n", op, width)
					fmt.Fprintf(&src, "\t%s.BCST $31, 16(BX), %s3\n", op, width)
					if target.goarch == "amd64" {
						fmt.Fprintf(&src, "\t%s $7, %s4, K1, %s5\n", op, width, width)
						fmt.Fprintf(&src, "\t%s.Z $11, 24(BX), K2, %s6\n", op, width)
						fmt.Fprintf(&src, "\t%s.BCST.Z $13, 32(BX), K3, %s7\n", op, width)
					}
				}
				fmt.Fprintf(&src, "\t%s $17, X30, X31\n", op)
				fmt.Fprintf(&src, "\t%s $19, Y30, Y31\n", op)
				if target.goarch == "amd64" {
					fmt.Fprintf(&src, "\t%s $23, Z30, Z31\n", op)
				} else {
					fmt.Fprintf(&src, "\t%s $23, Z6, Z7\n", op)
				}
			}
			for _, op := range variableOps {
				for _, width := range []string{"X", "Y", "Z"} {
					fmt.Fprintf(&src, "\t%s %s0, %s1, %s2\n", op, width, width, width)
					fmt.Fprintf(&src, "\t%s 8(BX), %s3, %s4\n", op, width, width)
					fmt.Fprintf(&src, "\t%s.BCST 16(BX), %s5, %s6\n", op, width, width)
					if target.goarch == "amd64" {
						fmt.Fprintf(&src, "\t%s %s7, %s8, K1, %s9\n", op, width, width, width)
						fmt.Fprintf(&src, "\t%s.Z 24(BX), %s10, K2, %s11\n", op, width, width)
						fmt.Fprintf(&src, "\t%s.BCST.Z 32(BX), %s12, K3, %s13\n", op, width, width)
					}
				}
				fmt.Fprintf(&src, "\t%s X29, X30, X31\n", op)
				fmt.Fprintf(&src, "\t%s Y29, Y30, Y31\n", op)
				if target.goarch == "amd64" {
					fmt.Fprintf(&src, "\t%s Z29, Z30, Z31\n", op)
				} else {
					fmt.Fprintf(&src, "\t%s Z5, Z6, Z7\n", op)
				}
			}
			for immediate := 0; immediate <= 255; immediate++ {
				fmt.Fprintf(&src, "\tVPROLD $%d, X0, X1\n", immediate)
				fmt.Fprintf(&src, "\tVPRORQ $%d, X2, X3\n", immediate)
			}
			src.WriteString("\tRET\n")

			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"packed_rotate_forms": {Name: "packed_rotate_forms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "packed-rotate-"+target.name+".ll", "packed-rotate-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedRotateRejectsFormsOutsideGo127Tables(t *testing.T) {
	for _, instruction := range []string{
		"VPROLD X0, X1",
		"VPROLQ $0, X0",
		"VPRORD $0, X0, X1, X2, X3",
		"VPRORQ $-1, X0, X1",
		"VPROLD $256, X0, X1",
		"VPROLVD X0, X1",
		"VPRORVQ X0, X1, X2, X3, X4",
		"VPROLD $7, Y0, X1",
		"VPRORQ $7, X0, Y1",
		"VPROLVD X0, Y1, Y2",
		"VPRORVQ Y0, Y1, X2",
		"VPROLD $7, X0, K0, X1",
		"VPROLVD X0, X1, K0, X2",
		"VPRORD.Z $7, X0, X1",
		"VPRORVD.Z X0, X1, X2",
		"VPROLQ.BCST $7, X0, X1",
		"VPROLVQ.BCST X0, X1, X2",
		"VPRORD.BCST.Z $7, 8(BX), X1",
		"VPRORVD.BCST.Z 8(BX), X1, X2",
		"VPROLD.Z.BCST $7, 8(BX), K1, X1",
		"VPROLVD.SAE X0, X1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalid_packed_rotate(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalid_packed_rotate": {Name: "invalid_packed_rotate", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's _yvprold/_yvblendmpd tables", instruction)
			}
		})
	}
}

func TestTranslate386PackedRotateRejectsMaskedAndHighZForms(t *testing.T) {
	for _, instruction := range []string{
		"VPROLD $7, X0, K1, X1",
		"VPRORQ.Z $7, Y0, K7, Y1",
		"VPROLVD X0, X1, K1, X2",
		"VPRORVQ.BCST.Z 8(BX), Y1, K1, Y2",
		"VPROLD $7, Z7, Z8",
		"VPRORD $7, Z8, Z7",
		"VPROLVD Z6, Z7, Z8",
		"VPRORVQ Z8, Z7, Z6",
	} {
		for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
			src := "TEXT invalid_packed_rotate_386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				continue
			}
			if _, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"invalid_packed_rotate_386": {Name: "invalid_packed_rotate_386", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q for %s outside Go 1.27's 386 source forms", instruction, triple)
			}
		}
	}
}

func TestTranslateX86EVEXPackedLogicalCompleteGo127Forms(t *testing.T) {
	ops := []string{"VPANDD", "VPANDQ", "VPANDND", "VPANDNQ", "VPORD", "VPORQ", "VPXORD", "VPXORQ"}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var src strings.Builder
			src.WriteString("TEXT evex_packed_logical_forms(SB),NOSPLIT,$0-0\n")
			for _, op := range ops {
				for _, width := range []string{"X", "Y", "Z"} {
					fmt.Fprintf(&src, "\t%s %s0, %s1, %s2\n", op, width, width, width)
					fmt.Fprintf(&src, "\t%s 8(BX), %s3, %s4\n", op, width, width)
					fmt.Fprintf(&src, "\t%s.BCST 16(BX), %s5, %s6\n", op, width, width)
					if target.goarch == "amd64" {
						fmt.Fprintf(&src, "\t%s %s7, %s8, K1, %s9\n", op, width, width, width)
						fmt.Fprintf(&src, "\t%s.Z 24(BX), %s10, K2, %s11\n", op, width, width)
						fmt.Fprintf(&src, "\t%s.BCST.Z 32(BX), %s12, K3, %s13\n", op, width, width)
					}
				}
				fmt.Fprintf(&src, "\t%s X29, X30, X31\n", op)
				fmt.Fprintf(&src, "\t%s Y29, Y30, Y31\n", op)
				if target.goarch == "amd64" {
					fmt.Fprintf(&src, "\t%s Z29, Z30, Z31\n", op)
				} else {
					fmt.Fprintf(&src, "\t%s Z5, Z6, Z7\n", op)
				}
			}
			src.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, strings.Replace(src.String(), ",NOSPLIT", "", 1), true)
			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"evex_packed_logical_forms": {Name: "evex_packed_logical_forms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "evex-packed-logical-"+target.name+".ll", "evex-packed-logical-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86EVEXPackedLogicalRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"VPXORD X0, X1",
		"VPORQ X0, X1, X2, X3, X4",
		"VPANDD $1, X1, X2",
		"VPANDNQ X0, Y1, Y2",
		"VPORD Y0, Y1, X2",
		"VPXORQ X0, 8(BX), X2",
		"VPANDD X0, X1, 8(BX)",
		"VPANDNQ X0, X1, K0, X2",
		"VPORD.Z X0, X1, X2",
		"VPXORD.BCST X0, X1, X2",
		"VPANDQ.BCST.Z 8(BX), X1, X2",
		"VPORQ.Z.BCST 8(BX), X1, K1, X2",
		"VPXORD.SAE X0, X1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalid_evex_packed_logical(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalid_evex_packed_logical": {Name: "invalid_evex_packed_logical", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's _yvblendmpd table", instruction)
			}
		})
	}
}

func TestTranslate386EVEXPackedLogicalRejectsMaskedAndHighZForms(t *testing.T) {
	for _, op := range []string{"VPANDD", "VPANDQ", "VPANDND", "VPANDNQ", "VPORD", "VPORQ", "VPXORD", "VPXORQ"} {
		for _, operands := range []string{
			"X0, X1, K1, X2",
			"Z6, Z7, Z8",
			"Z8, Z7, Z6",
		} {
			instruction := op + " " + operands
			src := "TEXT invalid_evex_packed_logical_386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, "386", strings.Replace(src, ",NOSPLIT", "", 1), false)
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				continue
			}
			if _, err := Translate(file, Options{
				TargetTriple: "i386-unknown-linux-gnu",
				Goarch:       "386",
				Sigs: map[string]FuncSig{
					"invalid_evex_packed_logical_386": {Name: "invalid_evex_packed_logical_386", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's 386 operand/register limits", instruction)
			}
		}
	}
}

func TestTranslateX86PackedFloatingLogicalCompleteGo127Forms(t *testing.T) {
	legacyOps := []string{"ANDPS", "ANDPD", "ANDNPS", "ANDNPD", "ORPS", "ORPD", "XORPS", "XORPD"}
	vectorOps := []string{"VANDPS", "VANDPD", "VANDNPS", "VANDNPD", "VORPS", "VORPD", "VXORPS", "VXORPD"}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var src strings.Builder
			src.WriteString("TEXT packed_floating_logical_forms(SB),NOSPLIT,$0-0\n")
			for _, op := range legacyOps {
				fmt.Fprintf(&src, "\t%s X0, X1\n", op)
				fmt.Fprintf(&src, "\t%s 8(BX), X2\n", op)
				if target.goarch == "amd64" {
					fmt.Fprintf(&src, "\t%s X14, X15\n", op)
				} else {
					fmt.Fprintf(&src, "\t%s X6, X7\n", op)
				}
			}
			for _, op := range vectorOps {
				for _, width := range []string{"X", "Y", "Z"} {
					fmt.Fprintf(&src, "\t%s %s0, %s1, %s2\n", op, width, width, width)
					fmt.Fprintf(&src, "\t%s 8(BX), %s3, %s4\n", op, width, width)
					fmt.Fprintf(&src, "\t%s.BCST 16(BX), %s5, %s6\n", op, width, width)
					if target.goarch == "amd64" {
						fmt.Fprintf(&src, "\t%s %s7, %s8, K1, %s9\n", op, width, width, width)
						fmt.Fprintf(&src, "\t%s.Z 24(BX), %s10, K2, %s11\n", op, width, width)
						fmt.Fprintf(&src, "\t%s.BCST.Z 32(BX), %s12, K3, %s13\n", op, width, width)
					}
				}
				fmt.Fprintf(&src, "\t%s X29, X30, X31\n", op)
				fmt.Fprintf(&src, "\t%s Y29, Y30, Y31\n", op)
				if target.goarch == "amd64" {
					fmt.Fprintf(&src, "\t%s Z29, Z30, Z31\n", op)
				} else {
					fmt.Fprintf(&src, "\t%s Z5, Z6, Z7\n", op)
				}
			}
			src.WriteString("\tRET\n")

			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"packed_floating_logical_forms": {Name: "packed_floating_logical_forms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "packed-floating-logical-"+target.name+".ll", "packed-floating-logical-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedFloatingLogicalRejectsFormsOutsideGo127Tables(t *testing.T) {
	for _, instruction := range []string{
		"ANDPS X0",
		"ORPD X0, X1, X2",
		"ANDNPS Y0, X1",
		"XORPD X0, Y1",
		"ORPS.Z X0, X1",
		"VXORPS X0, X1",
		"VANDPD X0, X1, X2, X3, X4",
		"VANDNPS X0, Y1, Y2",
		"VORPD Y0, Y1, X2",
		"VXORPS X0, 8(BX), X2",
		"VANDPD X0, X1, K0, X2",
		"VANDNPS.Z X0, X1, X2",
		"VORPD.BCST X0, X1, X2",
		"VXORPS.BCST.Z 8(BX), X1, X2",
		"VANDPD.Z.BCST 8(BX), X1, K1, X2",
		"VORPS.SAE X0, X1, X2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT invalid_packed_floating_logical(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs: map[string]FuncSig{
					"invalid_packed_floating_logical": {Name: "invalid_packed_floating_logical", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's yxm/_yvandnpd tables", instruction)
			}
		})
	}
}

func TestTranslate386PackedFloatingLogicalRejectsArchitectureRestrictedForms(t *testing.T) {
	for _, instruction := range []string{
		"ANDPS X8, X7",
		"XORPD X7, X8",
		"VANDPS X0, X1, K1, X2",
		"VXORPD.BCST.Z 8(BX), Y1, K1, Y2",
		"VORPS Z6, Z7, Z8",
		"VANDNPD Z8, Z7, Z6",
	} {
		src := "TEXT invalid_packed_floating_logical_386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
		file, err := Parse(ArchAMD64, src)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs: map[string]FuncSig{
				"invalid_packed_floating_logical_386": {Name: "invalid_packed_floating_logical_386", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's 386 register/operand limits", instruction)
		}
	}
}

func go127FMA3PackedOps() []string {
	var ops []string
	for _, family := range []string{"VFMADD", "VFMSUB", "VFNMADD", "VFNMSUB", "VFMADDSUB", "VFMSUBADD"} {
		for _, order := range []string{"132", "213", "231"} {
			for _, element := range []string{"PS", "PD"} {
				ops = append(ops, family+order+element)
			}
		}
	}
	return ops
}

func go127FMA3ScalarOps() []string {
	var ops []string
	for _, family := range []string{"VFMADD", "VFMSUB", "VFNMADD", "VFNMSUB"} {
		for _, order := range []string{"132", "213", "231"} {
			for _, element := range []string{"SS", "SD"} {
				ops = append(ops, family+order+element)
			}
		}
	}
	return ops
}

func TestTranslateX86FMA3CompleteGo127Forms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var src strings.Builder
			src.WriteString("TEXT fma3_complete_forms(SB),NOSPLIT,$0-0\n")
			for _, op := range go127FMA3PackedOps() {
				for _, width := range []string{"X", "Y", "Z"} {
					fmt.Fprintf(&src, "\t%s %s0, %s1, %s2\n", op, width, width, width)
					fmt.Fprintf(&src, "\t%s 8(BX), %s3, %s4\n", op, width, width)
					fmt.Fprintf(&src, "\t%s.BCST 16(BX), %s5, %s6\n", op, width, width)
					if target.goarch == "amd64" {
						fmt.Fprintf(&src, "\t%s %s7, %s8, K1, %s9\n", op, width, width, width)
						fmt.Fprintf(&src, "\t%s.Z 24(BX), %s10, K2, %s11\n", op, width, width)
						fmt.Fprintf(&src, "\t%s.BCST.Z 32(BX), %s12, K3, %s13\n", op, width, width)
					}
				}
				fmt.Fprintf(&src, "\t%s X29, X30, X31\n", op)
				fmt.Fprintf(&src, "\t%s Y29, Y30, Y31\n", op)
				if target.goarch == "amd64" {
					fmt.Fprintf(&src, "\t%s Z29, Z30, Z31\n", op)
				} else {
					fmt.Fprintf(&src, "\t%s Z5, Z6, Z7\n", op)
				}
				for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
					fmt.Fprintf(&src, "\t%s.%s Z0, Z1, Z2\n", op, rounding)
					if target.goarch == "amd64" {
						fmt.Fprintf(&src, "\t%s.%s Z3, Z4, K4, Z5\n", op, rounding)
						fmt.Fprintf(&src, "\t%s.%s.Z Z6, Z7, K5, Z8\n", op, rounding)
					}
				}
			}
			for _, op := range go127FMA3ScalarOps() {
				fmt.Fprintf(&src, "\t%s X0, X1, X2\n", op)
				fmt.Fprintf(&src, "\t%s 8(BX), X3, X4\n", op)
				fmt.Fprintf(&src, "\t%s X29, X30, X31\n", op)
				if target.goarch == "amd64" {
					fmt.Fprintf(&src, "\t%s X5, X6, K1, X7\n", op)
					fmt.Fprintf(&src, "\t%s.Z 16(BX), X8, K2, X9\n", op)
				}
				for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
					fmt.Fprintf(&src, "\t%s.%s X10, X11, X12\n", op, rounding)
					if target.goarch == "amd64" {
						fmt.Fprintf(&src, "\t%s.%s X13, X14, K3, X15\n", op, rounding)
						fmt.Fprintf(&src, "\t%s.%s.Z X16, X17, K4, X18\n", op, rounding)
					}
				}
			}
			src.WriteString("\tRET\n")

			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"fma3_complete_forms": {Name: "fma3_complete_forms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "fma3-complete-"+target.name+".ll", "fma3-complete-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86FMA3RejectsFormsOutsideGo127Tables(t *testing.T) {
	reject := func(t *testing.T, instruction string) {
		t.Helper()
		src := "TEXT invalid_fma3(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
		file, err := Parse(ArchAMD64, src)
		if err != nil {
			return
		}
		if _, err := Translate(file, Options{
			TargetTriple: "x86_64-unknown-linux-gnu",
			Goarch:       "amd64",
			Sigs: map[string]FuncSig{
				"invalid_fma3": {Name: "invalid_fma3", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's _yvaddpd/_yvaddsd tables", instruction)
		}
	}
	for _, op := range go127FMA3PackedOps() {
		for _, operands := range []string{
			"X0, X1",
			"X0, X1, X2, X3, X4",
			"X0, Y1, Y2",
			"X0, 8(BX), X2",
			"X0, X1, K0, X2",
			"X0, X1, AX",
			".Z X0, X1, X2",
			".BCST X0, X1, X2",
			".BCST.Z 8(BX), X1, X2",
			".RN_SAE X0, X1, X2",
			".RN_SAE 8(BX), Z1, Z2",
			".SAE Z0, Z1, Z2",
			".Z.BCST 8(BX), X1, K1, X2",
			".BCST.RN_SAE 8(BX), Z1, Z2",
		} {
			instruction := op + " " + operands
			if strings.HasPrefix(operands, ".") {
				parts := strings.SplitN(operands, " ", 2)
				instruction = op + parts[0] + " " + parts[1]
			}
			t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
				reject(t, instruction)
			})
		}
	}
	for _, op := range go127FMA3ScalarOps() {
		for _, operands := range []string{
			"X0, X1",
			"X0, X1, X2, X3, X4",
			"Y0, X1, X2",
			"X0, 8(BX), X2",
			"X0, X1, K0, X2",
			".Z X0, X1, X2",
			".BCST 8(BX), X1, X2",
			".RN_SAE 8(BX), X1, X2",
			".SAE X0, X1, X2",
			".RN_SAE.BCST 8(BX), X1, X2",
		} {
			instruction := op + " " + operands
			if strings.HasPrefix(operands, ".") {
				parts := strings.SplitN(operands, " ", 2)
				instruction = op + parts[0] + " " + parts[1]
			}
			t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
				reject(t, instruction)
			})
		}
	}
}

func TestTranslate386FMA3RejectsArchitectureRestrictedForms(t *testing.T) {
	var instructions []string
	for _, op := range go127FMA3PackedOps() {
		instructions = append(instructions,
			op+" X0, X1, K1, X2",
			op+" Z6, Z7, Z8",
			op+" Z8, Z7, Z6",
		)
	}
	for _, op := range go127FMA3ScalarOps() {
		instructions = append(instructions, op+" X0, X1, K1, X2")
	}
	for _, instruction := range instructions {
		src := "TEXT invalid_fma3_386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
		file, err := Parse(ArchAMD64, src)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs: map[string]FuncSig{
				"invalid_fma3_386": {Name: "invalid_fma3_386", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's 386 register/operand limits", instruction)
		}
	}
}

func go127BinaryFloatingOps(scalar bool) []string {
	var ops []string
	for _, family := range []string{"VADD", "VSUB", "VMUL", "VDIV", "VMAX", "VMIN"} {
		elements := []string{"PS", "PD"}
		if scalar {
			elements = []string{"SS", "SD"}
		}
		for _, element := range elements {
			ops = append(ops, family+element)
		}
	}
	return ops
}

func go127BinaryFloatingUsesSAE(op string) bool {
	return strings.HasPrefix(op, "VMAX") || strings.HasPrefix(op, "VMIN")
}

func TestTranslateX86BinaryFloatingCompleteGo127Forms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var src strings.Builder
			src.WriteString("TEXT binary_floating_complete_forms(SB),NOSPLIT,$0-0\n")
			for _, op := range go127BinaryFloatingOps(false) {
				for _, width := range []string{"X", "Y", "Z"} {
					fmt.Fprintf(&src, "\t%s %s0, %s1, %s2\n", op, width, width, width)
					fmt.Fprintf(&src, "\t%s 8(BX), %s3, %s4\n", op, width, width)
					fmt.Fprintf(&src, "\t%s.BCST 16(BX), %s5, %s6\n", op, width, width)
					if target.goarch == "amd64" {
						fmt.Fprintf(&src, "\t%s %s7, %s8, K1, %s9\n", op, width, width, width)
						fmt.Fprintf(&src, "\t%s.Z 24(BX), %s10, K2, %s11\n", op, width, width)
						fmt.Fprintf(&src, "\t%s.BCST.Z 32(BX), %s12, K3, %s13\n", op, width, width)
					}
				}
				fmt.Fprintf(&src, "\t%s X29, X30, X31\n", op)
				fmt.Fprintf(&src, "\t%s Y29, Y30, Y31\n", op)
				if target.goarch == "amd64" {
					fmt.Fprintf(&src, "\t%s Z29, Z30, Z31\n", op)
				} else {
					fmt.Fprintf(&src, "\t%s Z5, Z6, Z7\n", op)
				}
				if go127BinaryFloatingUsesSAE(op) {
					fmt.Fprintf(&src, "\t%s.SAE Z0, Z1, Z2\n", op)
					if target.goarch == "amd64" {
						fmt.Fprintf(&src, "\t%s.SAE.Z Z3, Z4, K4, Z5\n", op)
					}
				} else {
					for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
						fmt.Fprintf(&src, "\t%s.%s Z0, Z1, Z2\n", op, rounding)
						if target.goarch == "amd64" {
							fmt.Fprintf(&src, "\t%s.%s.Z Z3, Z4, K4, Z5\n", op, rounding)
						}
					}
				}
			}
			for _, op := range go127BinaryFloatingOps(true) {
				fmt.Fprintf(&src, "\t%s X0, X1, X2\n", op)
				fmt.Fprintf(&src, "\t%s 8(BX), X3, X4\n", op)
				fmt.Fprintf(&src, "\t%s X29, X30, X31\n", op)
				if target.goarch == "amd64" {
					fmt.Fprintf(&src, "\t%s X5, X6, K1, X7\n", op)
					fmt.Fprintf(&src, "\t%s.Z 16(BX), X8, K2, X9\n", op)
				}
				if go127BinaryFloatingUsesSAE(op) {
					fmt.Fprintf(&src, "\t%s.SAE X10, X11, X12\n", op)
					if target.goarch == "amd64" {
						fmt.Fprintf(&src, "\t%s.SAE.Z X13, X14, K3, X15\n", op)
					}
				} else {
					for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
						fmt.Fprintf(&src, "\t%s.%s X10, X11, X12\n", op, rounding)
						if target.goarch == "amd64" {
							fmt.Fprintf(&src, "\t%s.%s.Z X13, X14, K3, X15\n", op, rounding)
						}
					}
				}
			}
			src.WriteString("\tRET\n")

			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"binary_floating_complete_forms": {Name: "binary_floating_complete_forms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "binary-floating-complete-"+target.name+".ll", "binary-floating-complete-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86BinaryFloatingRejectsFormsOutsideGo127Tables(t *testing.T) {
	reject := func(t *testing.T, instruction string) {
		t.Helper()
		src := "TEXT invalid_binary_floating(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
		file, err := Parse(ArchAMD64, src)
		if err != nil {
			return
		}
		if _, err := Translate(file, Options{
			TargetTriple: "x86_64-unknown-linux-gnu",
			Goarch:       "amd64",
			Sigs: map[string]FuncSig{
				"invalid_binary_floating": {Name: "invalid_binary_floating", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's _yvaddpd/_yvaddsd tables", instruction)
		}
	}
	for _, op := range go127BinaryFloatingOps(false) {
		forms := []string{
			"X0, X1",
			"X0, X1, X2, X3, X4",
			"X0, Y1, Y2",
			"X0, 8(BX), X2",
			"X0, X1, K0, X2",
			"X0, X1, AX",
			".Z X0, X1, X2",
			".BCST X0, X1, X2",
			".BCST.Z 8(BX), X1, X2",
			".Z.BCST 8(BX), X1, K1, X2",
		}
		if go127BinaryFloatingUsesSAE(op) {
			forms = append(forms,
				".RN_SAE Z0, Z1, Z2",
				".SAE X0, X1, X2",
				".SAE 8(BX), Z1, Z2",
				".BCST.SAE 8(BX), Z1, Z2",
			)
		} else {
			forms = append(forms,
				".SAE Z0, Z1, Z2",
				".RN_SAE X0, X1, X2",
				".RN_SAE 8(BX), Z1, Z2",
				".BCST.RN_SAE 8(BX), Z1, Z2",
			)
		}
		for _, operands := range forms {
			instruction := op + " " + operands
			if strings.HasPrefix(operands, ".") {
				parts := strings.SplitN(operands, " ", 2)
				instruction = op + parts[0] + " " + parts[1]
			}
			t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
				reject(t, instruction)
			})
		}
	}
	for _, op := range go127BinaryFloatingOps(true) {
		forms := []string{
			"X0, X1",
			"X0, X1, X2, X3, X4",
			"Y0, X1, X2",
			"X0, 8(BX), X2",
			"X0, X1, K0, X2",
			".Z X0, X1, X2",
			".BCST 8(BX), X1, X2",
		}
		if go127BinaryFloatingUsesSAE(op) {
			forms = append(forms, ".RN_SAE X0, X1, X2", ".SAE 8(BX), X1, X2")
		} else {
			forms = append(forms, ".SAE X0, X1, X2", ".RN_SAE 8(BX), X1, X2")
		}
		for _, operands := range forms {
			instruction := op + " " + operands
			if strings.HasPrefix(operands, ".") {
				parts := strings.SplitN(operands, " ", 2)
				instruction = op + parts[0] + " " + parts[1]
			}
			t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
				reject(t, instruction)
			})
		}
	}
}

func TestTranslate386BinaryFloatingRejectsArchitectureRestrictedForms(t *testing.T) {
	var instructions []string
	for _, op := range append(go127BinaryFloatingOps(false), go127BinaryFloatingOps(true)...) {
		if strings.HasSuffix(op, "PS") || strings.HasSuffix(op, "PD") {
			instructions = append(instructions, op+" X0, X1, K1, X2", op+" Z6, Z7, Z8", op+" Z8, Z7, Z6")
		} else {
			instructions = append(instructions, op+" X0, X1, K1, X2")
		}
	}
	for _, instruction := range instructions {
		src := "TEXT invalid_binary_floating_386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
		file, err := Parse(ArchAMD64, src)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs: map[string]FuncSig{
				"invalid_binary_floating_386": {Name: "invalid_binary_floating_386", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's 386 register/operand limits", instruction)
		}
	}
}

func TestTranslateX86HorizontalFloatingCompleteGo127Forms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var src strings.Builder
			src.WriteString("TEXT horizontal_floating_complete_forms(SB),NOSPLIT,$0-0\n")
			for _, operation := range []string{"HADD", "HSUB"} {
				for _, element := range []string{"PS", "PD"} {
					op := operation + element
					fmt.Fprintf(&src, "\t%s X0, X1\n", op)
					fmt.Fprintf(&src, "\t%s 8(BX), X15\n", op)
					vop := "V" + op
					fmt.Fprintf(&src, "\t%s X0, X1, X2\n", vop)
					fmt.Fprintf(&src, "\t%s 16(BX), X14, X15\n", vop)
					fmt.Fprintf(&src, "\t%s Y0, Y1, Y2\n", vop)
					fmt.Fprintf(&src, "\t%s 32(BX), Y14, Y15\n", vop)
				}
			}
			src.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"horizontal_floating_complete_forms": {Name: "horizontal_floating_complete_forms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "horizontal-floating-complete-"+target.name+".ll", "horizontal-floating-complete-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86HorizontalFloatingRejectsFormsOutsideGo127Tables(t *testing.T) {
	for _, op := range []string{"HADDPS", "HADDPD", "HSUBPS", "HSUBPD", "VHADDPS", "VHADDPD", "VHSUBPS", "VHSUBPD"} {
		forms := []string{"X0", "X0, X1, X2, X3", "Y0, X1", "X16, X1"}
		validOperands := "X0, X1"
		if strings.HasPrefix(op, "V") {
			forms = []string{
				"X0, X1", "X0, X1, X2, X3", "X0, Y1, Y2", "X16, X1, X2",
				"X0, X1, X16", "Z0, Z1, Z2", "X0, X1, K1, X2",
			}
			validOperands = "X0, X1, X2"
		}
		var instructions []string
		for _, operands := range forms {
			instructions = append(instructions, op+" "+operands)
		}
		for _, suffix := range []string{".Z", ".BCST", ".SAE", ".RN_SAE"} {
			instructions = append(instructions, op+suffix+" "+validOperands)
		}
		for _, instruction := range instructions {
			t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
				src := "TEXT invalid_horizontal_floating(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
				file, err := Parse(ArchAMD64, src)
				if err != nil {
					return
				}
				if _, err := Translate(file, Options{
					TargetTriple: "x86_64-unknown-linux-gnu",
					Goarch:       "amd64",
					Sigs: map[string]FuncSig{
						"invalid_horizontal_floating": {Name: "invalid_horizontal_floating", Ret: Void},
					},
				}); err == nil {
					t.Fatalf("Translate accepted %q outside Go 1.27's yxm/_yvaddsubpd tables", instruction)
				}
			})
		}
	}
}

func translateAMD64EcosystemCase(t *testing.T, src, symbol string) string {
	t.Helper()
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		Sigs:         map[string]FuncSig{symbol: {Name: symbol, Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ll
}

func translateX86FrameCase(t *testing.T, src, goarch, triple, symbol string) {
	t.Helper()
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	frame := FrameLayout{
		Params: []FrameSlot{
			{Offset: 0, Type: I64, Index: 0, Field: -1},
			{Offset: 8, Type: I64, Index: 1, Field: -1},
		},
		Results: []FrameSlot{
			{Offset: 16, Type: I64, Index: 0, Field: -1},
			{Offset: 24, Type: I64, Index: 1, Field: -1},
		},
	}
	if _, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       goarch,
		Sigs: map[string]FuncSig{symbol: {
			Name:  symbol,
			Args:  []LLVMType{I64, I64},
			Ret:   LLVMType("{ i64, i64 }"),
			Frame: frame,
		}},
	}); err != nil {
		t.Fatal(err)
	}
}
