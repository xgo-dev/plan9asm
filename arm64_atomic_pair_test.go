package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func translateARM64AtomicPairSource(src string) (string, error) {
	file, err := Parse(ArchARM64, src)
	if err != nil {
		return "", err
	}
	return Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"atomicpairforms": {Name: "atomicpairforms", Ret: Void},
		},
	})
}

func TestTranslateARM64AtomicPairFamilyCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 has ten paired-atomic opcodes. CASP accepts C_ZOREG and
	// C_ZAUTO memory, while paired exclusive loads/stores accept C_ZOREG.
	// Register pairs for LDXP/STXP need not be contiguous; SP/RSP in a data
	// pair encodes register 31 (ZR), rather than changing the stack pointer.
	src := `
TEXT atomicpairforms(SB),NOSPLIT,$16-0
	CASPW (R0, R1), (R2), (R4, R5)
	CASPW (R6, R7), local+0(SP), (R10, R11)
	CASPD (R12, R13), (ZR), (R14, R15)
	CASPD (R30, ZR), (RSP), (R28, R29)
	LDXPW (R16), (R0, R7)
	LDXP (RSP), (R30, ZR)
	LDAXPW (ZR), (RSP, R1)
	LDAXP (R18), (R2, R17)
	STXPW (R3, R3), (R19), R20
	STXP (RSP, R21), (RSP), ZR
	STLXPW (ZR, R22), (R23), R24
	STLXP (R25, R26), (ZR), R27
	RET
`
	ll, err := translateARM64AtomicPairSource(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"cmpxchg ptr", "load atomic i64", "load atomic i128", "%exclusive_value"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("paired atomic lowering omitted %q:\n%s", want, ll)
		}
	}

	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		goos   string
		triple string
	}{
		{goos: "darwin", triple: "arm64-apple-macosx"},
		{goos: "linux", triple: "aarch64-unknown-linux-gnu"},
		{goos: "windows", triple: "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.goos, func(t *testing.T) {
			file, err := Parse(ArchARM64, src)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"atomicpairforms": {Name: "atomicpairforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "atomic-pair.ll", "atomic-pair.o", ir)
		})
	}
}

func TestTranslateARM64AtomicPairFamilyRejectsFormsOutsideGoOptabs(t *testing.T) {
	invalid := []string{
		// CASP requires two even-starting contiguous pairs and zero-offset
		// C_ZOREG/C_ZAUTO memory.
		"CASPD (R1, R2), (R3), (R4, R5)",
		"CASPW (R0, R1), (R3), (R5, R6)",
		"CASPD (R0, R2), (R3), (R4, R5)",
		"CASPW (R0, R1), (R3), (R4, R6)",
		"CASPD (R30, RSP), (R3), (R4, R5)",
		"CASPW R0, (R3), (R4, R5)",
		"CASPD (R0, R1), (R3), R4",
		"CASPW (R0, R1), 8(R3), (R4, R5)",
		"CASPD (R0, R1), local+8(SP), (R4, R5)",
		"CASPW (R0, R1), value+0(FP), (R4, R5)",
		"CASPD (R0, R1), value(SB), (R4, R5)",
		"CASPW.P (R0, R1), (R3), (R4, R5)",

		// Paired exclusive loads require zero-offset register memory, exactly
		// two distinct GPR/ZR data registers, and no opcode suffix.
		"LDXP (R3), (R4, R4)",
		"LDAXPW (R3), (R4, R4)",
		"LDXPW 8(R3), (R4, R5)",
		"LDAXP local+0(SP), (R4, R5)",
		"LDXP value+0(FP), (R4, R5)",
		"LDAXPW value(SB), (R4, R5)",
		"LDXP (R3), R4",
		"LDAXP (R3), (R4, R5, R6)",
		"LDXP (R3), (F0, R4)",
		"LDAXPW.P (R3), (R4, R5)",

		// Paired exclusive stores allow repeated data registers, but the
		// status register cannot be SP/RSP or overlap either data register or
		// a non-RSP base register.
		"STXP (R4, R5), (R6), R4",
		"STLXPW (R4, R5), (R6), R5",
		"STXPW (R4, R5), (R6), R6",
		"STLXP (R4, R5), (ZR), ZR",
		"STXP (R4, R5), (R6), RSP",
		"STLXPW R4, (R6), R7",
		"STXP (R4, R5, R6), (R7), R8",
		"STLXP (R4, F0), (R6), R7",
		"STXPW (R4, R5), 8(R6), R7",
		"STLXP (R4, R5), local+0(SP), R7",
		"STXP (R4, R5), value+0(FP), R7",
		"STLXPW (R4, R5), value(SB), R7",
		"STXP.P (R4, R5), (R6), R7",
	}

	for _, instruction := range invalid {
		t.Run(strings.NewReplacer(" ", "_", "(", "", ")", "", ",", "_").Replace(instruction), func(t *testing.T) {
			src := fmt.Sprintf("TEXT atomicpairforms(SB),NOSPLIT,$16-0\n\t%s\n\tRET\n", instruction)
			if _, err := translateARM64AtomicPairSource(src); err == nil {
				t.Fatalf("Translate accepted %q, which is outside the Go 1.27 paired-atomic optabs", instruction)
			}
		})
	}
}

func TestParseARM64AtomicPairPreservesRSPAndNamedSP(t *testing.T) {
	file, err := Parse(ArchARM64, `
TEXT atomicpairforms(SB),NOSPLIT,$16-0
	CASPD (R0, R1), local+0(SP), (R2, R3)
	LDAXP (RSP), (RSP, R4)
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	casMem := file.Funcs[0].Instrs[1].Args[1].Mem
	if casMem.Base != SP || casMem.OffRaw == "" {
		t.Fatalf("named SP memory = %+v, want pseudo-SP plus preserved name", casMem)
	}
	load := file.Funcs[0].Instrs[2]
	if load.Args[0].Mem.Base != Reg("RSP") || load.Args[1].RegList[0] != Reg("RSP") {
		t.Fatalf("physical RSP was not preserved: %+v", load.Args)
	}
}

func TestARM64AtomicPairInstructionFamily(t *testing.T) {
	for _, op := range []string{
		"CASPW", "CASPD",
		"LDXPW", "LDXP", "LDAXPW", "LDAXP",
		"STXPW", "STXP", "STLXPW", "STLXP",
	} {
		if got := InstructionFamily(ArchARM64, op); got != "atomic-memory" {
			t.Errorf("InstructionFamily(arm64, %s) = %q, want atomic-memory", op, got)
		}
	}
}
