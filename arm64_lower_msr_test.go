package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64MSRCompleteGoAssemblerForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT ·systemRegisterForms(SB), $0-0\n")
	for _, field := range []string{"SPSel", "DAIFSet", "DAIFClr", "DIT"} {
		first := 0
		if field == "DAIFSet" || field == "DAIFClr" {
			// Go parses $0 as ZR, which is not an immediate PSTATE form
			// for these special operands.
			first = 1
		}
		for immediate := first; immediate < 16; immediate++ {
			fmt.Fprintf(&source, "\tMSR $%d, %s\n", immediate, field)
		}
	}
	source.WriteString("\tMSR $0, CPACR_EL1\n")
	source.WriteString("\tMSR R0, DAIF\n")
	source.WriteString("\tMRS DAIF, R1\n")
	source.WriteString("\tRET\n")

	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
				Sigs: map[string]FuncSig{
					"systemRegisterForms": {Name: "systemRegisterForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"msr SPSel, xzr",
				"msr SPSel, #1",
				"msr DAIFSet, #2",
				"msr DAIFClr, #15",
				"msr DIT, xzr",
				"msr DIT, #1",
				`"target-features"="+dit"`,
				"msr CPACR_EL1, xzr",
				"msr DAIF, $0",
				"mrs $0, DAIF",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 MSR lowering omitted %q", want)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-msr.ll", "arm64-msr.o", ll)
		})
	}
}

func TestTranslateARM64MSRRejectsImmediateOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"MSR $-1, DAIFSet",
		"MSR $0, DAIFSet",
		"MSR $0, DAIFClr",
		"MSR $16, DAIFClr",
		"MSR $16, SPSel",
		"MSR $16, DIT",
		"MSR $1, CPACR_EL1",
		"MSR R0, DAIFSet",
	} {
		source := "TEXT ·badMSR(SB), $0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
			Sigs: map[string]FuncSig{
				"badMSR": {Name: "badMSR", Ret: Void},
			},
		})
		if err == nil {
			t.Fatalf("accepted %s outside Go's MSR immediate format", instruction)
		}
	}
}

func TestARM64MSRPStateEncodingMatchesGoAssembler(t *testing.T) {
	// Go 1.27's -S listing supplies these words independently of the LLVM
	// encoder. These privileged instructions cannot run in a user-mode test.
	for _, tc := range []struct {
		goForm   string
		llvmForm string
		word     uint32
	}{
		{"MSR $0, SPSel", "msr SPSel, xzr", 0xd518421f},
		{"MSR $1, SPSel", "msr SPSel, #1", 0xd50041bf},
		{"MSR $2, DAIFSet", "msr DAIFSet, #2", 0xd50342df},
		{"MSR $15, DAIFClr", "msr DAIFClr, #15", 0xd5034fff},
		{"MSR $0, DIT", "msr DIT, xzr", 0xd51b42bf},
		{"MSR $1, DIT", "msr DIT, #1", 0xd503415f},
		{"MSR $0, CPACR_EL1", "msr CPACR_EL1, xzr", 0xd518105f},
	} {
		source := "TEXT ·msrOracle(SB), $0-0\n\t" + tc.goForm + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, true)
		words := assembleARM64LLVMWords(t, []string{tc.llvmForm}, "+dit")
		if words[0] != tc.word {
			t.Fatalf("%s: LLVM encoded %#08x, Go encoded %#08x", tc.goForm, words[0], tc.word)
		}
	}
}
