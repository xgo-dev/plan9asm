package plan9asm

import (
	"strings"
	"testing"
)

const arm64ExceptionForms = `
TEXT exceptionforms(SB),$0-0
	BRK
	BRK $0
	BRK $65535
	BRK $65536
	BRK $-1
	RET

TEXT undefinedform(SB),$0-0
	UNDEF
`

func TestTranslateARM64ExceptionCompleteGoAssemblerForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64ExceptionForms, true)

	for _, triple := range []string{
		"arm64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, arm64ExceptionForms)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"exceptionforms": {Name: "exceptionforms", Ret: Void},
					"undefinedform":  {Name: "undefinedform", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(ll, `asm sideeffect "brk #0"`); got != 3 {
				t.Fatalf("ARM64 BRK zero-immediate count = %d, want 3:\n%s", got, ll)
			}
			if got := strings.Count(ll, `asm sideeffect "brk #65535"`); got != 2 {
				t.Fatalf("ARM64 BRK max-immediate count = %d, want 2:\n%s", got, ll)
			}
			if !strings.Contains(ll, `asm sideeffect "udf #0"`) || !strings.Contains(ll, "unreachable") {
				t.Fatalf("ARM64 UNDEF did not lower to a terminating undefined instruction:\n%s", ll)
			}
			// BRK is resumable under a debugger, so exceptionforms must retain RET.
			start := strings.Index(ll, "define void @exceptionforms()")
			end := strings.Index(ll[start:], "define void @undefinedform()")
			if start < 0 || end < 0 || !strings.Contains(ll[start:start+end], "ret void") {
				t.Fatalf("ARM64 BRK incorrectly terminated the resumable function:\n%s", ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-exception.ll", "arm64-exception.o", ll)
		})
	}
}

func TestTranslateARM64ExceptionRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"BRK R0",
		"BRK $1, $2",
		"BRK.P $1",
		"UNDEF $0",
		"UNDEF.P",
	} {
		source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's BRK/UNDEF forms", instruction)
		}
	}
}

func TestTranslateARM64PrivilegedExceptionCompleteGoAssemblerForms(t *testing.T) {
	const source = `TEXT privilegedforms(SB),$0-0
	HVC
	HVC $61428
	SMC
	SMC $37977
	RET

TEXT dcps1zero(SB),$0-0
	DCPS1

TEXT dcps1imm(SB),$0-0
	DCPS1 $11378

TEXT dcps2zero(SB),$0-0
	DCPS2

TEXT dcps2imm(SB),$0-0
	DCPS2 $10699

TEXT dcps3zero(SB),$0-0
	DCPS3

TEXT dcps3imm(SB),$0-0
	DCPS3 $24415

TEXT haltzero(SB),$0-0
	HLT

TEXT haltimm(SB),$0-0
	HLT $65509

TEXT drpsform(SB),$0-0
	DRPS

TEXT eretform(SB),$0-0
	ERET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"privilegedforms": {Name: "privilegedforms", Ret: Void},
			"dcps1zero":       {Name: "dcps1zero", Ret: Void},
			"dcps1imm":        {Name: "dcps1imm", Ret: Void},
			"dcps2zero":       {Name: "dcps2zero", Ret: Void},
			"dcps2imm":        {Name: "dcps2imm", Ret: Void},
			"dcps3zero":       {Name: "dcps3zero", Ret: Void},
			"dcps3imm":        {Name: "dcps3imm", Ret: Void},
			"haltzero":        {Name: "haltzero", Ret: Void},
			"haltimm":         {Name: "haltimm", Ret: Void},
			"drpsform":        {Name: "drpsform", Ret: Void},
			"eretform":        {Name: "eretform", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`asm sideeffect "hvc #0"`,
		`asm sideeffect "hvc #61428"`,
		`asm sideeffect "smc #0"`,
		`asm sideeffect "smc #37977"`,
		`asm sideeffect "dcps1 #0"`,
		`asm sideeffect "dcps1 #11378"`,
		`asm sideeffect "dcps2 #0"`,
		`asm sideeffect "dcps2 #10699"`,
		`asm sideeffect "dcps3 #0"`,
		`asm sideeffect "dcps3 #24415"`,
		`asm sideeffect "hlt #0"`,
		`asm sideeffect "hlt #65509"`,
		`asm sideeffect "drps"`,
		`asm sideeffect "eret"`,
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM64 exception lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "arm64-privileged-exception.ll", "arm64-privileged-exception.o", ll)
}

func TestTranslateARM64RawSMC(t *testing.T) {
	const source = `TEXT rawsmc(SB),$0-0
	WORD $0xd4000003
	RET
`
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"rawsmc": {Name: "rawsmc", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, `asm sideeffect "smc #0"`) {
		t.Fatalf("ARM64 raw SMC lowering omitted the instruction:\n%s", ll)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "arm64-raw-smc.ll", "arm64-raw-smc.o", ll)
}

func TestTranslateARM64RejectsUnexpandedExceptionMacros(t *testing.T) {
	for _, instruction := range []string{
		"BREAK",
		"#UNDEF",
		"SAVE_R19_TO_R28(32)",
		"RESTORE_R19_TO_R28(32)",
		"SAVE_F8_TO_F15(112)",
		"RESTORE_F8_TO_F15(112)",
		"P256ADDINLINE",
		"P256MULBY2INLINE",
		"STY",
		"MOV",
	} {
		file, err := Parse(ArchARM64, "TEXT bad(SB),$0-0\n\t"+instruction+"\n\tRET\n")
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate silently accepted unexpanded macro %q", instruction)
		}
	}
}
