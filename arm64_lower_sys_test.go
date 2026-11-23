package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestTranslateARM64SYSCompleteGoAssemblerForms(t *testing.T) {
	const source = `TEXT sysforms(SB),$0-0
	SYS $0
	SYS $0x37520, R3
	SYS $0x7ffe0, ZR
	SYSL $0, R12
	SYSL $0x7ffe0, ZR
	RET
`
	requireARM64GoAssemblerResult(t, source, true)

	for _, triple := range []string{
		"arm64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"sysforms": {Name: "sysforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`asm sideeffect "sys #0, c0, c0, #0, xzr"`,
				`asm sideeffect "sys #3, c7, c5, #1, $0"`,
				`asm sideeffect "sys #7, c15, c15, #7, xzr"`,
				`asm sideeffect "sysl $0, #0, c0, c0, #0"`,
				`asm sideeffect "sysl xzr, #7, c15, c15, #7"`,
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 SYS/SYSL lowering omitted %q:\n%s", want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sys.ll", "arm64-sys.o", ll)
		})
	}
}

func TestARM64RawSystemOperationsShareNamedOperands(t *testing.T) {
	const source = `TEXT conversion(SB),4,$0-0
 MOVD $42,R1
 WORD $0xd5088001
 WORD $0xd508801f
 WORD $0xd52c5b0c
 WORD $0xd52c5b1f
 WORD $0xd50e853e
 TLBI RVAE3OS, R30
 RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"arm64-apple-darwin", arm64LinuxGNUTriple, "aarch64-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := arm64ScalarConversionAPI(t, api, source, triple)
				if err != nil {
					t.Fatal(err)
				}
				for _, op := range []string{
					"sys #0, c8, c0, #0, $0",
					"sys #0, c8, c0, #0, xzr",
					"sysl $0, #4, c5, c11, #0",
					"sysl xzr, #4, c5, c11, #0",
					"sys #6, c8, c5, #1, $0",
				} {
					if !strings.Contains(ir, op) {
						t.Fatalf("missing typed system operation %q", op)
					}
				}
				compileLLVMToObject(t, llc, triple, "raw-system.ll", "raw-system.o", ir)
			})
		}
	}
	for _, instruction := range file.Funcs[0].Instrs {
		if instruction.Op == OpWORD && !errors.Is(ProbeInstruction(ArchARM64, "arm64", instruction), ErrProbeNeedsContext) {
			t.Fatalf("isolated %q acquired privileged execution context", instruction.Raw)
		}
	}
	for _, instruction := range []string{"SYSL $285440,R30", "WORD $0xd52c5b1e"} {
		source := "TEXT conversion(SB),4,$0-0\n" + instruction + "\nRET\n"
		if _, err := arm64ScalarConversionAPI(t, "text", source, arm64LinuxGNUTriple); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("%q changed the caller's link without a restore: %v", instruction, err)
		}
	}
}

func TestTranslateARM64SYSRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"SYS $1",
		"SYS $0x80000",
		"SYS $0, R1, R2",
		"SYS R1",
		"SYS.P $0",
		"AT $1",
		"AT $0x80000",
		"AT $0, R1, R2",
		"AT S1E1R, R3",
		"AT.P $0",
		"SYSL $0",
		"SYSL $0, $1",
		"SYSL $0, R1, R2",
		"SYSL.P $0, R1",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SYS/SYSL/AT forms", instruction)
			}
		})
	}
}
