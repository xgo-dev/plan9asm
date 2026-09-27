package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestProbeARM64PrivilegedOfficialFormsRequireExecutionContext(t *testing.T) {
	for _, instruction := range []string{
		"TLBI VMALLE1IS",
		"TLBI VAE1IS, R0",
		"TLBI VAE3IS, ZR",
		"SYS $32768",
		"SYS $32768, R1",
		"SYSL $285440, R12",
		"DCPS1 $11378",
		"DCPS2 $10699",
		"DCPS3 $24415",
		"DRPS",
		"ERET",
		"HLT $65509",
		"HLT",
		"HVC $61428",
		"HVC",
		"SMC $37977",
		"SMC",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT privileged(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			probeErr := ProbeInstruction(ArchARM64, "arm64", file.Funcs[0].Instrs[1])
			if !errors.Is(probeErr, ErrProbeNeedsContext) {
				t.Fatalf("ProbeInstruction(%q) error = %v, want ErrProbeNeedsContext", instruction, probeErr)
			}
			_, translateErr := Translate(file, Options{
				TargetTriple: arm64LinuxGNUTriple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"privileged": {Name: "privileged", Ret: Void}},
			})
			op := strings.Fields(instruction)[0]
			supported := op == "SYS" || op == "SYSL" || op == "TLBI" || op == "HLT" || op == "HVC" || op == "SMC" ||
				op == "DRPS" || op == "ERET" || strings.HasPrefix(op, "DCPS")
			if supported && translateErr != nil {
				t.Fatalf("targeted translation of supported privileged instruction %q failed: %v", instruction, translateErr)
			}
			if !supported && translateErr == nil {
				t.Fatalf("unsupported privileged instruction %q unexpectedly translated", instruction)
			}
		})
	}
}
