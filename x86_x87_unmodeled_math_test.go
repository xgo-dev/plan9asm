package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// All inputs are source-defined exact ones and every original instruction is
// retained. This distinguishes an unmodeled mathematical effect from missing
// entry values, malformed syntax or a memory-address failure.
func TestX86X87SoftwareUnmodeledMathSourceBoundary(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []Op{"F2XM1", "FCOS", "FSIN", "FPATAN", "FPREM", "FPREM1", "FPTAN", "FSCALE", "FSINCOS", "FXTRACT", "FYL2X", "FYL2XP1"} {
			inputs, outputs := 1, 1
			switch op {
			case "FPATAN", "FYL2X", "FYL2XP1":
				inputs = 2
			case "FPREM", "FPREM1", "FSCALE":
				inputs, outputs = 2, 2
			case "FPTAN", "FSINCOS", "FXTRACT":
				outputs = 2
			}
			for _, result := range []string{"value", "balanced-Void", "dead-Void"} {
				declaration := "func Value()"
				body := "FINIT\n" + strings.Repeat("FLD1\n", inputs) + string(op) + "\n"
				remaining := outputs
				if result == "value" {
					declaration += " float64"
					body += "FMOVDP F0,ret+0(FP)\n"
					remaining--
				}
				if result != "dead-Void" {
					body += strings.Repeat("FMOVDP F0,F0\n", remaining)
				}
				body += "RET\n"
				_, _, _, source := x86ResultInitializationFixture(t, arch, declaration, body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", arch, op, result, api), func(t *testing.T) {
						ir, err := x86X87InitializedWordAPI(t, source, declaration, arch, testTargetTriple("linux", arch), api, X87Software)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("unmodeled Software math did not retain an explicit unsupported boundary", op, result, len(ir), err)
						}
						if !strings.Contains(err.Error(), "portable binary80 provider is not implemented") {
							t.Fatal("legal defined-input math was misclassified as unknown input", err)
						}
						for _, mode := range []X87Mode{X87Auto, X87Hardware} {
							ir, err := x86X87InitializedWordAPI(t, source, declaration, arch, testTargetTriple("linux", arch), api, mode)
							if err != nil || ir == "" || !strings.Contains(ir, strings.ToLower(string(op))+";") || strings.Contains(ir, "call double @") {
								t.Fatal("matching native mathematical instruction lost its existing admission", mode, err)
							}
							if mode == X87Hardware && result != "dead-Void" {
								for _, level := range []string{"-O0", "-O2"} {
									t.Run(level, func(t *testing.T) {
										x86PackedStringCompileObject(t, llc, testTargetTriple("linux", arch), ir, level)
									})
								}
							}
						}
						if result != "dead-Void" {
							return
						}
						for _, target := range []string{"armv7-unknown-linux-gnueabihf", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
							ir, err := x86X87InitializedWordAPI(t, source, declaration, arch, target, api, X87Auto)
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "portable binary80 provider is not implemented") {
								t.Fatal("portable Auto fell back to an approximate mathematical provider", target, err)
							}
						}
					})
				}
			}
		}
		for _, control := range []struct {
			name, declaration, body string
		}{
			{"missing-F0", "func Value() float64", "FINIT\nF2XM1\nFMOVDP F0,ret+0(FP)\nRET\n"},
			{"missing-F1", "func Value() float64", "FINIT\nFLD1\nFPATAN\nFMOVDP F0,ret+0(FP)\nRET\n"},
			{"full-stack", "func Value() float64", "FINIT\n" + strings.Repeat("FLD1\n", 8) + "FXTRACT\nFMOVDP F0,ret+0(FP)\n" + strings.Repeat("FMOVDP F0,F0\n", 8) + "RET\n"},
			{"conditional-second-value", "func Value() float64", "FINIT\nFLDPI\nFPTAN\nFMOVDP F0,ret+0(FP)\nFMOVDP F0,F0\nRET\n"},
			{"conditional-extra-pop", "func Value() float64", "FINIT\nFLDPI\nFSINCOS\nFMOVDP F0,ret+0(FP)\nFMOVDP F0,F0\nRET\n"},
			{"undefined-remainder-status", "func Value() uint16", "FINIT\nFLD1\nFLD1\nFPREM\nFSTSW AX\nANDW $0x4500,AX\nMOVW AX,ret+0(FP)\nFMOVDP F0,F0\nFMOVDP F0,F0\nRET\n"},
			{"raw-math", "func Value() float64", "FINIT\nFLD1\nBYTE $0xd9\nBYTE $0xfe\nFMOVDP F0,ret+0(FP)\nRET\n"},
		} {
			_, _, _, source := x86ResultInitializationFixture(t, arch, control.declaration, control.body)
			goAssemblerOracleOutput(t, arch, source, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/native-obligations/%s/%s", arch, control.name, api), func(t *testing.T) {
					for _, mode := range []X87Mode{X87Auto, X87Hardware} {
						ir, err := x86X87InitializedWordAPI(t, source, control.declaration, arch, testTargetTriple("linux", arch), api, mode)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("native mathematical effect borrowed unavailable source facts", control.name, mode, len(ir), err)
						}
					}
				})
			}
		}
	}
}
