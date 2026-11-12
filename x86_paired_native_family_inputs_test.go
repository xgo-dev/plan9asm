package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

// This is a source-input boundary, not a second mnemonic implementation.
// The separate original-Go and object matrices retain the complete formats.
func TestX86PairedNativeFamiliesRetainIndependentInputs(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		rows := x86PackedNativeAddressRows()
		for _, name := range append(x86LegacyFloatMemoryOpcodes(), "PMADDWL", "PMADDUBSW", "PMULLD", "VPMULLD", "VPMULLQ") {
			rows = append(rows, struct{ name, destination string }{name, "X1"})
		}
		for _, row := range rows {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				instruction := row.name + " (AX)," + row.destination
				if row.name == "VPMULLD" || row.name == "VPMULLQ" {
					instruction = row.name + " (AX),X0," + row.destination
				}
				source := x86OrdinaryBPNativeSource(arch, "Value", instruction, "(AX)", 0)
				move := "MOVQ"
				if arch == "386" {
					move = "MOVL"
				}
				variants := map[string]string{
					"unknown-pointer": strings.Replace(source, "p+0(FP),AX", "p+0(FP),DI", 1),
					"numeric-pointer": strings.Replace(source, move+" p+0(FP),AX", move+" $42,AX", 1),
				}
				if !strings.Contains(row.name, "CVT") {
					input := "X1"
					if strings.HasPrefix(row.name, "V") {
						input = "X0"
					}
					variants["unknown-vector"] = strings.Replace(source, "PXOR "+input+","+input+"\n", "", 1)
				}
				for _, api := range []string{"text", "module", "Go"} {
					originalIR, err := x86ScalarFPBitViewAPI(t, source, "func Value(p *byte)", arch, triple, api)
					if err != nil || originalIR == "" {
						t.Error("initialized paired native control rejected", api, err)
					}
					for name, changed := range variants {
						ir, err := x86ScalarFPBitViewAPI(t, changed, "func Value(p *byte)", arch, triple, api)
						if name == "numeric-pointer" {
							if err != nil || ir == "" {
								t.Fatal("complete numerical address lost its paired source", api, err)
							}
							x86RequireSameNativeMemoryEffects(t, originalIR, ir)
							x86RequireNumericNativeSourceContext(t, changed, "func Value(p *byte)", arch)
							x86NumericNativeAddressObject(t, ir, triple)
						} else if arch == "amd64" && name == "unknown-vector" {
							x86VectorScratchCodegenControl(t, changed, "func Value(p *byte)", arch, triple, ir, err)
						} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Error("native continuation invented an independent input", api, name, err)
						}
					}
				}
			})
		}
	}
}
