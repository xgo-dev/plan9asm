package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type x86IsolatedVoidSample struct {
	name, source, declaration string
	context                   bool
	goRejected                bool
}

// Complete stock-Go programs precede every tested API. There are deliberately
// no SETcc, vector loads, result stores or unrelated mandatory instructions
// that could accidentally request the tested family's missing source proof.
func x86CheckIsolatedVoidSamples(t *testing.T, arch string, samples []x86IsolatedVoidSample) {
	t.Helper()
	var original strings.Builder
	for _, sample := range samples {
		if !sample.goRejected {
			original.WriteString(sample.source)
		}
	}
	goAssemblerOracleOutput(t, arch, original.String(), "", true)
	for _, sample := range samples {
		if sample.goRejected {
			// Go386's byte-SP source is not an accepted physical SP row.
			// Preserve its actual source-bound rejection separately instead
			// of treating a failed prior as an input-proof defect.
			goAssemblerOracleOutput(t, arch, sample.source, "", false)
			continue
		}
		function := mustParseX86RawReturn(t, sample.source).Funcs[0]
		setup := function
		setup.Instrs = nil
		for _, instruction := range function.Instrs {
			_, compare, _ := x86COMIProperties(instruction, arch)
			_, store, _ := x86ScalarStaticStoreProperties(instruction.Op, instruction, arch)
			if !compare && !store {
				setup.Instrs = append(setup.Instrs, instruction)
			}
		}
		if x86TypedFPResultNeedsProof(setup, FuncSig{Ret: Void}, arch) {
			t.Fatal("fixture contains an unrelated mandatory source-proof instruction", sample.name)
		}
	}
	for _, target := range x86AddressMemoryTargets(arch) {
		t.Run(target, func(t *testing.T) {
			for _, sample := range samples {
				t.Run(sample.name, func(t *testing.T) {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, sample.source, sample.declaration, arch, target, api)
							if sample.goRejected {
								if err == nil || errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("Go-rejected byte-SP syntax became a source-context or accepted program", err)
								}
							} else if sample.context {
								if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
									t.Fatal("isolated Void instruction acquired absent input or storage authority", err)
								}
							} else if err != nil || ir == "" {
								t.Fatal("same isolated Void instruction lost its complete initialized inputs", err)
							}
						})
					}
				})
			}
		})
	}
}

func TestX86COMIIsolatedVoidRetainsCompleteInputObligations(t *testing.T) {
	// Independent original Go and LLVM physical priors retain all four raw
	// VEX/EVEX names, including low-bank EVEX and register-only SAE. Legacy
	// names use the complete named grammar below, not this new raw permission.
	rawRows := x86COMIRawProducerRows(t)
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			type form struct {
				label, operation string
				memory           bool
			}
			var forms []form
			for _, op := range []string{"COMISS", "UCOMISS", "COMISD", "UCOMISD", "VCOMISS", "VUCOMISS", "VCOMISD", "VUCOMISD"} {
				forms = append(forms, form{op + "_register", op + " X1,X0\n", false},
					form{op + "_memory", op + " (BX),X0\n", true})
				if strings.HasPrefix(op, "V") {
					forms = append(forms, form{op + "_SAE", op + ".SAE X1,X0\n", false})
				}
			}
			for _, row := range rawRows {
				forms = append(forms, form{row.op + "_raw_" + row.encoding + "_" + row.form,
					x86RawDisplacementDirectives(row.code), row.form == "memory"})
			}
			if len(forms) != 40 {
				t.Fatal("complete isolated named/raw COMI inventory changed", len(forms))
			}
			word, move := goWordSize(arch), "MOVQ"
			if arch == "386" {
				move = "MOVL"
			}
			var samples []x86IsolatedVoidSample
			for _, row := range forms {
				controls := []string{"initialized", "missing-right", "partial-right"}
				if row.memory {
					controls = append(controls, "missing-pointer", "numeric-pointer")
				} else {
					controls = append(controls, "missing-left", "partial-left", "missing-both")
				}
				for _, control := range controls {
					name := fmt.Sprint("VoidCOMI", len(samples))
					setup := "MOVL $0,AX\nMOVL AX,X0\nMOVL AX,X1\n"
					if row.memory {
						setup += move + " p+0(FP),BX\n"
					}
					switch control {
					case "missing-right", "missing-both":
						setup = strings.Replace(setup, "MOVL AX,X0\n", "", 1)
					case "partial-right":
						setup = strings.Replace(setup, "MOVL AX,X0\n", "MOVB $0,DL\nMOVL DX,X0\n", 1)
					case "missing-left":
						setup = strings.Replace(setup, "MOVL AX,X1\n", "", 1)
					case "partial-left":
						setup = strings.Replace(setup, "MOVL AX,X1\n", "MOVB $0,DL\nMOVL DX,X1\n", 1)
					case "missing-pointer":
						setup = strings.Replace(setup, move+" p+0(FP),BX\n", "", 1)
					case "numeric-pointer":
						setup = strings.Replace(setup, move+" p+0(FP),BX\n", move+" $1,BX\n", 1)
					}
					if control == "missing-both" {
						setup = strings.Replace(setup, "MOVL AX,X1\n", "", 1)
					}
					extent, declaration := 0, fmt.Sprintf("func %s()\n", name)
					if row.memory {
						extent, declaration = word, fmt.Sprintf("func %s(p *byte)\n", name)
					}
					source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s%sRET\n", name, extent, setup, row.operation)
					samples = append(samples, x86IsolatedVoidSample{row.label + "/" + control, source, declaration, control != "initialized", false})
				}
			}
			x86CheckIsolatedVoidSamples(t, arch, samples)
		})
	}
}

func TestX86OwnedScalarMOVIsolatedVoidRetainsInputsAndStorage(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			word, move := goWordSize(arch), "MOVQ"
			if arch == "386" {
				move = "MOVL"
			}
			var samples []x86IsolatedVoidSample
			for _, row := range x86OwnedScalarStoreRows(arch) {
				for _, control := range []string{"initialized", "immediate", "missing", "partial", "pointer", "physical-SP", "readonly", "past-end", "external"} {
					name := fmt.Sprint("VoidMOV", len(samples))
					storage := fmt.Sprint("·storage", len(samples))
					global := "GLOBL " + storage + "(SB),16,$32\n"
					setup := move + " $0x12345678,AX\n"
					input, destination := row.register, storage+"+3(SB)"
					extent, declaration := 0, fmt.Sprintf("func %s()\n", name)
					switch control {
					case "immediate":
						setup, input = "", "$7"
					case "missing":
						setup = ""
					case "partial":
						setup = "MOVB $7,AL\n"
						if row.width == 1 && row.first == 0 {
							setup = "MOVB $7,AH\n" // Define a different byte, never the selected AL.
						}
					case "pointer":
						setup = move + " p+0(FP),AX\n"
						extent, declaration = word, fmt.Sprintf("func %s(p *byte)\n", name)
					case "physical-SP":
						setup, input = "", "SP"
					case "readonly":
						global = "GLOBL " + storage + "(SB),8,$32\n"
					case "past-end":
						destination = storage + "+32(SB)"
					case "external":
						global = ""
					}
					source := fmt.Sprintf("%sTEXT ·%s(SB),4,$0-%d\n%s%s %s,%s\nRET\n",
						global, name, extent, setup, row.op, input, destination)
					samples = append(samples, x86IsolatedVoidSample{row.op + "/" + row.register + "/" + control,
						source, declaration, control != "initialized" && control != "immediate",
						arch == "386" && row.width == 1 && control == "physical-SP"})
				}
			}
			x86CheckIsolatedVoidSamples(t, arch, samples)
		})
	}
}
