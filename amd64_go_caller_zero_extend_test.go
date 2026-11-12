package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86GoCallerPackedZeroExtendCurrentGap(t *testing.T) {
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)",
		"VMOVUPS (DI),X0\nVPMOVZXBD X0,Y1\nVMOVSS X1,(DX)", 1)
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
		t.Fatalf("Go-accepted bounded byte widening with initialized input: %v", err)
	}
}

func TestX86GoCallerPackedZeroExtendCompleteInitializedForms(t *testing.T) {
	for _, ratio := range x86ZeroExtendTestRatios {
		for _, prefix := range []string{"P", "VP"} {
			for _, original := range x86ZeroExtendAcceptedForms(prefix+"MOVZX"+ratio.suffix, "amd64") {
				t.Run(original, func(t *testing.T) {
					row := strings.NewReplacer("(AX)", "(DI)", "X15", "X2", "X31", "X2", "Y31", "Y2", "Z31", "Z2").Replace(original)
					body := "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (SI),Z2\nKMOVQ AX,K1\nKMOVQ AX,K7\n" + row
					if strings.HasSuffix(row, "X1") || strings.HasSuffix(row, "Y1") {
						body += "\nVMOVSS X1,(DX)"
					} else {
						body += "\nVMOVSS X2,(DX)"
					}
					assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
					requireX86GoAssemblerResult(t, "amd64", assembly, true)
					pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
					if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestX86GoCallerPackedZeroExtendRetainsUnknownAndEnvelopeFailures(t *testing.T) {
	for name, body := range map[string]string{
		"unknown input":           "VPMOVZXBD X0,Y1\nVMOVSS X1,(DX)",
		"unknown merge":           "VMOVUPS (DI),X0\nKMOVQ AX,K1\nVPMOVZXBD X0,K1,Y1\nVMOVSS X1,(DX)",
		"unknown mask":            "VMOVUPS (DI),X0\nVPMOVZXBD.Z X0,K1,Y1\nVMOVSS X1,(DX)",
		"pointer mask":            "VMOVUPS (DI),X0\nKMOVQ DI,K1\nVPMOVZXBD.Z X0,K1,Y1\nVMOVSS X1,(DX)",
		"unknown base":            "VPMOVZXBD (BX),Y1\nVMOVSS X1,(DX)",
		"private stack":           "VPMOVZXBD (SP),Y1\nVMOVSS X1,(DX)",
		"pointer FP data":         "VPMOVZXBD a+0(FP),Y1\nVMOVSS X1,(DX)",
		"overread length":         "VPMOVZXBW (CX),Y1\nVMOVSS X1,(DX)",
		"zero mask envelope":      "MOVL $0,AX\nKMOVQ AX,K1\nVPMOVZXBW.Z (DX),K1,Y1\nVMOVSS X1,(DX)",
		"source write":            "VPMOVZXBD (DI),Y1\nVMOVSS X1,(DI)",
		"wide result":             "VPMOVZXBD (DI),Y1\nVMOVUPS Y1,(DX)",
		"undefined CFG join":      "CMPQ AX,$0\nJE joined\nVMOVUPS (DI),X0\njoined:\nVPMOVZXBD X0,Y1\nVMOVSS X1,(DX)",
		"unknown upper alias":     "VMOVUPS (DI),X0\nPMOVZXBD X0,X1\nVPMOVZXBW Y1,Z2\nVMOVSS X2,(DX)",
		"signed sign byte absent": "PINSRB $0,AX,X0\nVPMOVSXWQ X0,X1\nPEXTRD $1,X1,AX\nMOVL AX,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			// The upper-alias negative must observe an unknown part, not the
			// correctly initialized low X bytes of the first widening result.
			if name == "unknown upper alias" {
				assembly = strings.Replace(assembly, "VMOVSS X2,(DX)", "VEXTRACTI128 $1,Y1,X2\nVMOVSS X2,(DX)", 1)
			}
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved zero-extension acquired caller continuation: %v", err)
			}
		})
	}
}

func TestX86GoCallerPackedZeroExtendIndependentByteKnowledge(t *testing.T) {
	for _, ratio := range x86ZeroExtendTestRatios {
		for _, vector := range []bool{false, true} {
			for _, width := range []int{16, 32, 64} {
				if !vector && width != 16 {
					continue
				}
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
				source := "X0"
				if width*ratio.input/ratio.output > 16 {
					source = "Y0"
				}
				for _, destination := range []int{0, 1} {
					for mode := 0; mode < 3; mode++ {
						if !vector && mode != 0 {
							continue
						}
						name, mask := "PMOVZX"+ratio.suffix, ""
						if vector {
							name = "V" + name
						}
						if mode != 0 {
							mask = "K1,"
							if mode == 2 {
								name += ".Z"
							}
						}
						row := fmt.Sprintf("%s %s,%s%s%d", name, source, mask, bank, destination)
						file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
						if err != nil {
							t.Fatal(err)
						}
						ins := file.Funcs[0].Instrs[1]
						form, _, err := x86PackedZeroExtendProperties(ins, "amd64")
						if err != nil {
							t.Fatal(err)
						}
						for seed := 0; seed < 64; seed++ {
							input, old := uint64(seed)*0x391072d5e64b8a0f, uint64(seed+7)*0x6a89e14f30725bc1
							initial := map[Reg]uint64{"Z0": input, "Z1": old}
							before := initial[Reg(fmt.Sprintf("Z%d", destination))]
							result := x86ResultState{flags: x86ByteFlagsAll}
							result.writeVector(0, 64, input, false)
							result.writeVector(1, 64, old, false)
							result.masks[1] = true
							if !x86ResultTransfer(ins, &result, nil, 0, "amd64") {
								t.Fatal("independent result observer lacks widening byte effects", row)
							}
							state := x86SourceStackState{vectors: initial, masks: map[Reg]bool{"K1": true}}
							if !x86CallerPackedZeroExtendStep(&ins, form, &state, nil) {
								t.Fatal("register byte effect refused")
							}
							var want uint64
							for output := 0; output < 64; output++ {
								known := false
								if output >= width {
									known = vector || before>>uint(output)&1 != 0
								} else {
									part := output % ratio.output
									known = part >= ratio.input || input>>uint(output/ratio.output*ratio.input+part)&1 != 0
									if mode == 1 {
										known = known && before>>uint(output)&1 != 0
									}
								}
								if known {
									want |= uint64(1) << uint(output)
								}
							}
							if got := state.vectors[Reg(fmt.Sprintf("Z%d", destination))]; got != want {
								t.Fatalf("%s seed%d: defined bytes %#x want %#x", row, seed, got, want)
							}
							if result.vectorBytes(destination) != want || result.flags != x86ByteFlagsAll ||
								result.vectorBytes(1-destination) != map[int]uint64{0: input, 1: old}[1-destination] {
								t.Fatalf("%s seed%d: result bytes %#x want %#x, or changed another register/FLAGS", row, seed, result.vectorBytes(destination), want)
							}
							if state.vectors[Reg(fmt.Sprintf("Z%d", 1-destination))] != map[int]uint64{0: input, 1: old}[1-destination] {
								t.Fatal("widening changed another SIMD register")
							}
						}
					}
				}
			}
		}
	}
}
