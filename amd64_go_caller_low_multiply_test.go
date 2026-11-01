package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86GoCallerLowMultiplyUnknownInputsRemainContext(t *testing.T) {
	for _, name := range []string{"VPMULLD", "VPMULLQ"} {
		for reason, body := range map[string]string{
			"unknown first":          "VMOVUPS (DI),Z1\n%s Z0,Z1,Z2\nVMOVSS X2,(DX)",
			"unknown second":         "VMOVUPS (DI),Z0\n%s Z0,Z1,Z2\nVMOVSS X2,(DX)",
			"partial source":         "MOVSS (DI),X0\nVMOVUPS (SI),Z1\n%s Z0,Z1,Z2\nVEXTRACTF128 $1,Y2,X3\nVMOVSS X3,(DX)",
			"unknown mask":           "VMOVUPS (DI),Z0\n%s.Z Z0,Z0,K1,Z2\nVMOVSS X2,(DX)",
			"unknown merge":          "VMOVUPS (DI),Z0\nMOVL $1,AX\nKMOVQ AX,K1\n%s Z0,Z0,K1,Z2\nVMOVSS X2,(DX)",
			"pointer mask":           "VMOVUPS (DI),Z0\nKMOVQ DI,K1\n%s.Z Z0,Z0,K1,Z2\nVMOVSS X2,(DX)",
			"zero mask lacks region": "VMOVUPS (DI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\n%s.Z (DX),Z0,K1,Z2\nVMOVSS X2,(DX)",
			"unknown address":        "VMOVUPS (DI),Z0\n%s (BX),Z0,Z2\nVMOVSS X2,(DX)",
			"input write":            "VMOVUPS (DI),Z0\n%s Z0,Z0,Z2\nVMOVSS X2,(DI)",
			"join missing second":    "VMOVUPS (DI),Z0\nCMPQ AX,$0\nJE joined\nVMOVUPS (SI),Z1\njoined:\n%s Z0,Z1,Z2\nVMOVSS X2,(DX)",
		} {
			t.Run(name+"/"+reason, func(t *testing.T) {
				assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", fmt.Sprintf(body, name), 1)
				goAssemblerOracleOutput(t, "amd64", assembly, "", true)
				pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
				if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("low product acquired unproved input/caller memory", err)
				}
			})
		}
	}
}

// Keep this independent of the external package which exposed the missing
// source-stack effect. The original Go caller owns every input/result region.
func TestX86GoCallerLowMultiplyCompleteForms(t *testing.T) {
	for _, name := range []string{"PMULLW", "VPMULLW", "PMULLD", "VPMULLD", "VPMULLQ"} {
		banks := []string{"X"}
		vector := strings.HasPrefix(name, "V")
		if vector {
			banks = append(banks, "Y", "Z")
		}
		for _, bank := range banks {
			for _, memory := range []bool{false, true} {
				for _, broadcast := range []bool{false, true} {
					if broadcast && (!memory || !vector || strings.HasSuffix(name, "W")) {
						continue
					}
					for mode := 0; mode < 3; mode++ {
						if !vector && mode != 0 {
							continue
						}
						first, opcode := bank+"0", name
						if memory {
							first = "(DI)"
						}
						if broadcast {
							opcode += ".BCST"
						}
						args, result := first+","+bank+"1", "X1"
						if vector {
							if mode != 0 {
								args += ",K1"
							}
							if mode == 2 {
								opcode += ".Z"
							}
							args += "," + bank + "2"
							result = "X2"
						}
						row := opcode + " " + args
						t.Run(row, func(t *testing.T) {
							body := fmt.Sprintf("VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (SI),Z2\nMOVL $1,AX\nKMOVQ AX,K1\n%s\nVMOVSS %s,(DX)", row, result)
							assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
							goAssemblerOracleOutput(t, "amd64", assembly, "", true)
							pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
							for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
								if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
									t.Fatal(err)
								}
							}
						})
					}
				}
			}
		}
	}
}
