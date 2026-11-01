package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86GoCallerPackedNarrowUnknownValuesAndRegionsRemainContext(t *testing.T) {
	for name, body := range map[string]string{
		"unknown second":           "VMOVUPS (DI),Z0\nVPACKSSDW Z0,Z1,Z2\nVMOVSS X2,(DX)",
		"unknown first high half":  "VMOVUPS (SI),Z1\nVPACKSSDW X0,X1,X2\nVPSRLDQ $8,X2,X3\nVMOVSS X3,(DX)",
		"partial second":           "MOVSS (DI),X3\nMOVSS X3,X1\nVMOVUPS (SI),Z0\nVPACKSSDW X0,X1,X2\nVMOVSS X2,(DX)",
		"unknown mask":             "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVPACKUSWB.Z Z0,Z1,K1,Z2\nVMOVSS X2,(DX)",
		"unknown merge":            "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nMOVL $1,AX\nKMOVQ AX,K1\nVPACKSSWB Z0,Z1,K1,Z2\nVMOVSS X2,(DX)",
		"pointer mask":             "VMOVUPS (DI),Z0\nKMOVQ DI,K1\nVPACKUSDW.Z Z0,Z0,K1,Z2\nVMOVSS X2,(DX)",
		"zero mask full tuple":     "VMOVUPS (DI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\nVPACKSSDW.Z (DX),Z0,K1,Z2\nVMOVSS X2,(DX)",
		"zero mask broadcast span": "VMOVUPS (DI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\nVPACKUSDW.BCST.Z 1(DX),Z0,K1,Z2\nVMOVSS X2,(DX)",
		"unknown address":          "VMOVUPS (DI),Z0\nVPACKUSWB (BX),Z0,Z2\nVMOVSS X2,(DX)",
		"stack alias":              "VMOVUPS (DI),Z0\nMOVQ SP,BX\nPACKSSWB (BX),X0\nVMOVSS X0,(DX)",
		"BP alias":                 "VMOVUPS (DI),Z0\nMOVQ BP,BX\nPACKUSWB (BX),X0\nVMOVSS X0,(DX)",
		"input write":              "VMOVUPS (DI),Z0\nVPACKSSDW Z0,Z0,Z2\nVMOVSS X2,(DI)",
		"MMX separate bank":        "PACKSSLW M0,M1\nVMOVSS X1,(DX)",
		"join missing second":      "VMOVUPS (DI),Z0\nCMPQ AX,$0\nJE joined\nVMOVUPS (SI),Z1\njoined:\nVPACKSSDW Z0,Z1,Z2\nVMOVSS X2,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unproved PACK acquired caller permission", err)
			}
		})
	}
	// The first input contributes only the high half of each 128-bit chunk.
	// Unknown unused bytes must not forbid this initialized low-half write.
	body := "VMOVUPS (SI),Z1\nVPACKSSDW Z0,Z1,Z2\nVMOVSS X2,(DX)"
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
		t.Fatal("independent initialized low half was lost", err)
	}
}

func TestX86GoCallerPackedNarrowFullReadCertificateIdentity(t *testing.T) {
	for _, name := range []string{"PACKSSLW", "PACKSSWB", "PACKUSDW", "PACKUSWB",
		"VPACKSSDW", "VPACKSSWB", "VPACKUSDW", "VPACKUSWB"} {
		banks := []string{"X"}
		if strings.HasPrefix(name, "V") {
			banks = append(banks, "Y", "Z")
		}
		for index, bank := range banks {
			broadcasts := []bool{false}
			if name == "VPACKSSDW" || name == "VPACKUSDW" {
				broadcasts = append(broadcasts, true)
			}
			for _, broadcast := range broadcasts {
				row, result, width := name+" (DI),X0", "X0", int64(16<<index)
				if strings.HasPrefix(name, "V") {
					suffix := ".Z"
					if broadcast {
						suffix, width = ".BCST.Z", 4
					}
					row, result = name+suffix+" (DI),"+bank+"0,K1,"+bank+"2", "X2"
				}
				t.Run(row, func(t *testing.T) {
					body := "VMOVUPS (SI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\n" + row + "\nVMOVSS " + result + ",(DX)"
					assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
					goAssemblerOracleOutput(t, "amd64", assembly, "", true)
					pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
					resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
					sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					normalized, err := normalizeX86RawFile(file, "amd64", Options{Goarch: "amd64", ResolveSym: resolve, Sigs: sigs})
					if err != nil {
						t.Fatal(err)
					}
					found := false
					for _, ins := range normalized.Funcs[0].Instrs {
						form, known, err := x86PackedNarrowProperties(ins, "amd64")
						if !known || err != nil || form.memory < 0 {
							continue
						}
						found = true
						access, present := ins.x86CallerMemory[form.memory]
						if !present || access.width != width || access.write || !x86CallerMemoryCertified(ins, form.memory) {
							t.Fatal("zero mask shrank the independent complete memory envelope", width)
						}
						for _, change := range []string{"op", "base", "offset", "width", "direction", "destination", "mask", "address size"} {
							mutated := ins
							mutated.Args = append([]Operand(nil), ins.Args...)
							mutated.x86CallerMemory = map[int]x86CallerMemoryAccess{form.memory: access}
							switch change {
							case "op":
								mutated.Op = "MOVOU"
							case "base":
								mutated.Args[form.memory].Mem.Base = BX
							case "offset":
								mutated.Args[form.memory].Mem.Off++
							case "width":
								changed := access
								changed.width--
								mutated.x86CallerMemory[form.memory] = changed
							case "direction":
								changed := access
								changed.write = true
								mutated.x86CallerMemory[form.memory] = changed
							case "destination":
								mutated.Args[form.destination].Reg = "X7"
							case "mask":
								if form.mask >= 0 {
									mutated.Args[form.mask].Reg = "K7"
								} else {
									mutated.Args = append(mutated.Args, Operand{Kind: OpReg, Reg: "K7"})
								}
							case "address size":
								mutated.x86AddressBits = 32
							}
							if x86CallerMemoryCertified(mutated, form.memory) {
								t.Fatal(fmt.Sprintf("stale complete instruction certificate survived %s", change))
							}
						}
					}
					if !found {
						t.Fatal("actual PACK memory proof absent")
					}
				})
			}
		}
	}
}
