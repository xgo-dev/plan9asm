package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86GoCallerLogicalOriginalZeroLiterals(t *testing.T) {
	for _, literal := range []struct{ name, word string }{
		{"VXORPS", "0xc057f8c5"}, {"VPXOR", "0xc0eff9c5"},
	} {
		t.Run(literal.name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", "LONG $"+literal.word+"\nVMOVSS X0,(DX)", 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestX86GoCallerLogicalCompleteFamilyInitializedForms(t *testing.T) {
	for _, op := range x86LogicalOpcodeNames() {
		spec := x86PackedLogicalSpecs[op]
		for _, row := range x86LogicalAcceptedForms(op, "amd64") {
			if strings.Contains(row, "M7") {
				continue
			} // No private MMX bank.
			t.Run(row, func(t *testing.T) {
				row = strings.NewReplacer("(AX)", "(DI)", "X15", "X2", "X31", "X2", "Y31", "Y2", "Z31", "Z2").Replace(row)
				instruction := strings.Split(row, " ")[1]
				operands := strings.Split(instruction, ",")
				destination := operands[len(operands)-1]
				index := destination[1:]
				init := fmt.Sprintf("VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (DI),Z%s\nKMOVQ AX,K1\nKMOVQ AX,K7\n", index)
				// Legacy destructive destinations must be initialized just as
				// masked merge destinations; register spelling grants nothing.
				if spec.encoding <= x86PackedLogicalLegacyInteger && destination == "X2" {
					init += "VMOVUPS (SI),Z2\n"
				}
				body := init + row + "\nVMOVSS X" + index + ",(DX)"
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

func TestX86GoCallerLogicalRetainsUnknownSourceAndEnvelopeFailures(t *testing.T) {
	for name, body := range map[string]string{
		"unknown source":                  "VANDPS X0,X1,X2\nVMOVSS X2,(DX)",
		"unknown destructive destination": "VMOVUPS (DI),X0\nANDPS X0,X1\nVMOVSS X1,(DX)",
		"masked unknown merge":            "KMOVQ AX,K1\nVXORPS X0,X0,K1,X2\nVMOVSS X2,(DX)",
		"unknown mask":                    "VXORPS.Z X0,X0,K1,X2\nVMOVSS X2,(DX)",
		"mask from pointer":               "KMOVQ DI,K1\nVXORPS.Z X0,X0,K1,X2\nVMOVSS X2,(DX)",
		"private stack":                   "VXORPS 0(SP),X0,X0\nVMOVSS X0,(DX)",
		"unknown address":                 "VXORPS (BX),X0,X0\nVMOVSS X0,(DX)",
		"FP pointer bits":                 "VXORPS a+0(FP),X0,X0\nVMOVSS X0,(DX)",
		"length full vector":              "VMOVUPS (DI),X0\nVPAND (CX),X0,X0\nVMOVSS X0,(DX)",
		"oversized broadcast":             "VMOVUPS (DI),X0\nVANDPD.BCST (DX),X0,X0\nVMOVSS X0,(DX)",
		"source data write":               "VXORPS X0,X0,X0\nVMOVSS X0,(DI)",
		"wide result":                     "VXORPS Y0,Y0,Y0\nVMOVUPS Y0,(DX)",
		"CFG undefined join":              "CMPQ AX,$0\nJE joined\nVXORPS X0,X0,X0\njoined:\nVORPS X0,X0,X1\nVMOVSS X1,(DX)",
		"legacy undefined other input":    "XORPS X0,X0\nVORPS Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"MMX zero cannot borrow Z0":       "PXOR M0,M0\nVMOVSS X0,(DX)",
		"MMX memory bank":                 "PAND (DI),M0\nMOVQ M0,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved logical value/region passed: %v", err)
			}
		})
	}
}

func TestX86GoCallerLogicalByteAvailabilityMatchesPhysicalEncoding(t *testing.T) {
	for _, op := range x86LogicalOpcodeNames() {
		spec := x86PackedLogicalSpecs[op]
		for _, width := range []int{16, 32, 64} {
			if spec.encoding <= x86PackedLogicalLegacyInteger && width != 16 || spec.encoding == x86PackedLogicalVEX && width == 64 {
				continue
			}
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			for _, maskMode := range []string{"none", "merge", "zero"} {
				if maskMode != "none" && spec.broadcastBytes == 0 {
					continue
				}
				for _, zeroIdiom := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%d/%s/zero=%v", op, width, maskMode, zeroIdiom), func(t *testing.T) {
						row := string(op) + " " + bank + "0," + bank + "1"
						if zeroIdiom {
							row = string(op) + " " + bank + "0," + bank + "0"
						}
						if spec.encoding > x86PackedLogicalLegacyInteger {
							if maskMode != "none" {
								row += ",K1"
							}
							row += "," + bank + "2"
							if maskMode == "zero" {
								row = strings.Replace(row, string(op), string(op)+".Z", 1)
							}
						}
						file, err := Parse(ArchAMD64, "TEXT one(SB),$0-0\n"+row+"\nRET\n")
						if err != nil {
							t.Fatal(err)
						}
						ins := file.Funcs[0].Instrs[1]
						form, _, err := x86PackedLogicalProperties(ins, "amd64")
						if err != nil {
							t.Fatal(err)
						}
						state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": 0x0f, "Z1": 0x07, "Z2": 0x05}, masks: map[Reg]bool{"K1": true}}
						if !x86CallerPackedLogicalStep(&ins, form, &state, nil) {
							t.Fatal("register effect rejected")
						}
						known := uint64(0x07)
						if zeroIdiom {
							known = 0x0f
							if strings.Contains(string(op), "XOR") || strings.Contains(string(op), "ANDN") {
								known = x86CallerVectorByteMask(int64(width))
							}
						}
						dest := "Z2"
						if form.legacy {
							dest = "Z1"
							if zeroIdiom {
								dest = "Z0"
							}
						} else {
							if maskMode == "merge" {
								known &= 0x05
							}
							known |= ^x86CallerVectorByteMask(int64(width))
						}
						if state.vectors[Reg(dest)] != known {
							t.Fatalf("defined bytes %#x want %#x", state.vectors[Reg(dest)], known)
						}
					})
				}
			}
		}
	}
}

func TestX86GoCallerLogicalReadCertificatesRetainExactSource(t *testing.T) {
	for _, row := range []string{"VPXOR (DI),X0,X1", "VANDPD.BCST (DI),Z0,K1,Z1"} {
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", "VMOVUPS (SI),Z0\nVMOVUPS (SI),Z1\nKMOVQ AX,K1\n"+row+"\nVMOVSS X1,(DX)", 1)
		pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
		resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
		sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := normalizeX86RawFile(file, "amd64", Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, instruction := range normalized.Funcs[0].Instrs {
			form, recognized, err := x86PackedLogicalProperties(instruction, "amd64")
			if !recognized || err != nil || form.memory < 0 {
				continue
			}
			index := form.memory
			access, exists := instruction.x86CallerMemory[index]
			if !exists || access.write || access.width != int64(form.memoryBytes) || !x86CallerMemoryCertified(instruction, index) {
				t.Fatal("missing exact read certificate")
			}
			found = true
			for _, change := range []string{"opcode", "suffix", "width", "mask", "address", "source", "direction", "address-size"} {
				mutated := instruction
				mutated.Args = append([]Operand(nil), instruction.Args...)
				mutated.x86CallerMemory = map[int]x86CallerMemoryAccess{index: access}
				switch change {
				case "opcode":
					mutated.Op = "VANDPS"
				case "suffix":
					mutated.Op = Op(string(mutated.Op) + ".Z")
				case "width":
					access.width++
					mutated.x86CallerMemory[index] = access
				case "mask":
					if form.mask >= 0 {
						mutated.Args[form.mask].Reg = "K2"
					} else {
						mutated.Args = append(mutated.Args, Operand{Kind: OpReg, Reg: "K2"})
					}
				case "address":
					mutated.Args[index].Mem.Off++
				case "source":
					mutated.Args[1].Reg = "X4"
				case "direction":
					access.write = true
					mutated.x86CallerMemory[index] = access
				case "address-size":
					mutated.x86AddressBits = 32
				}
				if x86CallerMemoryCertified(mutated, index) {
					t.Fatalf("%s retained stale read certificate: %s", row, change)
				}
			}
		}
		if !found {
			t.Fatal("logical source never acquired its independent actual read certificate")
		}
	}
}
