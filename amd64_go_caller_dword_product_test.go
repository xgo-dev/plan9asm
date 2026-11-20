package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86GoCallerDwordProductIndependentSourceEffect(t *testing.T) {
	for _, row := range []string{"PMULDQ X0,X1", "PMULULQ X0,X1", "VPMULDQ Y0,Y1,Y2", "VPMULUDQ Y0,Y1,Y2"} {
		t.Run(row, func(t *testing.T) {
			result := "X2"
			if !strings.HasPrefix(row, "V") {
				result = "X1"
			}
			body := "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\n" + row + "\nVMOVSS " + result + ",(DX)"
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestX86GoCallerDwordProductCompleteMaskBroadcastAndMemoryForms(t *testing.T) {
	rows := []string{"PMULDQ X0,X1", "PMULDQ X1,X1", "PMULDQ (DI),X1", "PMULULQ X0,X1", "PMULULQ X1,X1", "PMULULQ (DI),X1"}
	for _, name := range x86DwordProductOracleNames[2:] {
		for _, row := range x86OfficialPackedBinaryWitnesses(t)[name] {
			rows = append(rows, strings.Replace(row, "(AX)", "(DI)", 1))
		}
	}
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			result := "X2"
			if !strings.HasPrefix(row, "V") {
				result = "X1"
			}
			body := "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (SI),Z2\nMOVL $1,AX\nKMOVQ AX,K1\n" + row + "\nVMOVSS " + result + ",(DX)"
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
				if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
					t.Fatal("complete signed/unsigned family caller failed", row, triple, err)
				}
			}
		})
	}
}

func TestX86GoCallerDwordProductEveryPotentialByteAndUpperAliases(t *testing.T) {
	for _, row := range []string{"PMULDQ X0,X1", "PMULULQ X0,X1", "VPMULDQ X0,X1,X2", "VPMULUDQ Y0,Y1,Y2", "VPMULDQ Z0,Z1,K1,Z2", "VPMULUDQ.Z Z0,Z1,K1,Z2"} {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		form, _, err := x86DwordProductProperties(ins.Op, ins, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		for _, missing := range []Reg{"Z0", "Z1", "Z2"} {
			for index := 0; index < 64; index++ {
				t.Run(fmt.Sprintf("%s/missing%s/byte%d", row, missing, index), func(t *testing.T) {
					state := &x86SourceStackState{vectors: map[Reg]uint64{"Z0": ^uint64(0), "Z1": ^uint64(0), "Z2": ^uint64(0)}, masks: map[Reg]bool{"K1": true}}
					state.vectors[missing] &^= uint64(1) << uint(index)
					old := state.vectors[x86CallerVectorRoot(ins.Args[form.destination].Reg)]
					if !x86CallerDwordProductStep(&ins, form, state, nil) {
						t.Fatal("register-only numerical effect failed")
					}
					var want uint64
					for output := 0; output < 64; output++ {
						known := true
						if output >= form.byteWidth {
							known = !form.legacy || old&(uint64(1)<<uint(output)) != 0
						} else {
							start := output / 8 * 8
							// Independent reference: output qword j depends only
							// on bytes 8j..8j+3 of each input, never 8j+4..8j+7.
							if missing == "Z0" || missing == "Z1" {
								known = index < start || index >= start+4
							}
							if form.mask >= 0 && !form.zeroing && missing == x86CallerVectorRoot(ins.Args[form.destination].Reg) && index == output {
								known = false
							}
						}
						if known {
							want |= uint64(1) << uint(output)
						}
					}
					if got := state.vectors[x86CallerVectorRoot(ins.Args[form.destination].Reg)]; got != want {
						t.Fatalf("potential input/merge/upper byte lost: got=%016x want=%016x", got, want)
					}
				})
			}
		}
	}
}

func TestX86GoCallerDwordProductExactMemoryCertificates(t *testing.T) {
	for _, row := range []string{"PMULDQ (DI),X0", "PMULULQ (DI),X0", "VPMULDQ (DI),Y0,Y2", "VPMULUDQ.Z (DI),Z0,K1,Z2", "VPMULDQ.BCST.Z (DI),Z0,K1,Z2", "VPMULUDQ.BCST (DI),X0,X2"} {
		result := "X2"
		if !strings.HasPrefix(row, "V") {
			result = "X0"
		}
		body := "VMOVUPS (SI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\n" + row + "\nVMOVSS " + result + ",(DX)"
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
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
		for _, ins := range normalized.Funcs[0].Instrs {
			form, known, err := x86DwordProductProperties(ins.Op, ins, "amd64")
			if !known || err != nil || form.memory < 0 {
				continue
			}
			found = true
			index := form.memory
			access, exists := ins.x86CallerMemory[index]
			wantWidth := form.byteWidth
			if strings.Contains(row, ".BCST") {
				wantWidth = 8
			}
			if !exists || access.width != int64(wantWidth) || access.write || !x86CallerMemoryCertified(ins, index) {
				t.Fatal("zero mask/selected dwords shrank native envelope", row, access)
			}
			for _, mutation := range []string{"opcode", "width", "direction", "address", "destination", "mask", "address size"} {
				changed := ins
				changedAccess := access
				changed.Args = append([]Operand(nil), ins.Args...)
				changed.x86CallerMemory = map[int]x86CallerMemoryAccess{index: access}
				switch mutation {
				case "opcode":
					changed.Op = "VPMULDQ"
					if strings.Contains(row, "PMULDQ") {
						changed.Op = "VPMULUDQ"
					}
				case "width":
					changedAccess.width--
					changed.x86CallerMemory[index] = changedAccess
				case "direction":
					changedAccess.write = true
					changed.x86CallerMemory[index] = changedAccess
				case "address":
					changed.Args[index].Mem.Off++
				case "destination":
					changed.Args[form.destination].Reg = "X7"
				case "mask":
					if form.mask >= 0 {
						changed.Args[form.mask].Reg = "K7"
					} else {
						changed.Args = append(changed.Args, Operand{Kind: OpReg, Reg: "K7"})
					}
				case "address size":
					changed.x86AddressBits = 32
				}
				if x86CallerMemoryCertified(changed, index) {
					t.Fatal("stale native read certificate survived", row, mutation)
				}
			}
		}
		if !found {
			t.Fatal("normalized source omitted dword product", row)
		}
	}
}

func TestX86GoCallerDwordProductUnprovedInputsAndGuardsRemainContext(t *testing.T) {
	for name, body := range map[string]string{
		"unknown first":        "VMOVUPS (DI),Y1\nVPMULDQ Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"unknown second":       "VMOVUPS (DI),Y0\nVPMULUDQ Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"partial even dword":   "MOVSS (DI),X3\nMOVSS X3,X0\nVMOVUPS (SI),Z1\nVPMULDQ Z0,Z1,Z2\nVEXTRACTF128 $1,Y2,X3\nVMOVSS X3,(DX)",
		"unknown mask":         "VMOVUPS (DI),Z0\nVPMULDQ.Z Z0,Z0,K1,Z2\nVMOVSS X2,(DX)",
		"unknown merge":        "VMOVUPS (DI),Z0\nKMOVQ AX,K1\nVPMULUDQ Z0,Z0,K1,Z2\nVMOVSS X2,(DX)",
		"pointer mask":         "VMOVUPS (DI),Z0\nKMOVQ DI,K1\nVPMULDQ.Z Z0,Z0,K1,Z2\nVMOVSS X2,(DX)",
		"zero mask full tuple": "VMOVUPS (DI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\nVPMULDQ.Z (DX),Z0,K1,Z2\nVMOVSS X2,(DX)",
		"broadcast full qword": "VMOVUPS (DI),Z0\nVPMULUDQ.BCST (DX),Z0,Z2\nVMOVSS X2,(DX)",
		"unknown address":      "VMOVUPS (DI),Z0\nVPMULDQ (BX),Z0,Z2\nVMOVSS X2,(DX)",
		"private SP":           "VMOVUPS (DI),Z0\nVPMULDQ (SP),Z0,Z2\nVMOVSS X2,(DX)",
		"SP alias":             "VMOVUPS (DI),Z0\nMOVQ SP,BX\nPMULDQ (BX),X0\nVMOVSS X0,(DX)",
		"BP alias":             "VMOVUPS (DI),Z0\nMOVQ BP,BX\nPMULULQ (BX),X0\nVMOVSS X0,(DX)",
		"g use":                "VMOVUPS (DI),Z0\nVPMULDQ (R14),Z0,Z2\nVMOVSS X2,(DX)",
		"input write":          "VMOVUPS (DI),Z0\nVPMULDQ Z0,Z0,Z2\nVMOVSS X2,(DI)",
		"MMX caller":           "PMULULQ M0,M1\nVMOVSS X1,(DX)",
		"unknown CFG join":     "VMOVUPS (DI),Y0\nCMPQ AX,$0\nJE joined\nVMOVUPS (SI),Y1\njoined:\nVPMULDQ Y0,Y1,Y2\nVMOVSS X2,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unproved input/native/caller guard acquired permission", err)
			}
		})
	}
}

func TestX86GoCallerDwordProductRawTuplesBindNativeReadWidths(t *testing.T) {
	for _, name := range []string{"VPMULDQ", "VPMULUDQ"} {
		for _, width := range []int{16, 32, 64} {
			for _, broadcast := range []bool{false, true} {
				op, tuple := name, width
				if broadcast {
					op, tuple = name+".BCST", 8
				}
				bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
				for _, offset := range []int{-tuple, 64 - tuple, 64} {
					row := fmt.Sprintf("%s %d(DI),%s1,K1,%s2", op, offset, bank, bank)
					t.Run(row, func(t *testing.T) {
						original := x86OrderingHintGoBytes(t, "amd64", "TEXT original(SB),4,$0-0\n"+row+"\nRET\n")
						body := "VMOVUPS (SI),Z1\nVMOVUPS (SI),Z2\nMOVQ $1,AX\nKMOVQ AX,K1\n" + x86DwordProductDirectives(original[:len(original)-1]) + "VMOVSS X2,(DX)"
						assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
						goAssemblerOracleOutput(t, "amd64", assembly, "", true)
						pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
						if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
							t.Fatal("original raw tuple lost existing readonly slice role", row, err)
						}
						// The input is a dynamic slice role, not an observed fixed
						// 64-byte allocation. Certify only the exact possible native
						// instruction read, preserving native faulting addresses.
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
						for _, ins := range normalized.Funcs[0].Instrs {
							form, known, err := x86DwordProductProperties(ins.Op, ins, "amd64")
							if !known || err != nil {
								continue
							}
							found = true
							access, ok := ins.x86CallerMemory[0]
							if !ins.x86Encoded || form.memory != 0 || ins.Args[0].Mem.Base != DI || ins.Args[0].Mem.Off != int64(offset) || !ok || access.width != int64(tuple) || access.write || !x86CallerMemoryCertified(ins, 0) {
								t.Fatal("raw source tuple/address/native-width certificate drift", row, ins, access)
							}
						}
						if !found {
							t.Fatal("original raw source omitted from normalized proof", row)
						}
						// Conversely the fresh result is a real bounded four-byte
						// region: no full-vector or m64bcst read fits this role.
						boundedRow := strings.Replace(row, "(DI)", "(DX)", 1)
						bounded := x86OrderingHintGoBytes(t, "amd64", "TEXT original(SB),4,$0-0\n"+boundedRow+"\nRET\n")
						boundedBody := strings.Replace(body, x86DwordProductDirectives(original[:len(original)-1]), x86DwordProductDirectives(bounded[:len(bounded)-1]), 1)
						boundedAssembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", boundedBody, 1)
						boundedPkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, boundedAssembly)
						if err := x86CallerCoreTranslate(t, boundedPkg, boundedAssembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("actual raw tuple gained bounded result-object permission", boundedRow, err)
						}
					})
				}
			}
		}
	}
}
