package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86GoCallerSADOriginalRawEffect(t *testing.T) {
	// Unchanged instruction from Weaviate v1.39.6 hamming_avx256_amd64.s:77.
	// The independent fixture binds its own complete selected typed callers;
	// it does not borrow the external kernel's unresolved loop/frame contract.
	body := "VMOVDQU (DI),Y2\nVMOVDQU (SI),Y5\nLONG $0xeaf6d5c5\nVMOVSS X5,(DX)"
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
		t.Fatal(err)
	}
}

func TestX86GoCallerSADCompleteMemoryMaskAndAliasForms(t *testing.T) {
	for _, row := range x86SADRows("amd64") {
		// This caller fixture binds ordinary slice data, not arbitrary SB or
		// segment sources. Those accepted table forms have separate objects.
		if strings.Contains(row, "(FS)") || strings.Contains(row, "(GS)") || strings.Contains(row, "(SB)") {
			continue
		}
		// Rebind only register/address tokens, never the immediate selector.
		row = strings.NewReplacer(
			"16(AX)(BX*2)", "(DI)", "(AX)", "(DI)",
			"X15", "X2", "Y15", "Y2", "Z15", "Z2",
			"X31", "X1", "Y31", "Y1", "Z31", "Z1",
			"X30", "X2", "Y30", "Y2", "Z30", "Z2",
			"X7", "X2", "Y7", "Y2", "Z7", "Z2",
		).Replace(row)
		args := strings.Split(strings.SplitN(row, " ", 2)[1], ",")
		index := args[len(args)-1][1:]
		body := "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (DI),Z2\nMOVL $1,AX\nKMOVQ AX,K1\nKMOVQ AX,K7\n" + row + "\nVMOVSS X" + index + ",(DX)"
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
		t.Run(row, func(t *testing.T) {
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

func TestX86GoCallerSADMemoryCertificatesBindCompleteInstruction(t *testing.T) {
	for _, row := range []string{"PSADBW (DI),X0", "MPSADBW $5,(DI),X0", "VPSADBW (DI),Y0,Y2", "VMPSADBW $37,(DI),Y0,Y2", "VDBPSADBW.Z $228,(DI),Z0,K1,Z2"} {
		body := "VMOVUPS (SI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\n" + row + "\nVMOVSS X2,(DX)"
		if !strings.HasPrefix(row, "V") {
			body = strings.Replace(body, "VMOVSS X2", "VMOVSS X0", 1)
		}
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
		goAssemblerOracleOutput(t, "amd64", assembly, "", true)
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
			form, known, err := x86PackedSADProperties(ins, "amd64")
			if !known || err != nil || form.memory < 0 {
				continue
			}
			found = true
			access, exists := ins.x86CallerMemory[form.memory]
			if !exists || access.write || access.width != int64(form.memoryBytes) || !x86CallerMemoryCertified(ins, form.memory) {
				t.Fatal("SAD lost its exact native full-read witness")
			}
			for _, change := range []string{"opcode", "immediate", "width", "address", "destination", "direction", "mask", "address size"} {
				mutated := ins
				mutated.Args = append([]Operand(nil), ins.Args...)
				mutated.x86CallerMemory = map[int]x86CallerMemoryAccess{form.memory: access}
				switch change {
				case "opcode":
					mutated.Op = "VPMADDUBSW"
				case "immediate":
					if form.spec.kind != amd64PackedSADBlockSum {
						mutated.Args[0].Imm++
					} else {
						mutated.Args = append([]Operand{{Kind: OpImm, Imm: 1}}, mutated.Args...)
					}
				case "width":
					access.width--
					mutated.x86CallerMemory[form.memory] = access
				case "address":
					mutated.Args[form.memory].Mem.Off++
				case "destination":
					mutated.Args[form.destination].Reg = "X7"
				case "direction":
					access.write = true
					mutated.x86CallerMemory[form.memory] = access
				case "mask":
					if form.mask >= 0 {
						mutated.Args[form.mask].Reg = "K7"
					} else {
						mutated.Args = append(mutated.Args, Operand{Kind: OpReg, Reg: "K1"})
					}
				case "address size":
					mutated.x86AddressBits = 32
				}
				if x86CallerMemoryCertified(mutated, form.memory) {
					t.Fatalf("%s stale %s permission survived", row, change)
				}
			}
		}
		if !found {
			t.Fatal("no consumed SAD memory instruction")
		}
	}
}

func TestX86GoCallerSADRetainsUnprovedSourcesAndEnvelopes(t *testing.T) {
	for name, body := range map[string]string{
		"unknown first":       "VMOVUPS (DI),Y1\nVPSADBW Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"unknown second":      "VMOVUPS (DI),Y0\nVPSADBW Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"unknown legacy":      "MOVUPS (DI),X0\nMPSADBW $5,X0,X1\nVMOVSS X1,(DX)",
		"unknown upper":       "MOVUPS (DI),X0\nMOVUPS (SI),X1\nVPSADBW Y0,Y1,Y2\nVEXTRACTF128 $1,Y2,X3\nVMOVSS X3,(DX)",
		"unknown mask":        "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVDBPSADBW.Z $228,Z0,Z1,K1,Z2\nVMOVSS X2,(DX)",
		"unknown merge":       "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nKMOVQ AX,K1\nVDBPSADBW $228,Z0,Z1,K1,Z2\nVMOVSS X2,(DX)",
		"pointer mask":        "VMOVUPS (DI),Z0\nKMOVQ DI,K1\nVDBPSADBW.Z $228,Z0,Z0,K1,Z2\nVMOVSS X2,(DX)",
		"zero mask full read": "VMOVUPS (DI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\nVDBPSADBW.Z $0,(DX),Z0,K1,Z2\nVMOVSS X2,(DX)",
		"selected full read":  "VMOVUPS (DI),X0\nMPSADBW $0,(CX),X0\nVMOVSS X0,(DX)",
		"unknown address":     "VMOVUPS (DI),Y0\nVPSADBW (BX),Y0,Y1\nVMOVSS X1,(DX)",
		"private SP":          "VMOVUPS (DI),X0\nPSADBW (SP),X0\nVMOVSS X0,(DX)",
		"private alias":       "VMOVUPS (DI),X0\nMOVQ BP,BX\nMPSADBW $0,(BX),X0\nVMOVSS X0,(DX)",
		"input write":         "VMOVUPS (DI),X0\nPSADBW X0,X0\nVMOVSS X0,(DI)",
		"undefined join":      "VMOVUPS (DI),Y0\nCMPQ AX,$0\nJE joined\nVMOVUPS (SI),Y1\njoined:\nVPSADBW Y0,Y1,Y2\nVMOVSS X2,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("SAD became unproved source permission: %v", err)
			}
		})
	}
}

func TestX86GoCallerSADIndependentByteDependencies(t *testing.T) {
	// All selectors and widths are compared to perturbations of an independent
	// numeric reference, not expectations generated by the production masks.
	for _, kind := range []string{"PSADBW", "MPSADBW", "VDBPSADBW"} {
		for _, width := range []int{16, 32, 64} {
			if kind == "MPSADBW" && width == 64 {
				continue
			}
			for control := 0; control < 256; control++ {
				form := x86PackedSADForm{spec: amd64PackedSADSpecs[Op(kind)], immediate: uint8(control)}
				form.byteWidth = width
				for output := 0; output < width; output += 2 {
					var first, second uint64
					for input := 0; input < width; input++ {
						a, b := make([]byte, width), make([]byte, width)
						a[input] = 1
						if x86SADReference(kind, width, control, a, b)[output/2] != 0 {
							first |= uint64(1) << uint(input)
						}
						a[input], b[input] = 0, 1
						if x86SADReference(kind, width, control, a, b)[output/2] != 0 {
							second |= uint64(1) << uint(input)
						}
					}
					a, b := form.wordInputs(output)
					if first != a || second != b {
						t.Fatalf("%s width%d imm%d word%d: %x/%x != %x/%x", kind, width, control, output/2, a, b, first, second)
					}
				}
			}
		}
	}
	for _, row := range []string{"PSADBW X0,X1", "VPSADBW Y0,Y1,Y2", "MPSADBW $5,X0,X1", "VMPSADBW $37,Y0,Y1,Y2", "VDBPSADBW.Z $228,Z0,Z1,K1,Z2"} {
		file, _ := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		ins := file.Funcs[0].Instrs[1]
		form, _, err := x86PackedSADProperties(ins, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		for _, defined := range []uint64{0, 15, 255, 65535, 0xffffffff, ^uint64(0)} {
			state := &x86SourceStackState{vectors: map[Reg]uint64{"Z0": defined, "Z1": defined, "Z2": 0}, masks: map[Reg]bool{"K1": true}}
			if !x86CallerSADStep(&ins, form, state, nil) {
				t.Fatal("register effect failed")
			}
			got := state.vectors[x86CallerVectorRoot(ins.Args[form.destination].Reg)]
			var want uint64
			for output := 0; output < form.byteWidth; output += 2 {
				first, second := form.wordInputs(output)
				if defined&first == first && defined&second == second {
					want |= uint64(3) << uint(output)
				}
			}
			if !form.legacy {
				want |= ^x86CallerVectorByteMask(int64(form.byteWidth))
			} else {
				want |= defined &^ x86CallerVectorByteMask(int64(form.byteWidth))
			}
			if got != want {
				t.Fatal(fmt.Sprintf("ordered %s: %x != %x", row, got, want))
			}
		}
	}
}

func TestX86GoCallerSADCompleteNamedFamily(t *testing.T) {
	for _, row := range []struct {
		instruction string
		result      string
	}{
		{"PSADBW X0,X1", "X1"},
		{"VPSADBW Y0,Y1,Y2", "X2"},
		{"MPSADBW $5,X0,X1", "X1"},
		{"VMPSADBW $37,Y0,Y1,Y2", "X2"},
		{"VDBPSADBW $228,Z0,Z1,K1,Z2", "X2"},
	} {
		t.Run(row.instruction, func(t *testing.T) {
			body := "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (DI),Z2\nMOVL $1,AX\nKMOVQ AX,K1\n" + row.instruction + "\nVMOVSS " + row.result + ",(DX)"
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
