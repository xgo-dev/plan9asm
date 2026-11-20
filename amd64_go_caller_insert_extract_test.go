package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86GoCallerInsertExtractOriginalSourceReachesObjects(t *testing.T) {
	for _, body := range []string{
		"VMOVUPS (DI),Y0\nLONG $0x197de3c4\nWORD $0x01c1\nVMOVSS X1,(DX)",
		"VMOVUPS (DI),Z0\nVEXTRACTF64X4 $1,Z0,Y1\nVMOVSS X1,(DX)",
		"VMOVUPS (DI),Y0\nVMOVUPS (SI),X1\nVINSERTF128 $1,X1,Y0,Y2\nVMOVSS X2,(DX)",
		"VMOVUPS (DI),X0\nVEXTRACTPS $3,X0,AX\nMOVL AX,(DX)",
		"VMOVUPS (DI),X0\nVMOVUPS (SI),X1\nVINSERTPS $64,X1,X0,X2\nVMOVSS X2,(DX)",
	} {
		t.Run(strings.Split(body, "\n")[1], func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestX86GoCallerInsertExtractWholeFamilyByteKnowledge(t *testing.T) {
	for _, row := range x86InsertExtractFormats() {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		f, recognized, err := x86InsertExtractProperties(ins, "amd64")
		if !recognized || err != nil {
			t.Fatal(err)
		}
		if f.memory >= 0 {
			continue
		}
		if f.spec.scalar && !f.spec.insert {
			continue // full typed scalar-state coverage is exercised via public API below
		}
		for _, missing := range []int{-1, 0, 7, 15, 16, 31, 32, 63} {
			state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": ^uint64(0), "Z1": ^uint64(0), "Z2": ^uint64(0)}, masks: map[Reg]bool{"K1": true}}
			if missing >= 0 {
				state.vectors[x86CallerVectorRoot(ins.Args[f.source].Reg)] &^= uint64(1) << uint(missing)
			}
			accepted := x86CallerInsertExtractStep(&ins, f, &state, nil)
			if !f.spec.insert {
				want := missing < f.offset || missing >= f.offset+f.output
				if accepted != want {
					t.Fatalf("%s missing source byte %d: %t want %t", row, missing, accepted, want)
				}
			} else if !f.spec.scalar && accepted != (missing < 0 || missing >= f.spec.chunk) {
				t.Fatalf("%s missing insertion byte %d: %t", row, missing, accepted)
			}
		}
	}
	for _, row := range []string{"VEXTRACTF128 $1,Y1,X0", "VINSERTI128 $1,X0,Y1,Y2", "VINSERTPS $0,X0,X1,X2"} {
		file, _ := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		ins := file.Funcs[0].Instrs[1]
		f, _, _ := x86InsertExtractProperties(ins, "amd64")
		state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": 0xffff, "Z1": ^uint64(0), "Z2": 0}, masks: map[Reg]bool{}}
		if !x86CallerInsertExtractStep(&ins, f, &state, nil) || state.vectors[x86CallerVectorRoot(ins.Args[f.destination].Reg)] != ^uint64(0) {
			t.Fatalf("complete inputs did not establish physical upper-zero: %s", row)
		}
	}
}

func TestX86GoCallerInsertExtractAllOpcodesAndUnknownPermissions(t *testing.T) {
	for _, row := range x86InsertExtractFormats() {
		row = strings.Replace(row, "(BX)", "(DI)", 1)
		file, _ := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		ins := file.Funcs[0].Instrs[1]
		f, _, _ := x86InsertExtractProperties(ins, "amd64")
		if f.memoryWrite {
			continue // caller's scalar result is only four bytes, not vector output
		}
		store := fmt.Sprintf("VMOVSS X%d,(DX)", ins.Args[f.destination].Reg[len(ins.Args[f.destination].Reg)-1]-'0')
		if f.spec.scalar && !f.spec.insert {
			store = "MOVL AX,(DX)"
		}
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (SI),Z2\nKMOVQ AX,K1\n"+row+"\n"+store, 1)
		goAssemblerOracleOutput(t, "amd64", assembly, "", true)
		pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
		if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
			t.Fatalf("%s: %v", row, err)
		}
	}
	for name, body := range map[string]string{
		"unknown selected extract":         "VEXTRACTF128 $1,Y0,X1\nVMOVSS X1,(DX)",
		"unknown inserted bytes":           "VMOVUPS (DI),Y1\nVINSERTF128 $1,X0,Y1,Y2\nVEXTRACTF128 $1,Y2,X2\nVMOVSS X2,(DX)",
		"uninitialized retained base":      "VMOVUPS (DI),X0\nVINSERTI128 $1,X0,Y1,Y2\nVMOVSS X2,(DX)",
		"unknown mask":                     "VMOVUPS (DI),Z0\nVEXTRACTI32X4.Z $0,Z0,K1,X1\nVMOVSS X1,(DX)",
		"unknown masked merge destination": "VMOVUPS (DI),Z0\nKMOVQ AX,K1\nVEXTRACTF32X4 $0,Z0,K1,X1\nVMOVSS X1,(DX)",
		"pointer FP not numerical":         "VMOVUPS (DI),Y1\nVINSERTF128 $0,a+0(FP),Y1,Y2\nVMOVSS X2,(DX)",
		"unknown memory even zero mask":    "VMOVUPS (DI),Z1\nMOVQ $0,AX\nKMOVQ AX,K1\nVINSERTF32X4.Z $0,(BX),Z1,K1,Z2\nVMOVSS X2,(DX)",
		"read source SP":                   "VMOVUPS (DI),Y1\nVINSERTI128 $0,(SP),Y1,Y2\nVMOVSS X2,(DX)",
		"source length too narrow":         "VMOVUPS (DI),Y1\nVINSERTF128 $0,(CX),Y1,Y2\nVMOVSS X2,(DX)",
		"write input":                      "VMOVUPS (DI),X0\nVEXTRACTPS $0,X0,(DI)",
		"write g":                          "VMOVUPS (DI),X0\nVEXTRACTPS $0,X0,R14",
		"CFG incomplete":                   "CMPQ AX,$0\nJE join\nVMOVUPS (DI),Y0\njoin:\nVEXTRACTF128 $1,Y0,X1\nVMOVSS X1,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unknown source permission invented: %v", err)
			}
		})
	}
}
