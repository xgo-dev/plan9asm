package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86GoCallerWordMultiplyCompleteForms(t *testing.T) {
	for _, name := range x86WordMultiplyNames {
		banks := []string{"X"}
		if strings.HasPrefix(name, "V") {
			banks = append(banks, "Y", "Z")
		}
		for _, bank := range banks {
			for _, first := range []string{bank + "0", "(DI)"} {
				for _, mode := range []int{0, 1, 2} {
					if !strings.HasPrefix(name, "V") && mode != 0 {
						continue
					}
					opcode, args, result := name, first+","+bank+"1", "X1"
					if strings.HasPrefix(name, "V") {
						args, result = first+","+bank+"1", "X2"
						if mode != 0 {
							args += ",K1"
						}
						if mode == 2 {
							opcode += ".Z"
						}
						args += "," + bank + "2"
					}
					row := opcode + " " + args
					body := "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (SI),Z2\nMOVL $1,AX\nKMOVQ AX,K1\n" + row + "\nVMOVSS " + result + ",(DX)"
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
		}
	}
}

func TestX86GoCallerWordMultiplyUnknownAndMemoryPermissionsRemainContext(t *testing.T) {
	for name, body := range map[string]string{
		"unknown first":          "VMOVUPS (DI),Z1\nVPMULLW Z0,Z1,Z2\nVMOVSS X2,(DX)",
		"unknown second":         "VMOVUPS (DI),Z0\nVPMULHW Z0,Z1,Z2\nVMOVSS X2,(DX)",
		"partial source":         "MOVSS (DI),X0\nVMOVUPS (SI),Z1\nVPMULHUW Z0,Z1,Z2\nVEXTRACTF128 $1,Y2,X3\nVMOVSS X3,(DX)",
		"unknown mask":           "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVPMULHRSW.Z Z0,Z1,K1,Z2\nVMOVSS X2,(DX)",
		"unknown merge":          "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nMOVL $1,AX\nKMOVQ AX,K1\nVPMULHW Z0,Z1,K1,Z2\nVMOVSS X2,(DX)",
		"pointer mask":           "VMOVUPS (DI),Z0\nKMOVQ DI,K1\nVPMULLW.Z Z0,Z0,K1,Z2\nVMOVSS X2,(DX)",
		"zero mask lacks region": "VMOVUPS (DI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\nVPMULHW.Z (DX),Z0,K1,Z2\nVMOVSS X2,(DX)",
		"unknown address":        "VMOVUPS (DI),Z0\nVPMULHUW (BX),Z0,Z2\nVMOVSS X2,(DX)",
		"stack alias":            "VMOVUPS (DI),Z0\nMOVQ SP,BX\nPMULLW (BX),X0\nVMOVSS X0,(DX)",
		"BP alias":               "VMOVUPS (DI),Z0\nMOVQ BP,BX\nPMULHW (BX),X0\nVMOVSS X0,(DX)",
		"input write":            "VMOVUPS (DI),Z0\nVPMULHRSW Z0,Z0,Z2\nVMOVSS X2,(DI)",
		"MMX separate bank":      "PMULLW M0,M1\nVMOVSS X1,(DX)",
		"join missing second":    "VMOVUPS (DI),Z0\nCMPQ AX,$0\nJE joined\nVMOVUPS (SI),Z1\njoined:\nVPMULHW Z0,Z1,Z2\nVMOVSS X2,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unproved word multiply acquired caller permission", err)
			}
		})
	}
}

func TestX86GoCallerWordMultiplyFullReadCertificatesAndByteAliases(t *testing.T) {
	names := append(append([]string(nil), x86WordMultiplyNames...), "PMULLD", "VPMULLD", "VPMULLQ")
	for _, name := range names {
		row, result := name+" (DI),X0", "X0"
		if strings.HasPrefix(name, "V") {
			row, result = name+".Z (DI),Z0,K1,Z2", "X2"
		}
		body := "VMOVUPS (SI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\n" + row + "\nVMOVSS " + result + ",(DX)"
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
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
			form, known, err := x86LowAndWordMultiplyTestForm(ins)
			if !known || err != nil || form.memory < 0 {
				continue
			}
			found = true
			access, exists := ins.x86CallerMemory[form.memory]
			if !exists || access.width != int64(form.memoryBytes) || access.write || !x86CallerMemoryCertified(ins, form.memory) {
				t.Fatal("zero mask shrank the independent possible read envelope")
			}
			for _, change := range []string{"op", "base", "width", "direction", "destination", "mask", "address size"} {
				mutated := ins
				mutated.Args = append([]Operand(nil), ins.Args...)
				mutated.x86CallerMemory = map[int]x86CallerMemoryAccess{form.memory: access}
				switch change {
				case "op":
					mutated.Op = "MOVOU"
				case "base":
					mutated.Args[form.memory].Mem.Base = BX
				case "width":
					access.width--
					mutated.x86CallerMemory[form.memory] = access
				case "direction":
					access.write = true
					mutated.x86CallerMemory[form.memory] = access
				case "destination":
					mutated.Args[form.destination].Reg = "X7"
				case "mask":
					mutated.Args = append(mutated.Args, Operand{Kind: OpReg, Reg: "K7"})
				case "address size":
					mutated.x86AddressBits = 32
				}
				if x86CallerMemoryCertified(mutated, form.memory) {
					t.Fatal("stale original instruction memory certificate survived", change)
				}
			}
		}
		if !found {
			t.Fatal("no multiply memory proof")
		}
	}
	for _, name := range names {
		operands := "X0,X1"
		if strings.HasPrefix(name, "V") {
			operands = "X0,X1,X2"
		}
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+name+" "+operands+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		form, _, err := x86LowAndWordMultiplyTestForm(ins)
		if err != nil {
			t.Fatal(err)
		}
		state := &x86SourceStackState{vectors: map[Reg]uint64{"Z0": 0xfffd, "Z1": 0xffff}, masks: map[Reg]bool{}}
		if !x86CallerVectorMoveStep(&ins, state, nil) {
			t.Fatal("registered pure vector effect missing")
		}
		want := uint64(0xfffc) // One absent source byte kills its whole word.
		if name == "PMULLD" || name == "VPMULLD" {
			want = 0xfff0
		} else if name == "VPMULLQ" {
			want = 0xff00
		}
		if !form.legacy {
			want |= ^uint64(0xffff)
		}
		if got := state.vectors[x86CallerVectorRoot(ins.Args[form.destination].Reg)]; got != want {
			t.Fatal(fmt.Sprintf("incorrect word-byte/upper alias transfer %s got=%x want=%x", name, got, want))
		}
	}
}

func x86LowAndWordMultiplyTestForm(ins Instr) (x86PackedBinaryForm, bool, error) {
	if form, known, err := x86PackedLowMultiplyProperties(ins.Op, ins, "amd64"); known {
		return form.x86PackedBinaryForm, known, err
	}
	form, known, err := x86PackedWordMultiplyProperties(ins.Op, ins, "amd64")
	return form.x86PackedBinaryForm, known, err
}
