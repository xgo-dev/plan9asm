package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestX86GoCallerWordMultiplyAddOriginalRawEffect(t *testing.T) {
	// This is the unchanged raw instruction from Weaviate's dot_byte_256.
	// The independent fixture supplies actual typed, complete selected callers;
	// it does not borrow the external function's unclosed pointer loop.
	body := "VMOVDQU (DI),Y2\nVMOVDQU (SI),Y4\nLONG $0xd4f5edc5\nVMOVSS X2,(DX)"
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
		t.Fatal(err)
	}
}

func TestX86GoCallerWordMultiplyAddOriginalFollowingAddEffect(t *testing.T) {
	// Consecutive unchanged LONGs from dot_byte_avx256.s. Each arithmetic
	// family now has its separate complete typed caller effect.
	body := "VMOVDQU (DI),Y2\nVMOVDQU (SI),Y4\nVPXOR Y0,Y0,Y0\nLONG $0xd4f5edc5\nLONG $0xc0feedc5\nVMOVSS X0,(DX)"
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
		t.Fatal(err)
	}
}

func TestX86GoCallerWordMultiplyAddCompleteActualSourceConsumers(t *testing.T) {
	rows := []string{"PMADDWL X0,X1", "PMADDWL X1,X1", "PMADDWL (DI),X1"}
	for _, bank := range []string{"X", "Y", "Z"} {
		for _, first := range []string{bank + "0", "(DI)"} {
			rows = append(rows,
				"VPMADDWD "+first+","+bank+"1,"+bank+"2",
				"VPMADDWD "+first+","+bank+"1,K1,"+bank+"2",
				"VPMADDWD.Z "+first+","+bank+"1,K1,"+bank+"2")
		}
	}
	for _, row := range rows {
		t.Run(row, func(t *testing.T) {
			result := "X2"
			if strings.HasPrefix(row, "PMADDWL") {
				result = "X1"
			}
			body := "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (DI),Z2\nMOVL $1,AX\nKMOVQ AX,K1\n" + row + "\nVMOVSS " + result + ",(DX)"
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
				if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
					t.Fatalf("actual typed caller %s: %v", triple, err)
				}
			}
		})
	}
}

func TestX86GoCallerWordMultiplyAddRetainsUnknownSourceFailures(t *testing.T) {
	for name, body := range map[string]string{
		"unknown first":       "VMOVUPS (DI),Y1\nVPMADDWD Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"unknown second":      "VMOVUPS (DI),Y0\nVPMADDWD Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"unknown upper pairs": "MOVSS (DI),X0\nMOVSS (SI),X1\nVPMADDWD Y0,Y1,Y2\nVEXTRACTF128 $1,Y2,X3\nVMOVSS X3,(DX)",
		"unknown mask":        "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVPMADDWD.Z Z0,Z1,K1,Z2\nVMOVSS X2,(DX)",
		"unknown merge":       "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nKMOVQ AX,K1\nVPMADDWD Z0,Z1,K1,Z2\nVMOVSS X2,(DX)",
		"pointer mask":        "VMOVUPS (DI),Z0\nKMOVQ DI,K1\nVPMADDWD.Z Z0,Z0,K1,Z2\nVMOVSS X2,(DX)",
		"zero mask full read": "VMOVUPS (DI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\nVPMADDWD.Z (DX),Z0,K1,Z2\nVMOVSS X2,(DX)",
		"unknown address":     "VMOVUPS (DI),Z0\nVPMADDWD (BX),Z0,Z2\nVMOVSS X2,(DX)",
		"private stack":       "VMOVUPS (DI),Z0\nVPMADDWD (SP),Z0,Z2\nVMOVSS X2,(DX)",
		"legacy SP alias":     "VMOVUPS (DI),Z0\nMOVQ SP,BX\nPMADDWL (BX),X0\nVMOVSS X0,(DX)",
		"legacy BP alias":     "VMOVUPS (DI),Z0\nMOVQ BP,BX\nPMADDWL (BX),X0\nVMOVSS X0,(DX)",
		"input write":         "VMOVUPS (DI),Z0\nVPMADDWD Z0,Z0,Z2\nVMOVSS X2,(DI)",
		"MMX separate bank":   "PMADDWL M0,M1\nVMOVSS X1,(DX)",
		"undefined branch":    "VMOVUPS (DI),Z0\nCMPQ AX,$0\nJE joined\nVMOVUPS (SI),Z1\njoined:\nVPMADDWD Z0,Z1,Z2\nVMOVSS X2,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved packed multiply-add became caller permission: %v", err)
			}
		})
	}
}

func TestX86GoCallerWordMultiplyAddMemoryCertificatesRetainExactFullRead(t *testing.T) {
	for _, row := range []string{"PMADDWL (DI),X0", "VPMADDWD.Z (DI),Z0,K1,Z2", "PMADDUBSW (DI),X0", "VPMADDUBSW.Z (DI),Z0,K1,Z2"} {
		body := "VMOVUPS (SI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\n" + row + "\nVMOVSS X2,(DX)"
		if strings.HasPrefix(row, "PMADD") {
			body = strings.Replace(body, "VMOVSS X2", "VMOVSS X0", 1)
		}
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
			form, recognized, err := x86PackedMultiplyAddProperties(ins.Op, ins, "amd64")
			if !recognized || err != nil || form.memory < 0 {
				continue
			}
			found = true
			index := form.memory
			access, exists := ins.x86CallerMemory[index]
			if !exists || access.write || access.width != int64(form.memoryBytes) || !x86CallerMemoryCertified(ins, index) {
				t.Fatal("original legacy or zero-mask E4NF lost exact native full-read witness")
			}
			for _, change := range []string{"opcode", "width", "address", "destination", "direction", "mask", "address size"} {
				mutated := ins
				mutated.Args = append([]Operand(nil), ins.Args...)
				mutated.x86CallerMemory = map[int]x86CallerMemoryAccess{index: access}
				switch change {
				case "opcode":
					mutated.Op = "VPMADDUBSW"
					if strings.Contains(row, "UBSW") {
						mutated.Op = "VPMADDWD"
					}
				case "width":
					access.width--
					mutated.x86CallerMemory[index] = access
				case "address":
					mutated.Args[index].Mem.Off++
				case "destination":
					mutated.Args[form.destination].Reg = "X7"
				case "direction":
					access.write = true
					mutated.x86CallerMemory[index] = access
				case "mask":
					if form.mask >= 0 {
						mutated.Args[form.mask].Reg = "K7"
					} else {
						mutated.Args = append(mutated.Args, Operand{Kind: OpReg, Reg: "K1"})
					}
				case "address size":
					mutated.x86AddressBits = 32
				}
				if x86CallerMemoryCertified(mutated, index) {
					t.Fatalf("%s stale %s native read permission survived", row, change)
				}
			}
		}
		if !found {
			t.Fatal("normalized source omitted actual multiply-add")
		}
	}
}
