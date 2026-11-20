package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86GoCallerVectorMovesFreshScalarResults(t *testing.T) {
	for _, width := range []struct {
		suffix, typ string
	}{{"SS", "float32"}, {"SD", "float64"}} {
		legacy, vector := "MOV"+width.suffix, "VMOV"+width.suffix
		for _, form := range []struct {
			name, body string
		}{
			{name: "legacy load/copy/store", body: fmt.Sprintf("%s (DI),X0\n%s X0,X1\n%s X1,(DX)", legacy, legacy, legacy)},
			{name: "vector load/merge/store", body: fmt.Sprintf("%s (DI),X0\n%s X0,X0,X1\n%s X1,(DX)", vector, vector, vector)},
			{name: "masked load zero", body: fmt.Sprintf("KMOVW AX,K1\n%s.Z (DI),K1,X0\n%s X0,(DX)", vector, vector)},
			{name: "masked store", body: fmt.Sprintf("KMOVW AX,K1\n%s (DI),X0\n%s X0,K1,(DX)", vector, vector)},
			{name: "masked merge", body: fmt.Sprintf("KMOVW AX,K1\n%s (DI),X0\n%s (SI),X1\n%s (DI),X2\n%s X0,X1,K1,X2\n%s X2,(DX)", vector, vector, vector, vector, vector)},
			{name: "masked merge zero", body: fmt.Sprintf("KMOVW AX,K1\n%s (DI),X0\n%s (SI),X1\n%s.Z X0,X1,K1,X2\n%s X2,(DX)", vector, vector, vector, vector)},
			{name: "extended vector register", body: fmt.Sprintf("%s (DI),X31\n%s X31,(DX)", vector, vector)},
			{name: "complete numeric overwrite", body: fmt.Sprintf("%s X0,X1,X2\n%s (DI),X2\n%s X2,(DX)", vector, vector, vector)},
		} {
			for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
				t.Run(width.suffix+"/"+form.name+"/"+triple, func(t *testing.T) {
					source := strings.ReplaceAll(x86CallerFixtureSource, "float32", width.typ)
					assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", form.body, 1)
					requireX86GoAssemblerResult(t, "amd64", assembly, true)
					pkg, _ := x86CallerCoreFixture(t, source, assembly)
					if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestX86GoCallerMaskMovesAllWidthsAndDirections(t *testing.T) {
	for _, width := range []struct{ suffix, typ, move string }{
		{"B", "uint8", "MOVB"}, {"W", "uint16", "MOVW"},
		{"D", "uint32", "MOVL"}, {"Q", "uint64", "MOVQ"},
	} {
		maskMove := "KMOV" + width.suffix
		for _, form := range []struct{ name, body string }{
			{"GP to mask to memory", maskMove + " AX,K1\n" + maskMove + " K1,(DX)"},
			{"input to mask to memory", maskMove + " (DI),K1\n" + maskMove + " K1,(DX)"},
			{"length to mask to memory", maskMove + " (CX),K1\n" + maskMove + " K1,(DX)"},
			{"mask copy to memory", maskMove + " AX,K1\n" + maskMove + " K1,K2\n" + maskMove + " K2,(DX)"},
			{"mask to GP to memory", maskMove + " AX,K1\n" + maskMove + " K1,BX\n" + width.move + " BX,(DX)"},
		} {
			t.Run(width.suffix+"/"+form.name, func(t *testing.T) {
				source := strings.ReplaceAll(x86CallerFixtureSource, "float32", width.typ)
				assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", form.body, 1)
				requireX86GoAssemblerResult(t, "amd64", assembly, true)
				pkg, _ := x86CallerCoreFixture(t, source, assembly)
				for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
					if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func TestX86GoCallerVectorMovesDoNotWashPointersOrInventInitializedBytes(t *testing.T) {
	for _, example := range []struct{ name, body, result string }{
		{"unknown mask", "VMOVSS.Z (DI),K1,X0\nVMOVSS X0,(DX)", "float32"},
		{"unknown mask source", "KMOVW BX,K1\nVMOVSS.Z (DI),K1,X0\nVMOVSS X0,(DX)", "float32"},
		{"pointer to mask", "KMOVW DI,K1\nVMOVSS.Z (DI),K1,X0\nVMOVSS X0,(DX)", "float32"},
		{"fixed g to mask", "KMOVQ R14,K1\nKMOVQ K1,(DX)", "uint64"},
		{"mask to fixed g", "KMOVW AX,K1\nKMOVQ K1,R14\nMOVL AX,(DX)", "float32"},
		{"mask to SP", "KMOVW AX,K1\nKMOVQ K1,SP\nMOVL AX,(DX)", "float32"},
		{"mask to BP", "KMOVW AX,K1\nKMOVQ K1,BP\nMOVL AX,(DX)", "float32"},
		{"mask replaces input pointer", "KMOVW AX,K1\nKMOVQ K1,DI\nVMOVSS (DI),X0\nVMOVSS X0,(DX)", "float32"},
		{"GP pointer as vector data", "MOVQ DI,X0\nMOVSD X0,(DX)", "float64"},
		{"private SP as vector data", "MOVQ SP,X0\nMOVSD X0,(DX)", "float64"},
		{"fixed g as vector data", "MOVQ R14,X0\nMOVSD X0,(DX)", "float64"},
		{"FP pointer as vector data", "MOVSD a+0(FP),X0\nMOVSD X0,(DX)", "float64"},
		{"saved BP as vector data", "MOVSD 0(SP),X0\nMOVSD X0,(DX)", "float64"},
		{"unknown vector bytes", "VMOVSS X0,(DX)", "float32"},
		{"unknown low source", "VMOVSS (DI),X0\nVMOVSS X1,X0,X2\nVMOVSS X2,(DX)", "float32"},
		{"legacy unknown upper bytes", "MOVSS (DI),X0\nMOVSS X0,X1\nMOVSD X1,(DX)", "float64"},
		{"masked merge unknown destination", "KMOVW AX,K1\nVMOVSS (DI),X0\nVMOVSS (SI),X1\nVMOVSS X0,X1,K1,X2\nVMOVSS X2,(DX)", "float32"},
		{"wide result", "VMOVSD (DI),X0\nVMOVSD X0,(DX)", "float32"},
		{"result one byte overlap", "VMOVSS (DI),X0\nVMOVSS X0,1(DX)", "float32"},
		{"result negative offset", "VMOVSS (DI),X0\nVMOVSS X0,-1(DX)", "float32"},
		{"result indexed", "VMOVSS (DI),X0\nVMOVSS X0,(DX)(AX*1)", "float32"},
		{"input write", "VMOVSS (DI),X0\nVMOVSS X0,(DI)", "float32"},
		{"length write", "VMOVSS (DI),X0\nVMOVSS X0,(CX)", "float32"},
		{"unknown input base", "VMOVSS (BX),X0\nVMOVSS X0,(DX)", "float32"},
		{"mask input write", "KMOVW AX,K1\nKMOVW K1,(DI)", "uint16"},
		{"mask wide result", "KMOVQ AX,K1\nKMOVQ K1,(DX)", "uint32"},
		{"literal result one byte overlap", "MOVSS $1.25,X0\nMOVSS X0,1(DX)", "float32"},
		{"literal unknown mask", "VMOVSS.Z $1.25,K1,X0\nVMOVSS X0,(DX)", "float32"},
		{"literal mask from pointer", "KMOVW DI,K1\nVMOVSS.Z $1.25,K1,X0\nVMOVSS X0,(DX)", "float32"},
	} {
		t.Run(example.name, func(t *testing.T) {
			source := strings.ReplaceAll(x86CallerFixtureSource, "float32", example.result)
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", example.body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, source, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved vector/mask state acquired raw-RET continuation: %v", err)
			}
		})
	}
}

func TestX86GoCallerVectorMemoryCertificatesBindMaskWidthAndEveryOperand(t *testing.T) {
	for _, body := range []string{
		"KMOVW AX,K1\nVMOVSS (DI),X0\nVMOVSS X0,K1,(DX)",
		"KMOVD AX,K1\nKMOVD K1,(DX)",
	} {
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
		pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
		resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
		sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}
		normalized, err := normalizeX86RawFile(file, "amd64", options)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, instruction := range normalized.Funcs[0].Instrs {
			for index, access := range instruction.x86CallerMemory {
				if !access.write || !x86CallerMemoryCertified(instruction, index) {
					continue
				}
				found = true
				for _, change := range []string{"opcode", "source", "address", "address-bits", "width", "direction", "mask"} {
					mutated := instruction
					mutated.Args = append([]Operand(nil), instruction.Args...)
					mutated.x86CallerMemory = map[int]x86CallerMemoryAccess{index: access}
					switch change {
					case "opcode":
						mutated.Op = "VMOVSD"
					case "source":
						mutated.Args[0].Reg = "X3"
					case "address":
						mutated.Args[index].Mem.Off++
					case "address-bits":
						mutated.x86AddressBits = 32
					case "width":
						access.width++
						mutated.x86CallerMemory[index] = access
					case "direction":
						access.write = false
						mutated.x86CallerMemory[index] = access
					case "mask":
						if len(mutated.Args) != 3 {
							continue
						}
						mutated.Args[1].Reg = "K2"
					}
					if x86CallerMemoryCertified(mutated, index) {
						t.Fatalf("%s borrowed a %s memory certificate", change, instruction.Op)
					}
				}
			}
		}
		if !found {
			t.Fatal("fixture produced no complete vector/mask write certificate")
		}
	}
}
