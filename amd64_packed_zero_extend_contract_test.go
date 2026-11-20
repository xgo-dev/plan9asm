package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86PackedZeroExtendDispatchIdentityBeforeEmission(t *testing.T) {
	for _, ratio := range x86ZeroExtendTestRatios {
		for _, prefix := range []string{"P", "VP"} {
			opcode := prefix + "MOVZX" + ratio.suffix
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+opcode+" X0,X1\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			for _, identity := range []Op{"", Op(opcode), Op(strings.ToLower(opcode)), "PMOVSXBW", "VPMOVZXBW.Z"} {
				ins := file.Funcs[0].Instrs[1]
				ins.Op = identity
				ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
				before := output.String()
				known, term, err := ctx.lowerPackedExtendMove(Op(opcode), ins)
				conflict := identity != "" && !strings.EqualFold(string(identity), opcode)
				if !known || term || (err != nil) != conflict || conflict && output.String() != before {
					t.Fatalf("dispatch %s/%s: known=%t term=%t err=%v", opcode, identity, known, term, err)
				}
			}
		}
	}
}

func TestX86PackedZeroExtendFPBytesBindActualGoDeclaration(t *testing.T) {
	for _, ratio := range x86ZeroExtendTestRatios {
		for _, prefix := range []string{"P", "VP"} {
			for _, bank := range []string{"X", "Y", "Z"} {
				if prefix == "P" && bank != "X" {
					continue
				}
				width := map[string]int{"X": 16, "Y": 32, "Z": 64}[bank] * ratio.input / ratio.output
				for _, layout := range []string{"complete", "last byte absent", "alignment hole"} {
					var parameters []string
					for i := 0; i < width; i++ {
						if layout == "last byte absent" && i == width-1 {
							continue
						}
						if layout == "alignment hole" && i >= 1 {
							parameters = append(parameters, fmt.Sprintf("a%d uint64", i))
						} else {
							parameters = append(parameters, fmt.Sprintf("a%d byte", i))
						}
					}
					fset := token.NewFileSet()
					declaration, err := parser.ParseFile(fset, "decl.go", "package bound\nfunc f("+strings.Join(parameters, ",")+")\n", 0)
					if err != nil {
						t.Fatal(err)
					}
					typed, err := (&types.Config{Sizes: types.SizesFor("gc", "amd64")}).Check("bound", fset, []*ast.File{declaration}, nil)
					if err != nil {
						t.Fatal(err)
					}
					row := prefix + "MOVZX" + ratio.suffix + " a0+0(FP)," + bank + "1"
					params := typed.Scope().Lookup("f").Type().(*types.Signature).Params()
					var fields []*types.Var
					for i := 0; i < params.Len(); i++ {
						fields = append(fields, params.At(i))
					}
					sizes := types.SizesFor("gc", "amd64")
					offsets := sizes.Offsetsof(fields)
					end := offsets[len(offsets)-1] + sizes.Sizeof(fields[len(fields)-1].Type())
					allocation := (end + 7) &^ 7 // Actual ABI0 word-aligned scalar allocation.
					assembly := fmt.Sprintf("TEXT f(SB),4,$0-%d\n%s\nRET\n", allocation, row)
					if layout == "complete" {
						requireX86GoAssemblerResult(t, "amd64", assembly, true)
					}
					ctx := llvm.NewContext()
					bound, err := translateGoModuleInContext(ctx, GoPackage{Path: "bound", Types: typed, Syntax: []*ast.File{declaration}}, []byte(assembly), GoModuleOptions{GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu"})
					if bound != nil {
						bound.Module.Dispose()
					}
					ctx.Dispose()
					if (err != nil) != (layout != "complete") {
						t.Fatalf("%s/%s ignored actual Go field layout: %v", row, layout, err)
					}
				}
			}
		}
	}
}

func TestX86PackedZeroExtendEveryDeclaredFPByteBeforeEmission(t *testing.T) {
	for _, ratio := range x86ZeroExtendTestRatios {
		for _, prefix := range []string{"P", "VP"} {
			for _, row := range x86ZeroExtendAcceptedForms(prefix+"MOVZX"+ratio.suffix, "amd64") {
				if !strings.Contains(row, "8(AX)") {
					continue
				}
				row = strings.Replace(row, "8(AX)", "a+1(FP)", 1)
				file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-64\n"+row+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				ins := file.Funcs[0].Instrs[1]
				form, _, err := x86PackedZeroExtendProperties(ins, "amd64")
				if err != nil {
					t.Fatal(err)
				}
				for missing := -1; missing < form.memoryBytes; missing++ {
					sig := FuncSig{Name: "f", Ret: Void}
					for i := 0; i < form.memoryBytes; i++ {
						if i != missing {
							sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: int64(i + 1), Type: I8, Index: len(sig.Args), Field: -1})
							sig.Args = append(sig.Args, I8)
						}
					}
					ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], sig, nil)
					before := output.String()
					known, term, err := ctx.lowerPackedExtendMove(ins.Op, ins)
					if !known || term || (err != nil) != (missing >= 0) || missing >= 0 && output.String() != before {
						t.Fatalf("%s missing byte %d emitted/accepted undeclared FP bytes: %v", row, missing, err)
					}
				}
			}
		}
	}
}

func TestX86GoCallerPackedZeroExtendMemoryCertificatesBindNativeSource(t *testing.T) {
	for _, ratio := range x86ZeroExtendTestRatios {
		for _, prefix := range []string{"P", "VP"} {
			for _, original := range x86ZeroExtendAcceptedForms(prefix+"MOVZX"+ratio.suffix, "amd64") {
				if !strings.Contains(original, "8(AX)") {
					continue
				}
				row := strings.NewReplacer("8(AX)", "8(DI)", "X15", "X2", "X31", "X2", "Y31", "Y2", "Z31", "Z2").Replace(original)
				assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", "VMOVUPS (SI),Z2\nKMOVQ AX,K1\nKMOVQ AX,K7\n"+row+"\nVMOVSS X2,(DX)", 1)
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
					form, recognized, err := x86PackedZeroExtendProperties(ins, "amd64")
					if !recognized || err != nil || form.memory < 0 {
						continue
					}
					found = true
					index := form.memory
					access, exists := ins.x86CallerMemory[index]
					if !exists || access.write || access.width != int64(form.memoryBytes) || !x86CallerMemoryCertified(ins, index) {
						t.Fatalf("%s lacks its exact shrinking native read certificate", row)
					}
					for _, change := range []string{"opcode", "width", "address", "index", "destination", "direction", "mask", "address-bits"} {
						mutated := ins
						mutated.Args = append([]Operand(nil), ins.Args...)
						mutated.x86CallerMemory = map[int]x86CallerMemoryAccess{index: access}
						switch change {
						case "opcode":
							mutated.Op = "VPMOVSXBD"
						case "width":
							access.width++
							mutated.x86CallerMemory[index] = access
						case "address":
							mutated.Args[index].Mem.Off++
						case "index":
							mutated.Args[index].Mem.Index, mutated.Args[index].Mem.Scale = BX, 4
						case "destination":
							mutated.Args[form.destination].Reg = "X3"
						case "direction":
							access.write = true
							mutated.x86CallerMemory[index] = access
						case "mask":
							if form.mask >= 0 {
								mutated.Args[form.mask].Reg = "K2"
							} else {
								mutated.Args = append(mutated.Args, Operand{Kind: OpReg, Reg: "K2"})
							}
						case "address-bits":
							mutated.x86AddressBits = 32
						}
						if x86CallerMemoryCertified(mutated, index) {
							t.Fatalf("%s mutation retained %s source certificate", change, row)
						}
					}
				}
				if !found {
					t.Fatal("no widening source instruction consumed its caller certificate")
				}
			}
		}
	}
}

func TestX86PackedZeroExtendInvalidMemoryAndMaskGrammar(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []string{
			"VPMOVZXBD (AX)(SP*1),X1", "VPMOVZXBD (AX)(CX*3),X1",
			"VPMOVZXBD $glob(SB),X1", "VPMOVZXBD X0,K0,X1",
			"VPMOVZXBD.SAE X0,X1", "VPMOVZXBD.RN_SAE X0,X1",
			"VPMOVZXBD. X0,X1", "PMOVZXBD X0,K1,X1",
		} {
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				continue
			}
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			ctx.goarch = arch
			before := output.String()
			ins := file.Funcs[0].Instrs[1]
			known, term, err := ctx.lowerPackedExtendMove(ins.Op, ins)
			if !known || term || err == nil || output.String() != before {
				t.Fatalf("%s/%s emitted invalid grammar: %v", arch, row, err)
			}
		}
	}
	// A full signed displacement must not silently wrap in native amd64.
	for _, off := range []int64{1 << 31, -1<<31 - 1, 1 << 32} {
		ins := Instr{Op: "VPMOVZXBD", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: AX, Off: off}}, {Kind: OpReg, Reg: "X1"}}}
		if _, recognized, err := x86PackedZeroExtendProperties(ins, "amd64"); !recognized || err == nil {
			t.Fatalf("out-of-range native displacement %d accepted", off)
		}
	}
	for _, scale := range []int64{1, 2, 4, 8} {
		row := fmt.Sprintf("VPMOVZXBD 3(AX)(CX*%d),X1", scale)
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := x86PackedZeroExtendProperties(file.Funcs[0].Instrs[1], "amd64"); err != nil {
			t.Fatal(row, err)
		}
	}
}
