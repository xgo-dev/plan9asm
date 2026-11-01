package plan9asm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86SourceStackNumericalFixture(arch, body string) (string, FuncSig, GoPackage) {
	word, move, typ, llvmType := int64(8), "MOVQ", "uint64", I64
	if arch == "386" {
		word, move, typ, llvmType = 4, "MOVL", "uint32", I32
	}
	return x86SourceStackTypedFixture(arch, typ, llvmType, word, move, body)
}

func x86SourceStackTypedFixture(arch, typ string, llvmType LLVMType, word int64, move, body string) (string, FuncSig, GoPackage) {
	body = strings.NewReplacer("@MOV", move, "@WORD", fmt.Sprint(word), "@RESULT", fmt.Sprint(2*word)).Replace(body)
	source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s\n", 2*word, body)
	sig := FuncSig{Name: "sourceframe.Value", Args: []LLVMType{llvmType}, Ret: llvmType,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: llvmType, Index: 0, Field: -1}},
			Results: []FrameSlot{{Offset: word, Type: llvmType, Index: 0, Field: -1}},
		}}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "value.go", "package sourceframe\nfunc Value(x "+typ+") "+typ+"\nfunc callee()\n", 0)
	if err != nil {
		panic(err)
	}
	pkg, err := (&types.Config{Sizes: types.SizesFor("gc", arch)}).Check("sourceframe", fset, []*ast.File{file}, nil)
	if err != nil {
		panic(err)
	}
	return source, sig, GoPackage{Path: "sourceframe", Types: pkg, Syntax: []*ast.File{file}}
}

func x86SourceStackOptions(arch, triple string, sig FuncSig) Options {
	return Options{Goarch: arch, TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "sourceframe.", 1) },
		Sigs:       map[string]FuncSig{sig.Name: sig},
	}
}

func TestX86RawReturnBoundSourceStackNumerical(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		push, pop, arithmetic, address, align := "PUSHQ", "POPQ", "ADDQ", "LEAQ", 8
		if target.arch == "386" {
			push, pop, arithmetic, address, align = "PUSHL", "POPL", "ADDL", "LEAL", 4
		}
		for _, fixture := range []struct{ name, body string }{
			{"physical", "@MOV @WORD(SP),AX\n" + arithmetic + " $7,AX\n@MOV AX,@RESULT(SP)\nBYTE $0xc3"},
			{"balanced", "@MOV x+0(FP),AX\n" + push + " BP\n@MOV SP,BP\nAND" + strings.TrimPrefix(arithmetic, "ADD") + fmt.Sprintf(" $-%d,SP\n", align) + arithmetic + " $7,AX\n@MOV BP,SP\n" + pop + " BP\n@MOV AX,ret+@WORD(FP)\nBYTE $0xc3"},
			{"nested", "@MOV x+0(FP),AX\n" + push + " BP\n@MOV SP,BP\n" + push + " BX\n" + push + " AX\n" + address + " -2*@WORD(BP),SP\n" + pop + " AX\n" + pop + " BX\n@MOV BP,SP\n" + pop + " BP\n" + arithmetic + " $7,AX\n@MOV AX,ret+@WORD(FP)\nBYTE $0xc3"},
		} {
			t.Run(target.triple+"/"+fixture.name, func(t *testing.T) {
				source, sig, pkg := x86SourceStackNumericalFixture(target.arch, fixture.body)
				requireX86GoAssemblerResult(t, target.arch, source, true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				opt := x86SourceStackOptions(target.arch, target.triple, sig)
				ir, err := Translate(file, opt)
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "source-frame.ll", "source-frame.o", ir)
				ctx := llvm.NewContext()
				module, err := TranslateModuleInContext(ctx, file, opt)
				if err != nil {
					ctx.Dispose()
					t.Fatal(err)
				}
				module.Dispose()
				ctx.Dispose()
				ctx = llvm.NewContext()
				translation, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple})
				if err != nil {
					ctx.Dispose()
					t.Fatal(err)
				}
				translation.Module.Dispose()
				ctx.Dispose()
			})
		}
	}
}

func TestX86RawReturnBoundSourceStackRetainsContext(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		push, pop, sub, align := "PUSHQ", "POPQ", "SUBQ", 16
		if target.arch == "386" {
			push, pop, sub, align = "PUSHL", "POPL", "SUBL", 8
		}
		for _, body := range []string{
			"@MOV @WORD(SP),AX\n@MOV AX,0(SP)\nBYTE $0xc3",
			"@MOV @WORD(SP),AX\n@MOV AX,@WORD-1(SP)\nBYTE $0xc3",
			push + " AX\nBYTE $0xc3",
			push + " BP\n@MOV SP,BP\n" + pop + " AX\nBYTE $0xc3",
			push + " BP\n@MOV SP,BP\nAND" + strings.TrimPrefix(sub, "SUB") + fmt.Sprintf(" $-%d,SP\n", align) + "@MOV BP,SP\n" + pop + " BP\nBYTE $0xc3",
			push + " BP\n@MOV SP,BP\n@MOV BP,AX\n@MOV BP,SP\n" + pop + " BP\nBYTE $0xc3",
			"LEA" + strings.TrimPrefix(sub, "SUB") + " (SP),AX\nBYTE $0xc3",
			"@MOV @WORD(SP),AX\n@MOV AX,(BX)\nBYTE $0xc3",
			"CALL ·callee(SB)\nBYTE $0xc3",
			"@MOV $0,SP\nBYTE $0xc3",
			"CMP" + strings.TrimPrefix(sub, "SUB") + " $0,AX\nJE alternate\n" + push + " AX\nalternate:\nBYTE $0xc3",
		} {
			t.Run(target.triple+"/"+body, func(t *testing.T) {
				source, sig, pkg := x86SourceStackNumericalFixture(target.arch, body)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				opt := x86SourceStackOptions(target.arch, target.triple, sig)
				if _, err := Translate(file, opt); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unproved source continuation became callable: %v", err)
				}
				ctx := llvm.NewContext()
				module, err := TranslateModuleInContext(ctx, file, opt)
				if err == nil {
					module.Dispose()
				}
				ctx.Dispose()
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("module accepted unproved source continuation: %v", err)
				}
				ctx = llvm.NewContext()
				translation, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple})
				if err == nil {
					translation.Module.Dispose()
				}
				ctx.Dispose()
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("declaration API accepted unproved source continuation: %v", err)
				}
			})
		}
	}
}

func TestX86RawReturnBoundSourceStackGoFPProducerOffsets(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word, push, pop, move, rawPush, rawPop := int64(8), "PUSHQ", "POPQ", "MOVQ", "BYTE $0x50", "BYTE $0x59"
		if target.arch == "386" {
			word, push, pop, move = 4, "PUSHL", "POPL", "MOVL"
		}
		for _, test := range []struct {
			name, body string
			accepted   bool
		}{
			{"named FP after named push", push + " CX\n" + move + " x+0(FP),AX\n" + pop + " CX\n" + move + " AX,ret+@WORD(FP)\nBYTE $0xc3", true},
			{"raw push physical shifted argument", rawPush + "\n" + move + " @RESULT(SP),AX\n" + rawPop + "\n" + move + " AX,ret+@WORD(FP)\nBYTE $0xc3", true},
			{"raw push cannot shift Go FP", rawPush + "\n" + move + " x+0(FP),AX\n" + rawPop + "\n" + move + " AX,ret+@WORD(FP)\nBYTE $0xc3", false},
			{"partial scalar access", fmt.Sprintf("MOVB %d(SP),AX\n%s AX,ret+@WORD(FP)\nBYTE $0xc3", word, move), false},
			{"stack index", move + " @WORD(SP)(CX*1),AX\n" + move + " AX,ret+@WORD(FP)\nBYTE $0xc3", false},
			{"original BP is not argument frame", move + " @WORD(BP),AX\n" + move + " AX,ret+@WORD(FP)\nBYTE $0xc3", false},
		} {
			t.Run(target.triple+"/"+test.name, func(t *testing.T) {
				source, sig, pkg := x86SourceStackNumericalFixture(target.arch, test.body)
				requireX86GoAssemblerResult(t, target.arch, source, true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				opt := x86SourceStackOptions(target.arch, target.triple, sig)
				_, err = Translate(file, opt)
				if test.accepted && err != nil || !test.accepted && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("source ABI0 transport accepted=%t: %v", test.accepted, err)
				}
				ctx := llvm.NewContext()
				module, moduleErr := TranslateModuleInContext(ctx, file, opt)
				if moduleErr == nil {
					module.Dispose()
				}
				ctx.Dispose()
				if test.accepted && moduleErr != nil || !test.accepted && !errors.Is(moduleErr, ErrProbeNeedsContext) {
					t.Fatalf("module ABI0 transport accepted=%t: %v", test.accepted, moduleErr)
				}
				ctx = llvm.NewContext()
				translation, bindingErr := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple})
				if bindingErr == nil {
					translation.Module.Dispose()
				}
				ctx.Dispose()
				if test.accepted && bindingErr != nil || !test.accepted && !errors.Is(bindingErr, ErrProbeNeedsContext) {
					t.Fatalf("declaration ABI0 transport accepted=%t: %v", test.accepted, bindingErr)
				}
			})
		}
	}
}

func TestX86RawReturnBoundSourceStackScalarMoveWidths(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range x86RawReturnTargets {
		word, add := int64(8), "ADDQ"
		if target.arch == "386" {
			word, add = 4, "ADDL"
		}
		for _, typ := range []struct {
			goType string
			llvm   LLVMType
			move   string
		}{
			{"bool", I1, "MOVB"},
			{"uint8", I8, "MOVB"}, {"uint16", I16, "MOVW"}, {"uint32", I32, "MOVL"}, {"uint64", I64, "MOVQ"},
		} {
			if target.arch == "386" && typ.llvm == I64 {
				continue // Go's 386 GP ABI transports this value as two slots.
			}
			t.Run(target.triple+"/"+typ.goType, func(t *testing.T) {
				body := "@MOV @WORD(SP),AX\n" + add + " $7,AX\n@MOV AX,@RESULT(SP)\nBYTE $0xc3"
				if typ.llvm == I1 {
					body = "@MOV @WORD(SP),AX\n@MOV AX,@RESULT(SP)\nBYTE $0xc3"
				}
				source, sig, pkg := x86SourceStackTypedFixture(target.arch, typ.goType, typ.llvm, word, typ.move, body)
				requireX86GoAssemblerResult(t, target.arch, source, true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				ir, err := Translate(file, x86SourceStackOptions(target.arch, target.triple, sig))
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "scalar-sp.ll", "scalar-sp.o", ir)
				ctx := llvm.NewContext()
				module, err := TranslateModuleInContext(ctx, file, x86SourceStackOptions(target.arch, target.triple, sig))
				if err != nil {
					ctx.Dispose()
					t.Fatal(err)
				}
				module.Dispose()
				ctx.Dispose()
				ctx = llvm.NewContext()
				translation, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple})
				if err != nil {
					ctx.Dispose()
					t.Fatal(err)
				}
				translation.Module.Dispose()
				ctx.Dispose()
			})
		}
	}
}

func TestX86RawReturnBoundSourceStackDoesNotTrustChangedSignature(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		source, sig, _ := x86SourceStackNumericalFixture(target.arch, "@MOV @WORD(SP),AX\n@MOV AX,@RESULT(SP)\nBYTE $0xc3")
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := NormalizeRawFileForTranslation(file, target.arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, change := range []string{"no frame", "wrong type", "wrong offset", "wrong index", "custom registers", "pointer", "wrong size"} {
			t.Run(target.triple+"/"+change, func(t *testing.T) {
				changed := sig
				changed.Frame.Params = append([]FrameSlot(nil), sig.Frame.Params...)
				changed.Frame.Results = append([]FrameSlot(nil), sig.Frame.Results...)
				changed.Args = append([]LLVMType(nil), sig.Args...)
				switch change {
				case "no frame":
					changed.Frame = FrameLayout{}
				case "wrong type":
					changed.Frame.Params[0].Type = I8
				case "wrong offset":
					changed.Frame.Params[0].Offset = 1
				case "wrong index":
					changed.Frame.Params[0].Index = 1
				case "custom registers":
					changed.ArgRegs = []Reg{AX}
				case "pointer":
					changed.Args[0], changed.Frame.Params[0].Type = Ptr, Ptr
				case "wrong size":
					changed.Frame.Results[0].Offset = 1 << 20
				}
				if _, err := Translate(prepared, x86SourceStackOptions(target.arch, target.triple, changed)); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("prepartition metadata trusted a changed contract: %v", err)
				}
			})
		}
	}
}

func TestX86RawReturnBoundSourceStackFlagsNeedNumericalProvenance(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		suffix, word := "Q", 8
		if target.arch == "386" {
			suffix, word = "L", 4
		}
		start := "@MOV @WORD(SP),AX\n"
		finish := "@MOV AX,@RESULT(SP)\nBYTE $0xc3"
		movement := fmt.Sprintf("SUB%s $%d,SP\nADD%s $%d,SP\n", suffix, word, suffix, word)
		for _, test := range []struct {
			name, body string
			accepted   bool
		}{
			{"entry carry", start + "ADC" + suffix + " $0,AX\n" + finish, false},
			{"SP-derived flags", start + movement + "JS done\ndone:\n" + finish, false},
			{"flags exposed as scalar", start + "CMP" + suffix + " AX,$1\nPUSHF" + suffix + "\nPOP" + suffix + " AX\n" + finish, false},
			{"scalar replaces flags", start + "PUSH" + suffix + " AX\nPOPF" + suffix + "\nADC" + suffix + " $0,AX\n" + finish, false},
			{"different flag origins join", start + "CMP" + suffix + " AX,$1\nJE done\n" + movement + "done:\nADC" + suffix + " $0,AX\n" + finish, false},
			{"saved numeric flags restored", start + "CMP" + suffix + " AX,$1\nPUSHF" + suffix + "\n" + movement + "POPF" + suffix + "\nADC" + suffix + " $0,AX\n" + finish, true},
		} {
			t.Run(target.triple+"/"+test.name, func(t *testing.T) {
				source, sig, pkg := x86SourceStackNumericalFixture(target.arch, test.body)
				requireX86GoAssemblerResult(t, target.arch, source, true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				_, err = Translate(file, x86SourceStackOptions(target.arch, target.triple, sig))
				if test.accepted && err != nil || !test.accepted && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("numerical flags contract accepted=%t: %v", test.accepted, err)
				}
				ctx := llvm.NewContext()
				module, err := TranslateModuleInContext(ctx, file, x86SourceStackOptions(target.arch, target.triple, sig))
				if err == nil {
					module.Dispose()
				}
				ctx.Dispose()
				if test.accepted && err != nil || !test.accepted && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("module flags contract accepted=%t: %v", test.accepted, err)
				}
				ctx = llvm.NewContext()
				translation, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: target.arch, TargetTriple: target.triple})
				if err == nil {
					translation.Module.Dispose()
				}
				ctx.Dispose()
				if test.accepted && err != nil || !test.accepted && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("declaration flags contract accepted=%t: %v", test.accepted, err)
				}
			})
		}
	}
}

func TestX86RawReturnBoundSourceStackDoesNotTrustEditedRawProducer(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		source, sig, _ := x86SourceStackNumericalFixture(target.arch,
			"BYTE $0x50\n@MOV @RESULT(SP),AX\nBYTE $0x59\n@MOV AX,ret+@WORD(FP)\nBYTE $0xc3")
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := NormalizeRawFileForTranslation(file, target.arch)
		if err != nil {
			t.Fatal(err)
		}
		for index := range prepared.Funcs[0].Instrs {
			ins := &prepared.Funcs[0].Instrs[index]
			if spec, stack := amd64StackWidthSpecs[ins.Op]; stack && spec.mode == amd64StackPushValue {
				ins.Args = []Operand{{Kind: OpReg, Reg: BX}}
				break
			}
		}
		if _, err := Translate(prepared, x86SourceStackOptions(target.arch, target.triple, sig)); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("%s edited raw producer kept an original-Go prologue certificate: %v", target.triple, err)
		}
		ctx := llvm.NewContext()
		module, err := TranslateModuleInContext(ctx, prepared, x86SourceStackOptions(target.arch, target.triple, sig))
		if err == nil {
			module.Dispose()
		}
		ctx.Dispose()
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("%s module trusted edited raw producer: %v", target.triple, err)
		}
	}
}
