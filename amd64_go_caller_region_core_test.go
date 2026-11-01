package plan9asm

import (
	"errors"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86CallerCoreFixture(t *testing.T, source, assembly string) (GoPackage, *File) {
	t.Helper()
	pkg, selected, _, _ := x86CallerFixture(t, source)
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	selected.Assembly["kernel_amd64.s"] = file
	pkg.SourceSelection = &selected
	return pkg, file
}

func x86CallerCoreTranslate(t *testing.T, pkg GoPackage, assembly, triple string) error {
	t.Helper()
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	translated, err := translateGoModuleInContext(ctx, pkg, []byte(assembly), GoModuleOptions{
		FileName: "kernel_amd64.s", GOARCH: "amd64", TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) },
	})
	if err != nil {
		return err
	}
	defer translated.Module.Dispose()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "caller-regions.ll", "caller-regions.o", translated.Module.String())
	return nil
}

func TestX86GoCallerRegionCoreConsumesFreshScalarWrites(t *testing.T) {
	for _, form := range []struct{ typ, move string }{
		{"uint8", "MOVB"}, {"uint16", "MOVW"}, {"uint32", "MOVL"}, {"uint64", "MOVQ"},
	} {
		source := strings.Replace(x86CallerFixtureSource, "var res float32", "var res "+form.typ, 1)
		source = strings.Replace(source, ") float32 {", ") "+form.typ+" {", 1)
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL $7,AX\nMOVL AX,(DX)", form.move+" $7,AX\n"+form.move+" AX,(DX)", 1)
		for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
			t.Run(form.move+"/"+triple, func(t *testing.T) {
				requireX86GoAssemblerResult(t, "amd64", assembly, true)
				pkg, _ := x86CallerCoreFixture(t, source, assembly)
				if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestX86GoCallerRegionCoreDoesNotCertifyBadStackOrWrites(t *testing.T) {
	for name, replacement := range map[string]string{
		"input write":               "MOVL AX,(DI)",
		"length write":              "MOVL AX,(CX)",
		"wide result":               "MOVQ AX,(DX)",
		"one byte overlap":          "MOVL AX,1(DX)",
		"negative offset":           "MOVL AX,-1(DX)",
		"unknown base":              "MOVL AX,(BX)",
		"indexed result":            "MOVL AX,(DX)(BX*1)",
		"pointer as data":           "MOVL DI,(DX)",
		"partial pointer":           "MOVL DX,BX\nMOVL AX,(BX)",
		"fresh pointer join":        "CMPQ AX,$0\nJE joined\nMOVQ DI,DX\njoined:\nMOVL AX,(DX)",
		"return PC":                 "MOVQ AX,8(BP)",
		"saved BP":                  "MOVB AX,0(BP)",
		"SP escape":                 "MOVQ SP,AX\nMOVL AX,(DX)",
		"input pointer to SP":       "MOVQ DI,SP\nMOVL AX,(DX)",
		"input pointer to BP":       "MOVQ DI,BP\nMOVL AX,(DX)",
		"input address to SP":       "LEAQ 0(DI),SP\nMOVL AX,(DX)",
		"input address to BP":       "LEAQ 0(DI),BP\nMOVL AX,(DX)",
		"g use":                     "MOVQ R14,AX\nMOVL AX,(DX)",
		"g overwrite":               "MOVQ $0,R14\nMOVL AX,(DX)",
		"pointer FP store":          "MOVQ AX,res+16(FP)\nMOVL AX,(DX)",
		"unknown numeric input":     "MOVL BX,(DX)",
		"partial address clobber":   "MOVW $0,DX\nMOVL AX,(DX)",
		"pointer flags":             "ADDQ $0,DX\nJE joined\njoined:\nMOVL AX,(DX)",
		"different pointer offsets": "CMPQ AX,$0\nJE joined\nADDQ $1,DX\njoined:\nMOVB AX,(DX)",
		"unrestored SP":             "MOVL AX,(DX)",
		"unknown store effect":      "XCHGL AX,(DX)",
		"vector effect":             "VMOVSS X0,(DX)",
		"floating immediate":        "MOVQ $1.25,AX\nMOVL AX,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", replacement, 1)
			if name == "unrestored SP" {
				assembly = strings.Replace(assembly, "BYTE $0xc3", "SUBQ $8,SP\nBYTE $0xc3", 1)
			}
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu")
			if name == "floating immediate" {
				// Go's FLOAT class has no MOVQ row; this is invalid source,
				// not a native caller privilege that a later producer can grant.
				goAssemblerOracleOutput(t, "amd64", assembly, "", false)
				if err == nil || errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("Go-rejected FLOAT source became Context or success: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("bad source acquired caller-region continuation: %v", err)
			}
		})
	}
	// An actual producer snapshot is mandatory; a pointer signature remains
	// the original failure rather than acquiring source memory privileges.
	pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, x86CallerFixtureAssembly)
	pkg.SourceSelection = nil
	if err := x86CallerCoreTranslate(t, pkg, x86CallerFixtureAssembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("missing caller selection acquired pointer-store proof: %v", err)
	}
}

func TestX86GoCallerRegionCoreDoesNotStoreInputPointerAsFullWidthData(t *testing.T) {
	source := strings.NewReplacer(
		"var res float32", "var res uint64", ") float32 {", ") uint64 {",
	).Replace(x86CallerFixtureSource)
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", "MOVQ DI,(DX)", 1)
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	pkg, _ := x86CallerCoreFixture(t, source, assembly)
	if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("input pointer escaped through a correctly sized fresh result: %v", err)
	}
}

func TestX86GoCallerRegionCoreTracksScalarCopiesOffsetsAndInputs(t *testing.T) {
	for name, replacement := range map[string]string{
		"input load":           "MOVL (DI),AX\nADDL $7,AX\nMOVL AX,(DX)",
		"length load":          "MOVQ (CX),AX\nMOVL AX,(DX)",
		"pointer copy":         "MOVQ DX,BX\nMOVL AX,(BX)",
		"pointer offset":       "ADDQ $1,DX\nMOVB AX,(DX)",
		"LEA offset":           "LEAQ 3(DX),BX\nMOVB AX,(BX)",
		"safe adjacent":        "MOVB AX,3(DX)",
		"byte alias":           "MOVB $7,AH\nMOVB AH,(DX)",
		"indexed input":        "MOVQ $0,BX\nMOVL (DI)(BX*4),AX\nMOVL AX,(DX)",
		"copy input offset":    "MOVQ DI,BX\nADDQ $4,BX\nMOVL (BX),AX\nMOVL AX,(DX)",
		"saved result pointer": "PUSHQ DX\nMOVQ DI,DX\nPOPQ DX\nMOVL AX,(DX)",
		"identical join":       "MOVQ DX,BX\nCMPQ AX,$0\nJE joined\nMOVQ DX,BX\njoined:\nMOVL AX,(BX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", replacement, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
	physical := strings.NewReplacer(
		"a+0(FP)", "8(SP)", "b+8(FP)", "16(SP)",
		"res+16(FP)", "24(SP)", "length+24(FP)", "32(SP)",
	).Replace(x86CallerFixtureAssembly)
	leaf := strings.NewReplacer(
		"BYTE $0x55\nWORD $0x8948\nBYTE $0xe5\nLONG $0xf8e48348\n", "",
		"WORD $0x8948\nBYTE $0xec\nBYTE $0x5d\n", "",
	).Replace(x86CallerFixtureAssembly)
	for name, assembly := range map[string]string{"actual physical FP": physical, "stack-unobserving leaf": leaf} {
		t.Run(name, func(t *testing.T) {
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestX86GoCallerRegionCoreRejectsDifferentCompilerDataLayout(t *testing.T) {
	pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, x86CallerFixtureAssembly)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	translation, err := translateGoModuleInContext(ctx, pkg, []byte(x86CallerFixtureAssembly), GoModuleOptions{
		GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sizes: types.SizesFor("gc", "386"), FrameSizes: types.SizesFor("gc", "amd64"),
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) },
	})
	if translation != nil || !errors.Is(err, ErrProbeNeedsContext) {
		if translation != nil {
			translation.Module.Dispose()
		}
		t.Fatalf("typed Args/FP slots concealed a different local int/pointer layout: %v", err)
	}
}

func TestX86GoCallerRegionCoreRejectsStaleSourceSignatureAndAccess(t *testing.T) {
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
	for _, change := range []string{"original source", "normalized source", "signature", "slot", "memory access", "missing caller"} {
		t.Run(change, func(t *testing.T) {
			pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, x86CallerFixtureAssembly)
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}
			normalized, err := normalizeX86RawFile(file, "amd64", options)
			if err != nil {
				t.Fatal(err)
			}
			if change != "original source" {
				file = normalized
			}
			sig := sigs["caller.kernel"]
			switch change {
			case "original source", "normalized source":
				for index := range file.Funcs[0].Instrs {
					instruction := &file.Funcs[0].Instrs[index]
					if instruction.Op == "MOVL" && len(instruction.Args) == 2 && instruction.Args[1].Kind == OpMem {
						instruction.Args[1].Mem.Off++
					}
				}
			case "signature":
				sig.Args[0] = I64
			case "slot":
				sig.Frame.Params[0].Offset = 8
			case "missing caller":
				sig.x86CallerRegions = nil
			case "memory access":
				for index := range file.Funcs[0].Instrs {
					instruction := &file.Funcs[0].Instrs[index]
					for operand, access := range instruction.x86CallerMemory {
						access.width++
						instruction.x86CallerMemory[operand] = access
					}
				}
				if x86RawReturnMemoryBound(file.Funcs[0], file, options, true) {
					t.Fatal("edited access inherited a whole-function memory permission")
				}
				// This checks private access revocation. Public normalization
				// requires a fresh original source, not the edited sealed snapshot.
				return
			}
			sigs["caller.kernel"] = sig
			if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("changed %s borrowed a caller continuation: %v", change, err)
			}
		})
	}
}

func TestX86GoCallerRegionCoreCannotBorrowPhysicalFPWithoutAccessProof(t *testing.T) {
	assembly := strings.NewReplacer(
		"a+0(FP)", "8(SP)", "b+8(FP)", "16(SP)",
		"res+16(FP)", "24(SP)", "length+24(FP)", "32(SP)",
	).Replace(x86CallerFixtureAssembly)
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
	removed := false
	for index := range normalized.Funcs[0].Instrs {
		instruction := &normalized.Funcs[0].Instrs[index]
		for operand := range instruction.x86SourceStackFP {
			delete(instruction.x86CallerMemory, operand)
			removed = true
		}
	}
	if !removed {
		t.Fatal("fixture did not exercise a physical-SP imported parameter")
	}
	if x86RawReturnMemoryBound(normalized.Funcs[0], normalized, options, true) {
		t.Fatal("missing caller access borrowed the old numerical FP continuation")
	}
}

func TestX86GoCallerRegionCoreDoesNotExportScalarOrFloatingStackPermissions(t *testing.T) {
	for name, assembly := range map[string]string{
		"external scalar write": strings.Replace(x86CallerFixtureAssembly,
			"MOVL AX,(DX)", "MOVL AX,global(SB)\nMOVL AX,(DX)", 1) + "GLOBL global(SB),8,$4\n",
		"floating stack adjustment": strings.Replace(x86CallerFixtureAssembly,
			"BYTE $0xc3", "ADDQ $0.5,SP\nBYTE $0xc3", 1),
	} {
		t.Run(name, func(t *testing.T) {
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved permission acquired a caller continuation: %v", err)
			}
		})
	}
}
