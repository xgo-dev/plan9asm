package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"golang.org/x/arch/x86/x86asm"
)

func x86MOVSXDBytes(encoding []byte) string {
	var source strings.Builder
	for _, value := range encoding {
		fmt.Fprintf(&source, "BYTE $0x%02x\n", value)
	}
	return source.String()
}

func TestX86RawMOVSXDNativeWidths(t *testing.T) {
	for _, test := range []struct {
		name     string
		encoding []byte
		want     string
	}{
		{"long register", []byte{0x63, 0xc3}, "MOVL BX, AX"},
		{"long high source", []byte{0x41, 0x63, 0xc1}, "MOVL R9, AX"},
		{"long high result", []byte{0x44, 0x63, 0xc3}, "MOVL BX, R8"},
		{"long alias", []byte{0x63, 0xc0}, "MOVL AX, AX"},
		{"long memory", []byte{0x63, 0x07}, "MOVL 0(DI), AX"},
		{"long indexed", []byte{0x63, 0x44, 0x8f, 0x03}, "MOVL 0x3(DI)(CX*4), AX"},
		{"word register", []byte{0x66, 0x63, 0xc3}, "MOVW BX, AX"},
		{"word physical SI", []byte{0x66, 0x63, 0xc6}, "MOVW SI, AX"},
		{"word high source", []byte{0x66, 0x41, 0x63, 0xc1}, "MOVW R9, AX"},
		{"word high result", []byte{0x66, 0x44, 0x63, 0xc3}, "MOVW BX, R8"},
		{"quad register", []byte{0x48, 0x63, 0xc3}, "MOVLQSX BX, AX"},
		{"quad memory", []byte{0x48, 0x63, 0x07}, "MOVLQSX 0(DI), AX"},
	} {
		t.Run(test.name, func(t *testing.T) {
			inst, err := x86asm.Decode(test.encoding, 64)
			if err != nil || inst.Op != x86asm.MOVSXD || inst.Len != len(test.encoding) {
				t.Fatalf("physical decode: %+v %v", inst, err)
			}
			got, err := decodedX86GoSyntax(inst, test.encoding)
			if err != nil || got != test.want {
				t.Fatalf("physical width: got %q, want %q: %v", got, test.want, err)
			}
		})
	}
}

func TestX86RawMOVSXDLongCallerOriginalBytes(t *testing.T) {
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL $7,AX\nMOVL AX,(DX)",
		"MOVQ $0x80000000,BX\nWORD $0xc363\nMOVL AX,(DX)", 1)
	requireX86GoAssemblerResult(t, "amd64", assembly, true)
	pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
		t.Fatal(err)
	}
}

func TestX86RawMOVSXDCompleteRegisterModRM(t *testing.T) {
	registers := []string{"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI",
		"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"}
	for _, bits := range []int{16, 32, 64} {
		for result := range registers {
			for source := range registers {
				var encoding []byte
				if bits == 16 {
					encoding = append(encoding, 0x66)
				}
				rex := byte(0x40)
				if bits == 64 {
					rex |= 8
				}
				if result >= 8 {
					rex |= 4
				}
				if source >= 8 {
					rex |= 1
				}
				if rex != 0x40 {
					encoding = append(encoding, rex)
				}
				encoding = append(encoding, 0x63, byte(0xc0+(result%8)*8+source%8))
				inst, err := x86asm.Decode(encoding, 64)
				if err != nil {
					t.Fatal(err)
				}
				before := inst
				got, err := decodedX86GoSyntax(inst, encoding)
				op := map[int]string{16: "MOVW", 32: "MOVL", 64: "MOVLQSX"}[bits]
				want := fmt.Sprintf("%s %s, %s", op, registers[source], registers[result])
				if err != nil || got != want || !reflect.DeepEqual(inst, before) {
					t.Fatalf("bits=%d bytes=%x: got %q want %q changed=%t: %v", bits, encoding, got, want, inst != before, err)
				}
			}
		}
	}
}

func x86MOVSXDDenied(t *testing.T, source string) {
	t.Helper()
	requireX86GoAssemblerResult(t, "amd64", source, true)
	pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, source)
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		options := Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs, ResolveSym: resolve}
		if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("unproved raw MOVSXD Translate: %v", err)
		}
		ctx := llvm.NewContext()
		module, err := TranslateModuleInContext(ctx, file, options)
		if !module.IsNil() {
			module.Dispose()
		}
		ctx.Dispose()
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("unproved raw MOVSXD module: %v", err)
		}
		if err := x86CallerCoreTranslate(t, pkg, source, triple); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("unproved raw MOVSXD Go module: %v", err)
		}
	}
}

func TestX86RawMOVSXDInputAndVendorBoundaries(t *testing.T) {
	for _, test := range []struct{ name, body string }{
		{"undefined long source", "WORD $0xc363"},
		{"partial long source", "MOVW $7,BX\nWORD $0xc363"},
		{"undefined word source", "BYTE $0x66\nWORD $0xc363"},
		{"partial word source", "MOVB $7,BX\nBYTE $0x66\nWORD $0xc363"},
		{"caller pointer long source", "WORD $0xc763"},
		{"caller pointer word source", "BYTE $0x66\nWORD $0xc763"},
		{"word overwrites surviving pointer bits", "MOVQ DI,AX\nBYTE $0x66\nWORD $0xc363"},
		{"native SP source", "WORD $0xc463"},
		{"native BP source", "BYTE $0x66\nWORD $0xc563"},
		{"native SP result", "WORD $0xe363"},
		{"native BP result", "BYTE $0x66\nWORD $0xeb63"},
		{"g source", "BYTE $0x41\nWORD $0xc663"},
		{"g result", "BYTE $0x44\nWORD $0xf363"},
		{"unknown memory", "WORD $0x0363"},
		{"partial FP pointer slot", "WORD $0x4463\nWORD $0x0824"},
		{"return PC memory", "WORD $0x0463\nBYTE $0x24"},
		{"word memory vendor identity absent", "BYTE $0x66\nWORD $0x0763"},
		{"word indexed vendor identity absent", "BYTE $0x66\nLONG $0x038f4463"},
		{"address-size memory", "BYTE $0x67\nWORD $0x0763"},
		{"different initialized bytes join", "CMPQ AX,$0\nJE other\nMOVL $7,BX\nother:\nWORD $0xc363"},
	} {
		t.Run(test.name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", test.body+"\nMOVL AX,(DX)", 1)
			x86MOVSXDDenied(t, assembly)
		})
	}
}

func TestX86RawMOVSXDRequiresExactEncodingIdentity(t *testing.T) {
	encoding := []byte{0x63, 0xc3}
	physical, err := x86asm.Decode(encoding, 64)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"source", "result", "width", "mode", "extra operand", "bytes", "truncated", "extended"} {
		t.Run(change, func(t *testing.T) {
			inst, bytes := physical, append([]byte(nil), encoding...)
			switch change {
			case "source":
				inst.Args[1] = x86asm.ECX
			case "result":
				inst.Args[0] = x86asm.ECX
			case "width":
				inst.DataSize = 64
			case "mode":
				inst.Mode = 32
			case "extra operand":
				inst.Args[2] = x86asm.EAX
			case "bytes":
				bytes[1] = 0xc1
			case "truncated":
				bytes = bytes[:1]
			case "extended":
				bytes = append(bytes, 0x90)
			}
			if _, err := decodedX86GoSyntax(inst, bytes); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("mismatched native MOVSXD width acquired permission: %v", err)
			}
		})
	}
}

func TestX86RawMOVSXDNoncallerDoesNotAcquireInputProof(t *testing.T) {
	for _, prefix := range []string{"", "MOVW $7,BX\n", "MOVQ x+0(FP),BX\n"} {
		for _, raw := range []string{"WORD $0xc363", "BYTE $0x66\nWORD $0xc363"} {
			source, sig, pkg := x86SourceStackNumericalFixture("amd64", prefix+raw+"\nMOVQ AX,ret+8(FP)\nBYTE $0xc3")
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			options := x86SourceStackOptions("amd64", "x86_64-unknown-linux-gnu", sig)
			if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("noncaller raw scalar width acquired input proof: %v", err)
			}
			ctx := llvm.NewContext()
			module, err := TranslateModuleInContext(ctx, file, options)
			if !module.IsNil() {
				module.Dispose()
			}
			ctx.Dispose()
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("noncaller raw scalar module acquired input proof: %v", err)
			}
			ctx = llvm.NewContext()
			translation, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
				GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
			})
			if translation != nil {
				translation.Module.Dispose()
			}
			ctx.Dispose()
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("noncaller raw scalar Go module acquired input proof: %v", err)
			}
		}
	}
}

func TestX86RawMOVSXDLegacyModeRemainsARPL(t *testing.T) {
	for _, encoding := range [][]byte{{0x63, 0xc3}, {0x66, 0x63, 0xc3}} {
		inst, err := x86asm.Decode(encoding, 32)
		if err != nil || inst.Op != x86asm.ARPL {
			t.Fatalf("legacy mode opcode identity: %+v %v", inst, err)
		}
		syntax, err := decodedX86GoSyntax(inst, encoding)
		if err != nil || !strings.HasPrefix(syntax, "ARPL ") {
			t.Fatalf("legacy ARPL must not become a numerical copy: %q %v", syntax, err)
		}
	}
}

func TestX86RawMOVSXDUnregisteredPrefixesStayContext(t *testing.T) {
	for _, encoding := range [][]byte{
		{0x66, 0x66, 0x63, 0xc3}, {0x40, 0x41, 0x63, 0xc3},
		{0xf2, 0x63, 0xc3}, {0xf3, 0x63, 0xc3},
		{0x67, 0x63, 0x07}, {0x64, 0x63, 0x07}, {0x65, 0x48, 0x63, 0x07},
	} {
		inst, err := x86asm.Decode(encoding, 64)
		if err != nil || inst.Op != x86asm.MOVSXD {
			continue // Decoder rejection is also closed; it is not object/runtime P.
		}
		if _, err := decodedX86GoSyntax(inst, encoding); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("unregistered physical prefix %x was silently discarded: %v", encoding, err)
		}
	}
	if inst, err := x86asm.Decode([]byte{0xf0, 0x63, 0xc3}, 64); err == nil && inst.Op == x86asm.MOVSXD {
		if _, err := decodedX86GoSyntax(inst, []byte{0xf0, 0x63, 0xc3}); err == nil || errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("machine-invalid LOCK MOVSXD was accepted or misclassified as missing context", err)
		}
	}
}

func x86MOVSXDModuleObject(t *testing.T, file *File, options Options, triple, name string) {
	t.Helper()
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, options)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	compileLLVMToObject(t, findLLVM22Tool("llc"), triple, name+".ll", name+".o", module.String())
}

func x86MOVSXDGoModuleObject(t *testing.T, pkg GoPackage, source, triple, name string) {
	t.Helper()
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	translation, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
		GOARCH: "amd64", TargetTriple: triple,
	})
	if translation != nil {
		defer translation.Module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	compileLLVMToObject(t, findLLVM22Tool("llc"), triple, name+".ll", name+".o", translation.Module.String())
}

func TestX86RawMOVSXDSafeFormatsThreeAPIObjects(t *testing.T) {
	for _, body := range []string{
		"MOVL $0x80000000,BX\nWORD $0xc363",
		"MOVL $0x80000000,R9\nBYTE $0x41\nWORD $0xc163",
		"MOVL $0x80000000,BX\nBYTE $0x44\nWORD $0xc363\nMOVL R8,AX",
		"MOVL $0x80000000,AX\nWORD $0xc063",
		"WORD $0x0763", "WORD $0x4763\nBYTE $1", "MOVL $0,CX\nLONG $0x038f4463",
		"MOVL $0,CX\nLONG $0x008f4463",
		"MOVQ $0x1122334455667788,AX\nMOVW $0x8000,BX\nBYTE $0x66\nWORD $0xc363",
		"MOVQ $0x1122334455667788,AX\nMOVQ $0x8000,SI\nBYTE $0x66\nWORD $0xc663",
		"MOVQ $0x1122334455667788,AX\nMOVW $0x8000,R9\nWORD $0x4166\nWORD $0xc163",
		"MOVL $0x80000000,BX\nBYTE $0x48\nWORD $0xc363",
		"BYTE $0x48\nWORD $0x0763", "WORD $0x4866\nWORD $0x0763",
	} {
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body+"\nMOVL AX,(DX)", 1)
		requireX86GoAssemblerResult(t, "amd64", assembly, true)
		pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
		resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
		sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
			options := Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs, ResolveSym: resolve}
			ir, err := Translate(file, options)
			if err != nil {
				t.Fatalf("Translate %s: %v\n%s", triple, err, body)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM22 llc required")
			}
			compileLLVMToObject(t, llc, triple, "movsxd-text.ll", "movsxd-text.o", ir)
			x86MOVSXDModuleObject(t, file, options, triple, "movsxd-module")
			if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestX86RawMOVSXDLiteralExactReadExtent(t *testing.T) {
	for _, prefix := range []string{"", "BYTE $0x48\n"} {
		// The literal lies after the native C3, twelve/thirteen bytes from the
		// entry. Displacement six spans the encoded full result-slot store.
		body := prefix + "WORD $0x0563\nLONG $6\nWORD $0x8948\nWORD $0x2444\nBYTE $16\nBYTE $0xc3\nLONG $0x80000000"
		source, sig, pkg := x86SourceStackNumericalFixture("amd64", body)
		requireX86GoAssemblerResult(t, "amd64", source, true)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
			options := x86SourceStackOptions("amd64", triple, sig)
			ir, err := Translate(file, options)
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, findLLVM22Tool("llc"), triple, "movsxd-literal.ll", "movsxd-literal.o", ir)
			x86MOVSXDModuleObject(t, file, options, triple, "movsxd-literal-module")
			x86MOVSXDGoModuleObject(t, pkg, source, triple, "movsxd-literal-go")
		}
		// Preserve the real opcode and displacement; only truncate the object.
		truncated := strings.TrimSuffix(source, "LONG $0x80000000\n") + "WORD $0x8000\n"
		truncatedFile, err := Parse(ArchAMD64, truncated)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(truncatedFile, x86SourceStackOptions("amd64", "x86_64-unknown-linux-gnu", sig)); err == nil {
			t.Fatal("four-byte MOVSXD literal read borrowed a truncated object")
		}
		ctx := llvm.NewContext()
		module, err := TranslateModuleInContext(ctx, truncatedFile, x86SourceStackOptions("amd64", "x86_64-unknown-linux-gnu", sig))
		if !module.IsNil() {
			module.Dispose()
		}
		ctx.Dispose()
		if err == nil {
			t.Fatal("module borrowed a truncated MOVSXD literal")
		}
		ctx = llvm.NewContext()
		translation, err := translateGoModuleInContext(ctx, pkg, []byte(truncated), GoModuleOptions{
			GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		})
		if translation != nil {
			translation.Module.Dispose()
		}
		ctx.Dispose()
		if err == nil {
			t.Fatal("Go module borrowed a truncated MOVSXD literal")
		}
	}
}

func TestX86RawMOVSXDOriginalGoByteWitness(t *testing.T) {
	for _, encoding := range [][]byte{
		{0x63, 0xc3}, {0x66, 0x63, 0xc3}, {0x48, 0x63, 0xc3},
		{0x41, 0x63, 0xc1}, {0x44, 0x63, 0xc3},
		{0x66, 0x41, 0x63, 0xc1}, {0x66, 0x44, 0x63, 0xc3},
		{0x63, 0x07}, {0x63, 0x47, 0x01}, {0x63, 0x44, 0x8f, 0x03},
		{0x48, 0x63, 0x07}, {0x66, 0x48, 0x63, 0x07},
		{0x66, 0x63, 0x07}, // Go accepts the raw bytes; native extent remains Context.
	} {
		listing, err := x86ExtensionGoListing(t, "amd64", x86MOVSXDBytes(encoding))
		var bytes strings.Builder
		for _, value := range append(append([]byte(nil), encoding...), 0xc3) {
			fmt.Fprintf(&bytes, "%02x ", value)
		}
		if err != nil || !strings.Contains(listing, strings.TrimSpace(bytes.String())) {
			t.Fatalf("actual Go %x byte witness: %v\n%s", encoding, err, listing)
		}
	}
}

func TestX86RawMOVSXDLiteralCannotBorrowStaleCertificate(t *testing.T) {
	body := "BYTE $0x48\nWORD $0x0563\nLONG $6\nWORD $0x8948\nWORD $0x2444\nBYTE $16\nBYTE $0xc3\nLONG $0x80000000"
	source, sig, _ := x86SourceStackNumericalFixture("amd64", body)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	options := x86SourceStackOptions("amd64", "x86_64-unknown-linux-gnu", sig)
	normalized, err := normalizeX86RawFile(file, "amd64", options)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"source width", "opcode", "result", "source", "payload", "missing object", "g result"} {
		t.Run(change, func(t *testing.T) {
			mutated := *normalized
			mutated.Data = append([]DataStmt(nil), normalized.Data...)
			mutated.Funcs = append([]Func(nil), normalized.Funcs...)
			mutated.Funcs[0].Instrs = append([]Instr(nil), normalized.Funcs[0].Instrs...)
			instruction := &mutated.Funcs[0].Instrs[1]
			instruction.Args = append([]Operand(nil), instruction.Args...)
			switch change {
			case "source width":
				instruction.x86RIPMemoryRead.width = 8
			case "opcode":
				instruction.Op = "MOVQ"
			case "result":
				instruction.Args[1].Reg = BX
			case "source":
				instruction.Args[0] = Operand{Kind: OpReg, Reg: BX}
			case "g result":
				instruction.Args[1].Reg = "R14"
			case "payload":
				mutated.Data[0].Payload = []byte{1, 2, 3, 4}
			case "missing object":
				mutated.Data = nil
			}
			if _, err := Translate(&mutated, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("changed literal Translate: %v", err)
			}
			ctx := llvm.NewContext()
			module, err := TranslateModuleInContext(ctx, &mutated, options)
			if !module.IsNil() {
				module.Dispose()
			}
			ctx.Dispose()
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("changed literal module: %v", err)
			}
			// Go-module input is original bytes, not a File carrying a private
			// certificate. Its independently regenerated, truncated source is
			// tested above; it cannot accept this mutated certificate as input.
		})
	}
}
