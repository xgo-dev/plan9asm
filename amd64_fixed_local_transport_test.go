package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

func fixedLocalTransportAssembly(name string, args int, body string) string {
	return fmt.Sprintf(`TEXT ·%s(SB),4,$256-%d
MOVQ SP,BP
ADDQ $64,BP
ANDQ $-64,BP
MOVQ n+40(FP),AX
MOVQ AX,64(BP)
MOVQ AX,72(BP)
MOVQ AX,80(BP)
MOVQ AX,88(BP)
VMOVDQA 64(BP),Y14
VMOVDQA Y14,96(BP)
%s
RET
`, name, args, body)
}

func fixedLocalTransportFixture(t *testing.T, assembly, declarations, target, triple string) (GoPackage, GoAMD64FrameCaptureRequest, *File, Options) {
	t.Helper()
	pkg, request := goAMD64FrameTypedFixture(t, declarations, assembly)
	request.Target = target
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(map[string]FuncSig)
	for _, name := range pkg.Types.Scope().Names() {
		function, ok := pkg.Types.Scope().Lookup(name).(*types.Func)
		if !ok {
			continue
		}
		sig, err := DeriveGoFuncABI0Signature(pkg.Path+"."+name, function, "amd64", types.SizesFor("gc", "amd64"))
		if err != nil {
			t.Fatal(err)
		}
		sigs[sig.Name] = sig
	}
	return pkg, request, file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs,
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", pkg.Path+".", 1) }}
}

const fixedLocalTransportParams = "a []byte, p *uint64, b bool, n uint64"

const fixedLocalTransportBoolBody = `MOVQ a_base+0(FP),CX
MOVQ CX,128(BP)
MOVQ 128(BP),DX
MOVQ p+24(FP),R8
MOVB b+32(FP),BX
MOVB BX,160(BP)
MOVB 160(BP),BX
MOVB BX,ret+48(FP)`

func TestGoAMD64FixedLocalTransportActualObjects(t *testing.T) {
	t.Setenv("GOCACHE", t.TempDir())
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	var assembly, declarations strings.Builder
	cases := []struct {
		result string
		args   int
		body   string
	}{
		{"bool", 49, fixedLocalTransportBoolBody},
		{"bool", 49, strings.Replace(fixedLocalTransportBoolBody, "MOVQ p+24(FP),R8",
			"CMPQ AX,$0\nJE join\nMOVQ p+24(FP),DX\njoin:\nMOVQ (DX),AX", 1)},
		{"*uint64", 56, "MOVQ p+24(FP),CX\nMOVQ CX,128(BP)\nMOVQ 128(BP),DX\nMOVQ DX,ret+48(FP)"},
		{"[]byte", 72, "MOVQ a_base+0(FP),CX\nMOVQ a_len+8(FP),DX\nMOVQ a_cap+16(FP),BX\nMOVQ CX,128(BP)\nMOVQ 128(BP),CX\nMOVQ CX,ret_base+48(FP)\nMOVQ DX,ret_len+56(FP)\nMOVQ BX,ret_cap+64(FP)"},
		{"(r []byte, ok bool)", 73, "MOVQ a_base+0(FP),CX\nMOVQ a_len+8(FP),DX\nMOVQ a_cap+16(FP),BX\nMOVQ CX,r_base+48(FP)\nMOVQ DX,r_len+56(FP)\nMOVQ BX,r_cap+64(FP)\nMOVB b+32(FP),CX\nMOVB CX,ok+72(FP)"},
		{"", 48, "MOVQ a_base+0(FP),CX\nMOVQ CX,128(BP)\nMOVQ 128(BP),CX\nMOVQ p+24(FP),R8"},
	}
	for _, condition := range strings.Fields("SETCC SETCS SETEQ SETGE SETGT SETHI SETLE SETLS SETLT SETMI SETNE SETOC SETOS SETPC SETPL SETPS") {
		cases = append(cases, struct {
			result string
			args   int
			body   string
		}{"bool", 49, "CMPQ AX,$0\n" + condition + " BX\nMOVB BX,ret+48(FP)"})
	}
	for _, body := range fixedLocalCanonicalBoolBodies {
		cases = append(cases, struct {
			result string
			args   int
			body   string
		}{"bool", 49, body})
	}
	args := make([]int, len(cases))
	for i, test := range cases {
		args[i] = test.args
		name := fmt.Sprintf("Value%d", i)
		assembly.WriteString(fixedLocalTransportAssembly(name, test.args, test.body))
		fmt.Fprintf(&declarations, "func %s(%s) %s\n", name, fixedLocalTransportParams, test.result)
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
		{"windows/amd64", "x86_64-w64-windows-gnu"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly.String(), declarations.String(), target.name, target.triple)
			fixedLocalConversionPrepareToolCache(t, request)
			fixedLocalTransportRequireOriginalFrames(t, pkg, request, args)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
				if err != nil || strings.Count(ir, "%fixed_local_native = alloca") != len(cases) {
					t.Fatal("typed transport lost original private-frame proof", err)
				}
				compileLLVMToObject(t, llc, target.triple, "transport.ll", "transport.o", ir)
				compileLLVMToObject(t, llc, target.triple, "transport-opt.ll", "transport-opt.o", x86MulDivRoundOptimize(t, ir))
			})
		})
	}
}

// The original physical frame certificate is an independent prior. Close it
// before any API starts; it cannot supply or extend a consumer's binding.
func fixedLocalTransportRequireOriginalFrames(t *testing.T, pkg GoPackage, request GoAMD64FrameCaptureRequest, args []int) {
	t.Helper()
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	}()
	if len(source.functions) != len(args) {
		t.Fatal("missing complete original object functions")
	}
	for i, want := range args {
		observed := source.functions[fmt.Sprintf("%s.Value%d", pkg.Path, i)]
		if observed.args != int64(want) || observed.locals != 264 || len(observed.code) == 0 {
			t.Fatalf("actual Go ABI0 frame differs: %+v", observed)
		}
		wantOffsets := []int64{0, 8, 16, 24, 32, 40}
		if len(observed.signature.Frame.Params) != len(wantOffsets) {
			t.Fatal("slice ABI0 component inventory changed")
		}
		for j, slot := range observed.signature.Frame.Params {
			if slot.Offset != wantOffsets[j] {
				t.Fatal("actual component offset differs", slot)
			}
		}
	}
}

func TestGoAMD64FixedLocalTransportAuthorityNegatives(t *testing.T) {
	base := fixedLocalTransportAssembly("Value", 49, fixedLocalTransportBoolBody)
	declaration := "func Value(" + fixedLocalTransportParams + ") bool"
	t.Run("incoming arithmetic", func(t *testing.T) {
		body := strings.Replace(fixedLocalTransportBoolBody, "MOVQ p+24(FP),R8", "ADDQ CX,DX", 1)
		assembly := strings.Replace(base, fixedLocalTransportBoolBody, body, 1)
		pkg, _, file, options := fixedLocalTransportFixture(t, assembly, declaration, "linux/amd64", "x86_64-unknown-linux-gnu")
		if _, err := proveX86FixedLocal(file.Funcs[0], options.Sigs[pkg.Path+".Value"]); err != nil {
			t.Fatal("unused native-address arithmetic changed canonical bool transport", err)
		}
	})
	for name, body := range map[string]string{
		"undefined incoming index": strings.Replace(fixedLocalTransportBoolBody, "MOVQ p+24(FP),R8", "MOVQ (DX)(R9*2),AX", 1),
		"incoming comparison":      strings.Replace(fixedLocalTransportBoolBody, "MOVQ p+24(FP),R8", "CMPQ DX,R8", 1),
		"incoming mask":            strings.Replace(fixedLocalTransportBoolBody, "MOVQ p+24(FP),R8", "KMOVQ DX,K1", 1),
		"incoming partial":         strings.Replace(fixedLocalTransportBoolBody, "MOVQ 128(BP),DX", "MOVL 128(BP),DX", 1),
		"incoming numeric spill":   strings.Replace(fixedLocalTransportBoolBody, "MOVQ p+24(FP),R8", "VMOVDQA 128(BP),Y0", 1),
		"bool noncanonical":        strings.Replace(fixedLocalTransportBoolBody, "MOVB BX,ret+48(FP)", "MOVB $2,BX\nMOVB BX,ret+48(FP)", 1),
		"bool unknown":             strings.Replace(fixedLocalTransportBoolBody, "MOVB BX,ret+48(FP)", "MOVB AX,ret+48(FP)", 1),
		"bool wide FP":             strings.Replace(fixedLocalTransportBoolBody, "MOVB b+32(FP),BX", "MOVQ b+32(FP),BX", 1),
		"missing result":           strings.Replace(fixedLocalTransportBoolBody, "MOVB BX,ret+48(FP)", "", 1),
		"private pointer result":   "MOVQ BP,ret+48(FP)",
		"false SET flags":          "SETEQ BX\nMOVB BX,ret+48(FP)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(base, fixedLocalTransportBoolBody, body, 1)
			pkg, _, file, options := fixedLocalTransportFixture(t, assembly, declaration, "linux/amd64", "x86_64-unknown-linux-gnu")
			if _, err := proveX86FixedLocal(file.Funcs[0], options.Sigs[pkg.Path+".Value"]); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("typed transport granted unproved numerical/memory/result authority", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalTransportPartialWritesAndJoins(t *testing.T) {
	base := fixedLocalTransportAssembly("Value", 49, fixedLocalTransportBoolBody)
	declaration := "func Value(" + fixedLocalTransportParams + ") bool"
	cases := map[string]string{
		"opaque integer result": "MOVQ a_base+0(FP),CX\nMOVQ CX,ret+48(FP)",
		"opaque SP replacement": strings.Replace(fixedLocalTransportBoolBody, "MOVQ 128(BP),DX", "MOVQ 128(BP),SP", 1),
		"opaque BP replacement": strings.Replace(fixedLocalTransportBoolBody, "MOVQ 128(BP),DX", "MOVQ 128(BP),BP", 1),
		"opaque narrow GP":      strings.Replace(fixedLocalTransportBoolBody, "MOVQ 128(BP),DX", "MOVQ 128(BP),DX\nMOVB DX,AX", 1),
		"pointer and NUM join":  strings.Replace(fixedLocalTransportBoolBody, "MOVQ p+24(FP),R8", "CMPQ AX,$0\nJE join\nMOVQ AX,DX\njoin:\nMOVQ (DX),AX", 1),
		"bool lost in CMOV":     strings.Replace(fixedLocalTransportBoolBody, "MOVB BX,ret+48(FP)", "MOVQ $0,BX\nCMPQ AX,$0\nCMOVQEQ AX,BX\nMOVB BX,ret+48(FP)", 1),
		"bool unknown join":     strings.Replace(fixedLocalTransportBoolBody, "MOVB BX,ret+48(FP)", "CMPQ AX,$0\nJE join\nMOVB AX,BX\njoin:\nMOVB BX,ret+48(FP)", 1),
	}
	for index := 0; index < 8; index++ {
		cases[fmt.Sprintf("opaque spill byte %d", index)] = strings.Replace(fixedLocalTransportBoolBody, "MOVQ 128(BP),DX", fmt.Sprintf("MOVB $0,%d(BP)\nMOVQ 128(BP),DX", 128+index), 1)
	}
	for _, mask := range []string{"KMOVQ AX,K1", "MOVQ $0,R9\nKMOVQ R9,K1"} {
		cases["masked opaque spill/"+mask] = strings.Replace(fixedLocalTransportBoolBody, "MOVQ 128(BP),DX", mask+"\nVMOVDQU8 Y14,K1,128(BP)\nMOVQ 128(BP),DX", 1)
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(base, fixedLocalTransportBoolBody, body, 1)
			decl := declaration
			if name == "opaque integer result" {
				decl = "func Value(" + fixedLocalTransportParams + ") uint64"
				assembly = strings.Replace(assembly, "$256-49", "$256-56", 1)
			}
			pkg, _, file, options := fixedLocalTransportFixture(t, assembly, decl, "linux/amd64", "x86_64-unknown-linux-gnu")
			if _, err := proveX86FixedLocal(file.Funcs[0], options.Sigs[pkg.Path+".Value"]); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("overwritten or conflicting typed transport survived", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalTransportDerivedAndUnusedPointers(t *testing.T) {
	// These sources used to be negative fixtures before affine inputs and
	// unused differing-origin joins were supported. Retain their exact bodies
	// as positive controls; the negative siblings now consume a real missing
	// NUM operand, unknown comparison input or unresolved pointer identity.
	for name, replacement := range map[string]string{
		"incoming numerical index": "MOVQ (DX)(AX*2),AX",
		"incoming arithmetic":      "ADDQ $8,DX",
		"incoming comparison":      "CMPQ DX,$0",
		"unused pointer join":      "CMPQ AX,$0\nJE join\nMOVQ p+24(FP),DX\njoin:",
		"different pointer join":   "CMPQ AX,$0\nJE join\nMOVQ p+24(FP),DX\njoin:\nMOVQ (DX),AX",
	} {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(fixedLocalTransportBoolBody, "MOVQ p+24(FP),R8", replacement, 1)
			assembly := fixedLocalTransportAssembly("Value", 49, body)
			declaration := "func Value(" + fixedLocalTransportParams + ") bool"
			pkg, _, file, options := fixedLocalTransportFixture(t, assembly, declaration, "linux/amd64", "x86_64-unknown-linux-gnu")
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			if _, err := proveX86FixedLocal(file.Funcs[0], options.Sigs[pkg.Path+".Value"]); err != nil {
				t.Fatal("safe derived or unused pointer source regressed", err)
			}
		})
	}
}

var fixedLocalCanonicalBoolBodies = []string{
	"MOVB $0,ret+48(FP)", "MOVB $1,ret+48(FP)",
	"MOVW $256,AX\nMOVB AH,ret+48(FP)",
	"MOVB b+32(FP),AH\nMOVB AH,160(BP)\nMOVB 160(BP),AL\nMOVB AL,ret+48(FP)",
	"MOVQ $0,BX\nMOVQ $1,DX\nCMPQ AX,$0\nCMOVQEQ DX,BX\nMOVB BX,ret+48(FP)",
	"CMPQ AX,$0\nSETEQ 160(BP)\nMOVB 160(BP),BX\nMOVB BX,ret+48(FP)",
	"CMPQ AX,$0\nSETEQ ret+48(FP)",
}

func TestGoAMD64FixedLocalTransportCanonicalBoolBytes(t *testing.T) {
	for _, body := range fixedLocalCanonicalBoolBodies {
		t.Run(body, func(t *testing.T) {
			assembly := fixedLocalTransportAssembly("Value", 49, body)
			pkg, _, file, options := fixedLocalTransportFixture(t, assembly, "func Value("+fixedLocalTransportParams+") bool", "linux/amd64", "x86_64-unknown-linux-gnu")
			if _, err := proveX86FixedLocal(file.Funcs[0], options.Sigs[pkg.Path+".Value"]); err != nil {
				t.Fatal("canonical physical bool byte was lost", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalTransportLanguageAndLifetime(t *testing.T) {
	for _, declaration := range []string{
		"func Value(a []bool, p *bool, b bool, n uint64) bool",
		"func Value(a []int8, p *int8, b bool, n uint64) bool",
		"func Value(a []uint16, p *[4]uint16, b bool, n uint64) bool",
		"func Value(a []*uint64, p **uint64, b bool, n uint64) bool",
		"type B bool\ntype S []bool\ntype P *[2]bool\nfunc Value(a S, p P, b B, n uint64) B",
		"type B = bool\ntype S = []byte\ntype P = *[2]bool\nfunc Value(a S, p P, b B, n uint64) B",
		"type Packet struct { B bool; N uint64; Tail [0]byte }\nfunc Value(a []Packet, p *Packet, b bool, n uint64) bool",
	} {
		t.Run(declaration, func(t *testing.T) {
			assembly := fixedLocalTransportAssembly("Value", 49, fixedLocalTransportBoolBody)
			pkg, request, file, options := fixedLocalTransportFixture(t, assembly, declaration, "linux/amd64", "x86_64-unknown-linux-gnu")
			owner := requireGoAMD64FrameCapture(t, pkg, request)
			if !errors.Is(owner.numericDeclarations(pkg), ErrProbeNeedsContext) {
				t.Fatal("opaque observation was relabeled as a numeric declaration")
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			bound, err := owner.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatal("complete named/alias/element language identity was lost", err)
			}
			fixedLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
				if err != nil || !strings.Contains(ir, "fixed_local_native") {
					t.Fatal("opaque language contract did not reach complete consumer", err)
				}
			})
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			fixedLocalAPIs(t, pkg, file, bound, fixedLocalRequireContext)
		})
	}
}

func TestGoAMD64FixedLocalTransportEveryResultComponent(t *testing.T) {
	const body = "MOVQ a_base+0(FP),CX\nMOVQ a_len+8(FP),DX\nMOVQ a_cap+16(FP),BX\nMOVQ CX,r_base+48(FP)\nMOVQ DX,r_len+56(FP)\nMOVQ BX,r_cap+64(FP)\nMOVB b+32(FP),CX\nMOVB CX,ok+72(FP)"
	for _, missing := range []string{"MOVQ CX,r_base+48(FP)", "MOVQ DX,r_len+56(FP)", "MOVQ BX,r_cap+64(FP)", "MOVB CX,ok+72(FP)"} {
		t.Run(missing, func(t *testing.T) {
			assembly := fixedLocalTransportAssembly("Value", 73, strings.Replace(body, missing, "", 1))
			pkg, _, file, options := fixedLocalTransportFixture(t, assembly, "func Value("+fixedLocalTransportParams+") (r []byte, ok bool)", "linux/amd64", "x86_64-unknown-linux-gnu")
			if _, err := proveX86FixedLocal(file.Funcs[0], options.Sigs[pkg.Path+".Value"]); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("missing result component acquired initialized aggregate", err)
			}
		})
	}
}
