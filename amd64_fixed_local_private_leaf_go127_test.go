//go:build go1.27

package plan9asm

import (
	"errors"
	"go/types"
	"strings"
	"testing"
)

func fixedLocalPrivateLeafCases() []struct{ name, body, helper string } {
	return []struct{ name, body, helper string }{
		{"two_calls", "CALL leaf<>(SB)\n MOVQ $3,BX\n CALL leaf<>(SB)",
			"ADDQ BX,(BP)\n MOVQ (BP),AX"},
		{"incoming_flags", "CMPQ AX,BX\n CALL leaf<>(SB)\n SETCS CL\n MOVBLZX CL,AX",
			"MOVQ AX,DX\n MOVQ (BP),AX"},
		{"outgoing_flags", "CALL leaf<>(SB)\n SETCS CL\n MOVBLZX CL,AX",
			"CMPQ AX,BX"},
		{"distinct_call_addresses", "CALL leaf<>(SB)\n MOVQ AX,DX\n LEAQ 24(SP),BP\n CALL leaf<>(SB)\n ADDQ DX,AX",
			"ADDQ $1,(BP)\n MOVQ (BP),AX"},
		{"ordinary_address_register", "LEAQ 16(SP),SI\n CALL leaf<>(SB)",
			"MOVQ (SI),AX\n ADDQ BX,AX\n MOVQ AX,(SI)"},
	}
}

func fixedLocalPrivateLeafSource(body, helper string) string {
	return `TEXT ·Value(SB),4,$80-16
 MOVQ a+0(FP),AX
 MOVQ AX,16(SP)
 MOVQ $7,BX
 MOVQ BX,24(SP)
 LEAQ 16(SP),BP
 ` + body + `
 MOVQ AX,ret+8(FP)
 RET
TEXT leaf<>(SB),4,$0
 ` + helper + `
 RET
`
}

func fixedLocalPrivateLeafFixture(t *testing.T, assembly string, declarations ...string) (GoPackage, GoAMD64FrameCaptureRequest, Options) {
	t.Helper()
	declaration := "func Value(a uint64) uint64"
	if len(declarations) == 1 {
		declaration = declarations[0]
	} else if len(declarations) != 0 {
		t.Fatal("expected at most one actual Go declaration")
	}
	pkg, request := goAMD64FrameTypedFixture(t, declaration, assembly)
	decl := pkg.Types.Scope().Lookup("Value").(*types.Func)
	sig, err := DeriveGoFuncABI0Signature(pkg.Path+".Value", decl, "amd64", types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	return pkg, request, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym: testResolveSym(pkg.Path), Sigs: map[string]FuncSig{sig.Name: sig},
	}
}

func TestGoAMD64FixedLocalPrivateLeafCanonicalResult(t *testing.T) {
	assembly := strings.NewReplacer("$80-16", "$80-9", "MOVQ AX,ret+8(FP)", "MOVB AX,ret+8(FP)").Replace(
		fixedLocalPrivateLeafSource("CALL leaf<>(SB)\n SETCS AL", "CMPQ AX,BX"))
	x86InsertExtractGoListing(t, "amd64", assembly)
	pkg, request, options := fixedLocalPrivateLeafFixture(t, assembly, "func Value(a uint64) bool")
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
		func(t *testing.T, ir string, err error) {
			if err != nil || strings.Count(ir, "define ") != 1 {
				t.Fatal("actual framed canonical result did not retain its ordinary owner", err, ir)
			}
			fixedLocalPrivateLeafObjects(t, ir)
		})
}

func TestGoAMD64FixedLocalPrivateLeafBareSymbol(t *testing.T) {
	assembly := strings.ReplaceAll(fixedLocalPrivateLeafSource("CALL leaf<>(SB)", "MOVQ (BP),AX"), "leaf<>", "leaf")
	x86InsertExtractGoListing(t, "amd64", assembly)
	pkg, request, options := fixedLocalPrivateLeafFixture(t, assembly)
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
		func(t *testing.T, ir string, err error) {
			if err != nil || strings.Count(ir, "define ") != 1 {
				t.Fatal("same-source bare leaf lost its observed source role", err, ir)
			}
			fixedLocalPrivateLeafObjects(t, ir)
		})
}

func TestGoAMD64FixedLocalPrivateLeafWholeVectorResults(t *testing.T) {
	// Both qwords cross CALL, change in the leaf, and return separately.
	// This exercises private vector transport without claiming that the
	// separate GP-to-XMM MOVQ fixed-local owner gap has been implemented.
	assembly := `TEXT ·Value(SB),4,$80-24
 MOVQ a+0(FP),AX
 MOVQ AX,16(SP)
 MOVQ $7,BX
 MOVQ BX,24(SP)
 MOVOU 16(SP),X0
 CALL leaf<>(SB)
 MOVOU X0,32(SP)
 MOVQ 32(SP),AX
 MOVQ 40(SP),BX
 MOVQ AX,first+8(FP)
 MOVQ BX,second+16(FP)
 RET
TEXT leaf<>(SB),4,$0
 PADDQ X0,X0
 RET
`
	x86InsertExtractGoListing(t, "amd64", assembly)
	pkg, request, options := fixedLocalPrivateLeafFixture(t, assembly, "func Value(a uint64) (first, second uint64)")
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
		func(t *testing.T, ir string, err error) {
			if err != nil || strings.Count(ir, "define ") != 1 {
				t.Fatal("complete vector did not return both independent typed results", err, ir)
			}
			fixedLocalPrivateLeafObjects(t, ir)
		})
}

func TestGoAMD64FixedLocalPrivateLeafCompleteSources(t *testing.T) {
	for _, row := range fixedLocalPrivateLeafCases() {
		t.Run(row.name, func(t *testing.T) {
			assembly := fixedLocalPrivateLeafSource(row.body, row.helper)
			// Exact valid FP labels and all original helper TEXTs are assembled
			// before testing the observer or the translator's private contract.
			listing := x86InsertExtractGoListing(t, "amd64", assembly)
			if !strings.Contains(string(listing), "CALL") || !strings.Contains(string(listing), "leaf") {
				t.Fatal("original Go omitted the complete helper call")
			}
			pkg, request, options := fixedLocalPrivateLeafFixture(t, assembly)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal("nonzero root and original zero-frame leaf are not composed", err)
					}
					if strings.Count(ir, "define ") != 1 || !strings.Contains(ir, "fixed_local_native") ||
						strings.Contains(ir, "call void @\"leaf") || strings.Contains(ir, "define void @\"leaf") {
						t.Fatal("leaf acquired an independent ABI or lost its root frame", ir)
					}
					fixedLocalPrivateLeafObjects(t, ir)
				})
		})
	}
}

func fixedLocalPrivateLeafObjects(t *testing.T, ir string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	const target = "x86_64-unknown-linux-gnu"
	compileLLVMToObject(t, llc, target, "private-leaf.ll", "private-leaf.o", ir)
	compileLLVMToObject(t, llc, target, "private-leaf-opt.ll", "private-leaf-opt.o", x86MulDivRoundOptimize(t, ir))
}

func TestGoAMD64FixedLocalPrivateLeafBoundaries(t *testing.T) {
	valid := fixedLocalPrivateLeafSource("CALL leaf<>(SB)", "MOVQ (BP),AX")
	for _, row := range []struct{ name, source string }{
		{"undefined_input", strings.Replace(valid, "MOVQ (BP),AX", "MOVQ R8,AX", 1)},
		{"uninitialized_private", strings.Replace(valid, "MOVQ AX,16(SP)", "NOP", 1)},
		{"outside_private_extent", strings.Replace(valid, "MOVQ (BP),AX", "MOVQ 80(BP),AX", 1)},
		{"callee_SP", strings.Replace(valid, "MOVQ (BP),AX", "MOVQ 16(SP),AX", 1)},
		{"callee_FP", strings.Replace(valid, "MOVQ (BP),AX", "MOVQ a+0(FP),AX", 1)},
		{"callee_nonzero_frame", strings.Replace(valid, "TEXT leaf<>(SB),4,$0", "TEXT leaf<>(SB),4,$8", 1)},
		{"callee_negative_frame", strings.Replace(valid, "TEXT leaf<>(SB),4,$0", "TEXT leaf<>(SB),4,$-8", 1)},
		{"callee_nonleaf", strings.Replace(valid, "MOVQ (BP),AX", "CALL second<>(SB)", 1) + "TEXT second<>(SB),4,$0\n RET\n"},
		{"indirect_call", strings.Replace(valid, "CALL leaf<>(SB)", "CALL AX", 1)},
		{"address_escape", strings.Replace(valid, "CALL leaf<>(SB)", "LEAQ leaf<>(SB),AX\n CALL AX", 1)},
		{"dead_unclosed_helper", valid + "TEXT unused<>(SB),4,$8\n RET\n"},
		{"recursive", strings.Replace(valid, "MOVQ (BP),AX", "CALL leaf<>(SB)", 1)},
		{"missing_flags", strings.Replace(valid, "MOVQ (BP),AX", "SETCS CL\n MOVBLZX CL,AX", 1)},
	} {
		t.Run(row.name, func(t *testing.T) {
			x86InsertExtractGoListing(t, "amd64", row.source)
			pkg, request, options := fixedLocalPrivateLeafFixture(t, row.source)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			switch row.name {
			case "undefined_input", "uninitialized_private", "outside_private_extent", "missing_flags":
				if err != nil {
					t.Fatal("semantic negative requires successful complete original capture", err)
				}
			}
			if err == nil {
				defer owner.Close()
				expanded, readErr := owner.preprocess(request.AssemblyFile, []byte(row.source))
				if readErr != nil {
					t.Fatal(readErr)
				}
				file, parseErr := Parse(ArchAMD64, expanded)
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				_, err = owner.BindFixedLocal(ctx, pkg, file, options)
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unclosed helper/frame/state became authorized", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalPrivateLeafRejectsSuppliedSignature(t *testing.T) {
	for _, symbol := range []string{"leaf<>", "leaf"} {
		t.Run(symbol, func(t *testing.T) {
			assembly := strings.ReplaceAll(fixedLocalPrivateLeafSource("CALL leaf<>(SB)", "MOVQ (BP),AX"), "leaf<>", symbol)
			x86InsertExtractGoListing(t, "amd64", assembly)
			pkg, request, options := fixedLocalPrivateLeafFixture(t, assembly)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if err != nil {
				t.Fatal("complete original source precondition", err)
			}
			defer owner.Close()
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			name := options.ResolveSym(symbol)
			options.Sigs[name] = FuncSig{Name: name, Ret: Void}
			if _, err := owner.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) ||
				!strings.Contains(err.Error(), "private leaf cannot acquire a supplied callable signature") {
				t.Fatal("public binding silently discarded a caller-supplied helper ABI", err)
			}
		})
	}
}

func TestGoAMD64SDKFramePrivateLeafWholeOriginalSource(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "vendor/golang.org/x/crypto/chacha20poly1305")
	original, err := CaptureGoAMD64SDKFrameObservation(ctx, request)
	if err != nil {
		t.Fatal("complete actual SDK precondition", err)
	}
	defer original.Close()
	pkg := sdkAMD64FrameActualPackage(t, original.source)
	owner, err := CaptureGoAMD64SDKFrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, Target: request.Target,
		AssemblyFile: "chacha20poly1305_amd64.s", Environment: request.Environment,
	})
	if err != nil {
		t.Fatal("complete original leaf and declared root observation", err)
	}
	defer owner.Close()
	if len(owner.functions) != 3 || len(owner.declarations) != 2 {
		t.Fatal("complete original TEXT inventory or actual declarations changed",
			len(owner.functions), len(owner.declarations))
	}
	for _, name := range []string{"chacha20Poly1305Open", "chacha20Poly1305Seal"} {
		fn, found := owner.functions[pkg.Path+"."+name]
		if !found || fn.signature.Name != pkg.Path+"."+name || fn.locals != 296 {
			t.Fatal("root lost its actual Go signature or physical frame", name)
		}
	}
	leaves := 0
	for name, fn := range owner.functions {
		if strings.Contains(name, "polyHashADInternal") {
			leaves++
			if fn.signature.Name != "" || len(fn.code) == 0 {
				t.Fatal("leaf gained a Go signature or lost original bytes", name)
			}
		}
	}
	if leaves != 1 {
		t.Fatal("complete original inventory lost or duplicated its leaf", leaves)
	}
	for _, cpp := range owner.sdkFrame.owner.source.observation.CPP {
		file, err := Parse(ArchAMD64, cpp.Output)
		if err != nil {
			t.Fatal(err)
		}
		for _, fn := range file.Funcs {
			t.Logf("complete original TEXT %s: %d parsed non-label instructions", fn.Sym, len(x86DirectTailInstructions(fn)))
		}
	}
	if err := owner.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	t.Logf("all %d original TEXTs observed; this capture alone is not translation coverage", len(owner.functions))
}
