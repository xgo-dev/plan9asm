package plan9asm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixedLocalVoidFixture(t *testing.T, operation string) (GoPackage, GoAMD64FrameCaptureRequest, *File, Options) {
	t.Helper()
	original, _, _ := x86PrivateAlignedFrameAuditFixture(t, operation)
	assembly := strings.Replace(original, "$160-40", "$160-32", 1)
	assembly = strings.Replace(assembly, "MOVQ AX,ret+32(FP)\n", "", 1)
	pkg, request := goAMD64FrameTypedFixture(t, "func Value(a, b, c, d uint64)", assembly)
	sig, err := DeriveGoFuncABI0Signature(pkg.Path+".Value", pkg.Types.Scope().Lookup("Value").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	return pkg, request, file, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", pkg.Path+".", 1) },
		Sigs:       map[string]FuncSig{sig.Name: sig},
	}
}

func fixedLocalVoidAssembly(file *File) string {
	var source strings.Builder
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			source.WriteString(ins.Raw + "\n")
		}
	}
	return source.String()
}

func TestGoAMD64FixedLocalVoidActualTargetBoundaries(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range []struct{ goTarget, triple string }{
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
		{"linux/386", "i386-unknown-linux-gnu"},
		{"windows/386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.goTarget, func(t *testing.T) {
			pkg, request, file, options := fixedLocalVoidFixture(t, "PADDQ 16(SP),X0")
			request.Target, options.TargetTriple = target.goTarget, target.triple
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if strings.HasSuffix(target.goTarget, "/386") || target.goTarget == "windows/amd64" && err != nil {
				if source != nil || !errors.Is(err, ErrProbeNeedsContext) ||
					target.goTarget == "windows/amd64" && !strings.Contains(err.Error(), "SSEHUNWINDINFO") {
					t.Fatalf("unclosed target unexpectedly acquired void backing: %v", err)
				}
				t.Logf("unchanged original target observation boundary, not an LLVM object: %v", err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			})
			bound, err := source.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatal(err)
			}
			fixedLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, target.triple, "void-target.ll", "void-target.o", ir)
			})
		})
	}
}

func TestGoAMD64FixedLocalVoidAllPathMemoryAndReturnNegatives(t *testing.T) {
	pkg, _, file, options := fixedLocalVoidFixture(t, "PADDQ 16(SP),X0")
	base, sig := fixedLocalVoidAssembly(file), options.Sigs[pkg.Path+".Value"]
	mutations := map[string]string{
		"SP not restored":      strings.Replace(base, "MOVQ R11,SP", "MOVQ $0,R10", 1),
		"incoming BP read":     strings.Replace(base, "MOVQ AX,16(SP)", "MOVQ BP,AX\nMOVQ AX,16(SP)", 1),
		"incoming R14 read":    strings.Replace(base, "MOVQ AX,16(SP)", "MOVQ R14,AX\nMOVQ AX,16(SP)", 1),
		"input FP store":       strings.Replace(base, "MOVQ X0,AX", "MOVQ AX,a+0(FP)", 1),
		"private FP escape":    strings.Replace(base, "MOVQ X0,AX", "MOVQ R11,a+0(FP)", 1),
		"restored input store": strings.Replace(base, "MOVQ R11,SP\nRET", "MOVQ R11,SP\nMOVQ AX,a+0(FP)\nRET", 1),
		"restored FP escape":   strings.Replace(base, "MOVQ R11,SP\nRET", "MOVQ R11,SP\nMOVQ R11,a+0(FP)\nRET", 1),
		"external escape":      strings.Replace(base, "MOVQ X0,AX", "MOVQ R11,(AX)", 1),
		"unbound local alias":  strings.Replace(base, "PADDQ 16(SP)", "PADDQ 16(SI)", 1),
		"private read extent":  strings.Replace(base, "PADDQ 16(SP)", "PADDQ 152(SP)", 1),
		"saved BP overlap":     strings.Replace(base, "MOVQ AX,16(SP)", "MOVQ AX,160(SP)", 1),
		"bad alignment":        strings.Replace(base, "ADDQ $32,SP", "ADDQ $33,SP", 1),
		"pointer as numeric":   strings.Replace(base, "PADDQ 16(SP)", "PADDQ 96(SP)", 1),
		"pointer spill torn":   strings.Replace(base, "MOVQ 96(SP),R11", "MOVB $1,96(SP)\nMOVQ 96(SP),R11", 1),
		"raw instruction":      strings.Replace(base, "PADDQ", "BYTE $0x90\nPADDQ", 1),
		"unknown native call":  strings.Replace(base, "PADDQ", "CALL ·Other(SB)\nPADDQ", 1),
		"unknown dead effect":  base + "SYSCALL\n",
		"loop unknown input":   strings.Replace(base, "MOVQ AX,16(SP)", "again:\nCMPQ AX,R10\nJNE again\nMOVQ AX,16(SP)", 1),
		"overflow address":     strings.Replace(base, "ADDQ $32,SP", "ADDQ $9223372036854775807,SP", 1),
	}
	for missing := 0; missing < 16; missing++ {
		var stores strings.Builder
		for index := 0; index < 16; index++ {
			if index != missing {
				fmt.Fprintf(&stores, "MOVB $1,%d(SP)\n", 16+index)
			}
		}
		mutations[fmt.Sprintf("missing local byte %02d", missing)] = strings.Replace(base, "MOVQ AX,16(SP)\nMOVQ CX,24(SP)\n", stores.String(), 1)
	}
	for name, source := range mutations {
		t.Run(name, func(t *testing.T) {
			changed, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := proveX86FixedLocal(changed.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("void return bypassed complete source safety: %v", err)
			}
		})
	}
	for _, mutation := range []string{"nonvoid no result", "void result slot", "empty return", "multiple result slots"} {
		t.Run(mutation, func(t *testing.T) {
			changed := sig
			switch mutation {
			case "nonvoid no result":
				changed.Ret = I64
			case "empty return":
				changed.Ret = ""
			case "void result slot":
				changed.Frame.Results = []FrameSlot{{Offset: 32, Type: I64}}
			case "multiple result slots":
				changed.Ret = I64
				changed.Frame.Results = []FrameSlot{{Offset: 32, Type: I64}, {Offset: 40, Type: I64}}
			}
			if _, err := proveX86FixedLocal(file.Funcs[0], changed); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("inconsistent result contract obtained a void exemption: %v", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalVoidActualDAGInitialization(t *testing.T) {
	pkg, request, file, options := fixedLocalVoidFixture(t, "PADDQ 16(SP),X0")
	base := fixedLocalVoidAssembly(file)
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprintf("missing=%v", missing), func(t *testing.T) {
			join := "MOVQ CX,24(SP)\nCMPQ AX,CX\nJEQ joined\nMOVQ CX,24(SP)\njoined:"
			if missing {
				join = "CMPQ AX,CX\nJEQ joined\nMOVQ CX,24(SP)\njoined:"
			}
			assembly := strings.Replace(base, "MOVQ CX,24(SP)", join, 1)
			if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte(assembly), 0600); err != nil {
				t.Fatal(err)
			}
			actual, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			source := requireGoAMD64FrameCapture(t, pkg, request)
			// Complete actual Go objects accept both bodies. Only the all-path
			// initialized body may obtain the separate private-byte certificate.
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			bound, err := source.BindFixedLocal(ctx, pkg, actual, options)
			if missing {
				if !errors.Is(err, ErrProbeNeedsContext) || len(bound.Sigs) != 0 {
					t.Fatalf("void DAG bypassed a missing predecessor write: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			fixedLocalAPIs(t, pkg, actual, bound, func(t *testing.T, ir string, err error) {
				if err != nil || !strings.Contains(ir, "fixed_local_native") {
					t.Fatalf("actual initialized void DAG did not consume its certificate: %v", err)
				}
			})
		})
	}
}

func TestGoAMD64FixedLocalVoidCompositeNeedsCompleteBinding(t *testing.T) {
	for _, test := range []struct {
		name, declaration string
		args, n           int64
	}{
		{"pointer", "func Value(a *uint64, n uint64)", 16, 8},
		{"slice", "func Value(a []byte, n uint64)", 32, 24},
		{"array pointer", "func Value(a *[16]byte, n uint64)", 16, 8},
	} {
		t.Run(test.name, func(t *testing.T) {
			assembly := fixedLocalTransportAssembly("Value", int(test.args), "")
			assembly = strings.Replace(assembly, "n+40(FP)", fmt.Sprintf("n+%d(FP)", test.n), 1)
			pkg, request := goAMD64FrameTypedFixture(t, test.declaration, assembly)
			source := requireGoAMD64FrameCapture(t, pkg, request)
			observed := source.functions[pkg.Path+".Value"]
			if observed.transport != goAMD64FrameCompositeTransport || observed.signature.Ret != Void || len(observed.code) == 0 {
				t.Fatal("void composite observation lost its original role/object")
			}
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{
				Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", pkg.Path+".", 1) },
				Sigs:       map[string]FuncSig{observed.signature.Name: observed.signature},
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			fixedLocalAPIs(t, pkg, file, options, fixedLocalRequireContext)
			if bound, err := source.BindFixedLocal(ctx, pkg, file, options); err != nil || len(bound.Sigs) != 1 {
				t.Fatalf("complete void composite transport lacks its independent frame proof: %v", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalVoidThreeAPIsRequireExactLiveWitness(t *testing.T) {
	pkg, request, file, options := fixedLocalVoidFixture(t, "PADDQ 16(SP),X0")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bound, err := source.BindFixedLocal(ctx, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	name := pkg.Path + ".Value"
	for _, mutation := range []string{"JSON", "return", "input slot", "source"} {
		t.Run(mutation, func(t *testing.T) {
			changed := bound
			changed.Sigs, err = cloneFixedLocalSigs(bound.Sigs)
			if err != nil {
				t.Fatal(err)
			}
			sig := changed.Sigs[name]
			if mutation != "JSON" {
				sig.x86FixedLocal = bound.Sigs[name].x86FixedLocal
			}
			changedFile := *file
			changedFile.Funcs = append([]Func(nil), file.Funcs...)
			switch mutation {
			case "return":
				sig.Ret = I64
			case "input slot":
				sig.Frame.Params[0].Offset++
			case "source":
				changedFile.Funcs[0].FrameSize += 8
				changedFile.Funcs[0].Instrs = append([]Instr(nil), file.Funcs[0].Instrs...)
				changedFile.Funcs[0].Instrs[0].Raw = strings.Replace(changedFile.Funcs[0].Instrs[0].Raw, "$160-32", "$168-32", 1)
			}
			changed.Sigs[name] = sig
			fixedLocalAPIs(t, pkg, &changedFile, changed, fixedLocalRequireContext)
		})
	}
	for _, mutation := range fixedLocalTypedRoleMutations {
		t.Run(mutation, func(t *testing.T) {
			fixedLocalTypedRoleMutation(t, source, name, mutation)
			fixedLocalAPIs(t, pkg, file, bound, fixedLocalRequireContext)
		})
	}
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var clone GoAMD64FrameSource
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	if _, err := clone.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("JSON clone recreated void source authority: %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	fixedLocalAPIs(t, pkg, file, bound, fixedLocalRequireContext)
	if _, err := source.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("closed observer rebound void source: %v", err)
	}
	// Cancellation revokes a separately captured live void binding too, not
	// merely the already closed source used above.
	pkg, request, file, options = fixedLocalVoidFixture(t, "PADDQ 16(SP),X0")
	source = requireGoAMD64FrameCapture(t, pkg, request)
	child, stop := context.WithCancel(ctx)
	defer stop()
	bound, err = source.BindFixedLocal(child, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	fixedLocalAPIs(t, pkg, file, bound, fixedLocalRequireContext)
	if source.ready {
		t.Fatal("cancelled binding retained a live source token")
	}
}

func TestGoAMD64FixedLocalVoidActualNumericSourceAndObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, operation := range fixedLocalNativeOperations {
		t.Run(strings.Fields(operation)[0], func(t *testing.T) {
			pkg, request, file, options := fixedLocalVoidFixture(t, operation)
			source := requireGoAMD64FrameCapture(t, pkg, request)
			observed := source.functions[pkg.Path+".Value"]
			if observed.transport != goAMD64FrameNumericTransport || observed.signature.Ret != Void ||
				len(observed.signature.Frame.Results) != 0 || observed.args != 32 || observed.locals != 168 || len(observed.code) == 0 {
				t.Fatalf("void fixture lacks complete actual numeric Go object identity: %+v", observed)
			}
			object := filepath.Join(source.owned, request.AssemblyFile+".o")
			t.Logf("actual stock-Go void object: args=%d locals=%d bytes=%d object_sha=%x listing_sha=%x", observed.args, observed.locals, len(observed.code), source.inputs[object], source.inputs[object+".listing"])
			// The ordinary translation API must still lack native backing before
			// the live source token binds this complete numeric function.
			fixedLocalAPIs(t, pkg, file, options, fixedLocalRequireContext)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			bound, err := source.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatalf("actual Go accepted the numeric void source but its local backing is rejected: %v", err)
			}
			fixedLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
				if err != nil || !strings.Contains(ir, "define void") || !strings.Contains(ir, "fixed_local_native") || !strings.Contains(ir, "asm sideeffect") {
					t.Fatalf("sealed void source failed its compile-only native consumer: %v", err)
				}
				compileLLVMToObject(t, llc, bound.TargetTriple, "void-local.ll", "void-local.o", ir)
				compileLLVMToObject(t, llc, bound.TargetTriple, "void-local-opt.ll", "void-local-opt.o", x86MulDivRoundOptimize(t, ir))
			})
			if _, err := os.Stat(object); err != nil {
				t.Fatal(err)
			}
			t.Log("compile-only void local operations; no observable numerical result or external-library runtime claim")
		})
	}
}
