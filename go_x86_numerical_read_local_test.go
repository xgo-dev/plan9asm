//go:build go1.27

package plan9asm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestGoX86NumericalSBReadComposesOnlyWithActualFixedLocalOwner(t *testing.T) {
	ctx, pkg, request, file, bound, _, _ := numericalLocalFactory(t)
	request.NumericalReads = bound.NumericalReads
	local, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal("independent actual Go framed object precondition failed", err)
	}
	defer local.Close()
	bound, err = local.BindFixedLocal(ctx, pkg, file, bound)
	if err != nil {
		t.Fatal("certified numerical reads did not compose with complete actual local proof", err)
	}
	numericalLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
		if err != nil || !strings.Contains(ir, "fixed_local_native") || strings.Count(ir, "load volatile") < 22 {
			t.Fatal("complete frozen local/read consumer lost an independent owner or native read", err)
		}
		numericalLLVM22Axes(t, ir, bound.TargetTriple, nil)
	})
}

func TestGoAMD64FixedLocalFrameCopiedCapabilityCannotBorrowGeneration(t *testing.T) {
	pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	frame := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bound, err := frame.BindFixedLocal(ctx, pkg, file, options)
	if err != nil {
		t.Fatal("default actual local binding precondition", err)
	}
	original := bound.Sigs[pkg.Path+".Value"].x86FixedLocal
	if original == nil {
		t.Fatal("default factory did not issue a private local capability")
	}
	copied := *original
	if !errors.Is(copied.verify(), ErrProbeNeedsContext) {
		t.Fatal("default whole-value copy borrowed original frame generation")
	}
	if err := original.verify(); err != nil {
		t.Fatal("copy rejection revoked default original generation", err)
	}
	for name, sig := range bound.Sigs {
		sig.x86FixedLocal = &copied
		bound.Sigs[name] = sig
	}
	fixedLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
		if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("default consumer accepted whole-value copied local capability", err)
		}
	})
}

func numericalLocalJoinedFactory(t *testing.T) (context.Context, GoPackage, *File, Options, *GoX86NumericalReadSource, *GoAMD64FrameSource) {
	t.Helper()
	ctx, pkg, request, file, bound, source, _ := numericalLocalFactory(t)
	request.NumericalReads = bound.NumericalReads
	frame, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal("complete original frame/read producer precondition", err)
	}
	t.Cleanup(func() {
		if err := frame.Close(); err != nil {
			t.Error(err)
		}
	})
	bound, err = frame.BindFixedLocal(ctx, pkg, file, bound)
	if err != nil {
		t.Fatal("complete independent local/read consumer precondition", err)
	}
	return ctx, pkg, file, bound, source, frame
}

func TestGoX86NumericalSBReadLocalCapabilityCannotBeCopiedAndRebound(t *testing.T) {
	ctx, pkg, file, bound, source, _ := numericalLocalJoinedFactory(t)
	var original *x86FixedLocalBinding
	for _, sig := range bound.Sigs {
		if sig.x86FixedLocal == nil || original != nil && original != sig.x86FixedLocal {
			t.Fatal("fixture did not retain one complete actual local capability")
		}
		original = sig.x86FixedLocal
	}
	if original == nil {
		t.Fatal("fixture has no actual local capability")
	}
	copied := *original
	for name, sig := range bound.Sigs {
		sig.x86FixedLocal = &copied
		bound.Sigs[name] = sig
	}
	bound.NumericalReads = nil
	changed, err := source.BindNumericalReads(ctx, pkg, file, bound)
	if changed.NumericalReads != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("whole-value copied local capability issued a fresh numerical token", err)
	}
	if err := original.verify(); err != nil {
		t.Fatal("copy rejection revoked the independent original local capability", err)
	}
}

func TestGoX86NumericalSBReadLocalCapabilityDifferentActualOwner(t *testing.T) {
	ctx, pkg, file, bound, source, frame := numericalLocalJoinedFactory(t)
	foreign, err := CaptureGoAMD64FrameSource(ctx, pkg, frame.request)
	if err != nil {
		t.Fatal("different actual frame owner precondition", err)
	}
	defer foreign.Close()
	for _, sig := range bound.Sigs {
		sig.x86FixedLocal.source = foreign
	}
	bound.NumericalReads = nil
	changed, err := source.BindNumericalReads(ctx, pkg, file, bound)
	if changed.NumericalReads != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("different actual owner replaced the original local capability generation", err)
	}
}

func TestGoX86NumericalSBReadLocalCapabilityConsumerGuards(t *testing.T) {
	for _, name := range []string{"wrong capability", "copied capability", "revoked frame", "missing local capability", "missing numerical token"} {
		t.Run(name, func(t *testing.T) {
			_, pkg, file, bound, _, frame := numericalLocalJoinedFactory(t)
			switch name {
			case "wrong capability", "copied capability", "missing local capability":
				var replacement *x86FixedLocalBinding
				if name == "wrong capability" {
					replacement = &x86FixedLocalBinding{}
				} else if name == "copied capability" {
					for _, sig := range bound.Sigs {
						copied := *sig.x86FixedLocal
						replacement = &copied
						break
					}
				}
				for symbol, sig := range bound.Sigs {
					sig.x86FixedLocal = replacement
					bound.Sigs[symbol] = sig
				}
			case "revoked frame":
				if err := frame.Close(); err != nil {
					t.Fatal(err)
				}
			case "missing numerical token":
				bound.NumericalReads = nil
			}
			numericalLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("changed independent capability published native local/read output", err)
				}
			})
		})
	}
}

func TestGoX86NumericalSBReadUnboundNativeLocalRemainsContext(t *testing.T) {
	_, pkg, _, file, bound, _, _ := numericalLocalFactory(t)
	numericalLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
		if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("numerical read token alone authorized native local frame memory", err)
		}
	})
}

func numericalLocalAPIs(t *testing.T, pkg GoPackage, file *File, options Options, check func(*testing.T, string, error)) {
	t.Helper()
	for _, api := range []string{"text", "module", "context", "go-module"} {
		t.Run(api, func(t *testing.T) {
			if api == "text" {
				ir, err := Translate(file, options)
				check(t, ir, err)
				return
			}
			context := llvm.NewContext()
			defer context.Dispose()
			var module llvm.Module
			var err error
			switch api {
			case "module":
				module, err = TranslateModule(file, options)
			case "context":
				module, err = TranslateModuleInContext(context, file, options)
			case "go-module":
				var directory, assemblyFile string
				if options.NumericalReads != nil {
					source := options.NumericalReads.source
					directory, assemblyFile = source.request.Directory, source.request.AssemblyFile
				} else {
					for _, sig := range options.Sigs {
						if sig.x86FixedLocal != nil && sig.x86FixedLocal.source != nil {
							source := sig.x86FixedLocal.source
							directory, assemblyFile = source.request.Directory, source.request.AssemblyFile
							break
						}
					}
				}
				if directory == "" || assemblyFile == "" {
					t.Fatal("wrapper fixture lost its original input path")
				}
				data, readErr := os.ReadFile(filepath.Join(directory, assemblyFile))
				if readErr != nil {
					t.Fatal(readErr)
				}
				result, translateErr := TranslateGoModule(pkg, data, GoModuleOptions{
					GOARCH: options.Goarch, GOOS: "linux", TargetTriple: options.TargetTriple,
					FileName: assemblyFile, NumericalReads: options.NumericalReads,
					ResolveSym: options.ResolveSym,
				})
				err = translateErr
				if result != nil {
					module = result.Module
				}
			}
			ir := ""
			if !module.IsNil() {
				ir = module.String()
				module.Dispose()
			}
			check(t, ir, err)
		})
	}
}

func numericalLocalFactory(t *testing.T) (context.Context, GoPackage, GoAMD64FrameCaptureRequest, *File, Options, *GoX86NumericalReadSource, context.CancelFunc) {
	return numericalLocalFactoryWithContext(t, nil)
}

func numericalLocalFactoryWithContext(t *testing.T, wrap func(context.Context) context.Context) (context.Context, GoPackage, GoAMD64FrameCaptureRequest, *File, Options, *GoX86NumericalReadSource, context.CancelFunc) {
	t.Helper()
	pkg, request, initial, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	_, numericalProfile, _, _ := numericalSBFixture(t, "amd64")
	request.GoBinary, request.Environment = numericalProfile.GoBinary, numericalProfile.Environment
	options.ResolveSym = func(symbol string) string { return numericalNativeName(symbol, pkg.Path) }
	var err error
	request.Directory, err = filepath.EvalSymlinks(request.Directory)
	if err != nil {
		t.Fatal(err)
	}
	var reads strings.Builder
	for _, row := range numericalSBOracleRows {
		partner := "AX"
		if strings.HasPrefix(row.op, "CMP") {
			partner = "$1"
		}
		fmt.Fprintf(&reads, "%s internal∕cpu·X86+64(SB),%s\n", row.op, partner)
	}
	assembly := strings.Replace(fixedLocalVoidAssembly(initial), "MOVQ AX,16(SP)", reads.String()+"MOVQ AX,16(SP)", 1)
	if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte(assembly), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleProofContext(t)
	t.Cleanup(cancel)
	if wrap != nil {
		ctx = wrap(ctx)
	}
	owner, err := CaptureGoNumericalStorageOwner(ctx, GoNumericalStorageCaptureRequest{
		GoBinary: request.GoBinary, Directory: filepath.Join(filepath.Dir(filepath.Dir(request.GoBinary)), "src", "internal", "cpu"),
		PackagePath: "internal/cpu", Target: request.Target, Environment: request.Environment, SDKCPU: true,
		Variables: []GoNumericalStorageReference{{PackagePath: "internal/cpu", Name: "X86"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	numerical, err := CaptureGoX86NumericalReadSource(ctx, GoX86NumericalReadCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, PackagePath: pkg.Path,
		AssemblyFile: request.AssemblyFile, Target: request.Target, Environment: request.Environment,
		Owners: []*GoNumericalStorageOwner{owner},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := numerical.Close(); err != nil {
			t.Error(err)
		}
	})
	if len(numerical.reads) != 22 {
		t.Fatal("actual complete original family did not bind all numerical reads", len(numerical.reads))
	}
	bound, err := numerical.BindNumericalReads(ctx, pkg, file, options)
	if err != nil {
		t.Fatal("independent original numerical read precondition failed", err)
	}
	return ctx, pkg, request, file, bound, numerical, cancel
}

func TestGoX86NumericalSBReadFrameProducerExactObjectJoin(t *testing.T) {
	ctx, pkg, request, file, bound, numerical, _ := numericalLocalFactory(t)
	unbound, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil || unbound == nil {
		t.Fatal("complete original relocation observation was rejected", err)
	}
	defer unbound.Close()
	// Recording original bytes/relocations does not bind their numerical
	// consumer. Keep both the missing-owner and foreign-owner boundaries.
	withoutNumerical := bound
	withoutNumerical.NumericalReads = nil
	for _, options := range []Options{withoutNumerical, bound} {
		if _, err := unbound.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("default frame observation acquired a numerical read binding", err)
		}
	}
	request.NumericalReads = bound.NumericalReads
	frame, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal("independent complete original frame/numerical object join", err)
	}
	defer frame.Close()
	if err := frame.Verify(ctx); err != nil || len(frame.functions) != len(numerical.native.OriginalText) {
		t.Fatal("complete joined actual frame observation failed verification", err)
	}
	retainNumericalRead(t, numerical, "frame-join")
	retainNumericalFrame(t, frame)
}

func retainNumericalFrame(t *testing.T, frame *GoAMD64FrameSource) {
	t.Helper()
	artifact := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR")
	if artifact == "" {
		return
	}
	frame.mu.Lock()
	defer frame.mu.Unlock()
	folder := filepath.Join(artifact, "linux-amd64", "numerical-read-frame-join")
	if err := os.MkdirAll(folder, 0700); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".o", ".o.listing"} {
		data, err := os.ReadFile(filepath.Join(frame.owned, frame.request.AssemblyFile+suffix))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(folder, "frame-original"+suffix), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	type function struct {
		ObjectSymbol, ListingSymbol string
		Locals, Args                int64
		Code                        []byte
		Positions                   map[int]string
		Signature                   FuncSig
		Transport                   goAMD64FrameTransport
		LanguageType                string
	}
	functions := make(map[string]function, len(frame.functions))
	for name, fn := range frame.functions {
		functions[name] = function{fn.objectSymbol, fn.listingSymbol, fn.locals, fn.args, fn.code,
			fn.positions, fn.signature, fn.transport, fn.languageType}
	}
	data, err := json.MarshalIndent(struct {
		Directory, GoBinary, AssemblyFile, Target string
		Environment                               []string
		ActualEnvironment                         map[string]string
		Selection                                 goAMD64FrameSelection
		Inputs                                    map[string][32]byte
		Functions                                 map[string]function
		Commands                                  []numericalSBCommand
		NumericalSeal                             [32]byte
	}{frame.request.Directory, frame.request.GoBinary, frame.request.AssemblyFile, frame.request.Target,
		frame.request.Environment, frame.env, frame.selection, frame.inputs, functions,
		frame.numericalCommands, frame.numericalSeal}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "frame-observation.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}
