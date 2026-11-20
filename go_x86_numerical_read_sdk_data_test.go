//go:build go1.27

package plan9asm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// The source, generated header, assembly, object, CPU variable and initializer
// are actual independently captured SDK inputs. No instruction, DATA, feature
// offset, package declaration or original byte is replaced for this witness.
func numericalSDKLiteralFixture(t *testing.T) (context.Context, GoX86NumericalReadCaptureRequest, *GoX86SDKASMDataSource) {
	t.Helper()
	ctx, request, _ := numericalSDKCRC32Request(t)
	source, err := CaptureGoX86SDKASMDataSource(ctx, GoX86SDKASMDataCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, PackagePath: request.PackagePath,
		Target: request.Target, Environment: request.Environment,
	})
	if err != nil {
		t.Fatal("actual complete SDK source/header/CPP/object precondition", err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	owner, err := CaptureGoX86SDKReadonlyLiteralDataOwner(ctx, source)
	if err != nil {
		t.Fatal("actual complete SDK literal initializer precondition", err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	request.ReadonlyLiterals = owner
	return ctx, request, source
}

func numericalSDKLiteralPackage(t *testing.T, source *GoX86SDKASMDataSource, name string) (GoPackage, *File, Options) {
	t.Helper()
	pkg, file, options := numericalSDKOriginalTypedPackage(t, source, name)
	for _, fn := range file.Funcs {
		name := strings.TrimPrefix(goStripABISuffix(fn.Sym), "·")
		declaration, ok := pkg.Types.Scope().Lookup(name).(*types.Func)
		if !ok {
			t.Fatal("original TEXT lacks its actual Go function declaration", fn.Sym)
		}
		name = numericalNativeName(goStripABISuffix(fn.Sym), pkg.Path)
		sig, err := DeriveGoFuncABI0Signature(name, declaration, options.Goarch, types.SizesFor("gc", options.Goarch))
		if err != nil {
			t.Fatal(err)
		}
		options.Sigs[name] = sig
	}
	return pkg, file, options
}

// Retain one complete actual source/export/type importer for declaration-only
// members and whole-source graphs. This supplies no private helper signature.
func numericalSDKOriginalTypedPackage(t *testing.T, source *GoX86SDKASMDataSource, name string) (GoPackage, *File, Options) {
	t.Helper()
	fset := token.NewFileSet()
	var syntax []*ast.File
	for _, name := range source.guard.selection.GoFiles {
		filename := filepath.Join(source.request.Directory, name)
		file, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
		if err != nil {
			t.Fatal("original complete selected SDK Go source", err)
		}
		syntax = append(syntax, file)
	}
	imports := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		if mapped, found := source.guard.selection.ImportMap[path]; found {
			path = mapped
		}
		selected, found := source.guard.imports[path]
		if !found || selected.Export == "" {
			return nil, fmt.Errorf("missing actual SDK dependency export: %s", path)
		}
		return os.Open(selected.Export)
	})
	_, arch, paired := strings.Cut(source.request.Target, "/")
	if !paired || numericalSDKTargetTriple(source.request.Target) == "" {
		t.Fatal("missing actual SDK target", source.request.Target)
	}
	sizes := types.SizesFor("gc", arch)
	typed, err := (&types.Config{Sizes: sizes, Importer: imports, GoVersion: "go1.27"}).Check(source.request.PackagePath, fset, syntax, nil)
	if err != nil {
		t.Fatal("independently typed original complete SDK package", err)
	}
	pkg := GoPackage{Path: typed.Path(), Types: typed, Syntax: syntax, Imports: make(map[string]*types.Package)}
	for _, dependency := range typed.Imports() {
		pkg.Imports[dependency.Path()] = dependency
	}
	ordinal := -1
	for index, selected := range source.guard.selection.SFiles {
		if selected == name {
			if ordinal != -1 {
				t.Fatal("ambiguous original selected SDK assembly")
			}
			ordinal = index
		}
	}
	if ordinal < 0 || ordinal >= len(source.observation.CPP) {
		t.Fatal("missing complete SDK assembly CPP observation")
	}
	file, err := Parse(ArchAMD64, source.observation.CPP[ordinal].Output)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: arch, TargetTriple: numericalSDKTargetTriple(source.request.Target),
		Sigs: make(map[string]FuncSig), ResolveSym: func(symbol string) string {
			return numericalNativeName(goTextSymbolForResolution(symbol), pkg.Path)
		}}
	return pkg, file, options
}

func TestGoX86SDKNumericalReadLiteralOriginalCRC32LLVM22(t *testing.T) {
	ctx, request, observed := numericalSDKLiteralFixture(t)
	pkg, file, options := numericalSDKLiteralPackage(t, observed, request.AssemblyFile)
	if len(file.Funcs) != 3 || len(file.Globl) != 4 {
		t.Fatal("original complete CRC assembly changed; update the independent inventory")
	}
	source, err := CaptureGoX86SDKNumericalReadSource(ctx, request)
	if err != nil {
		t.Fatal("live initializer and CPU owner do not compose through the original SDK source", err)
	}
	t.Cleanup(func() { closeNumericalConsumerSource(t, source) })
	bound, err := source.BindNumericalReads(ctx, pkg, file, options)
	if err != nil {
		t.Fatal("complete original SDK numerical/data binding", err)
	}
	if len(source.reads) != 1 || source.reads[0].variable.NativeName != "internal/cpu.X86" || source.reads[0].width != 1 {
		t.Fatal("private literals acquired numerical Go variable authority")
	}
	for _, api := range []string{"text", "module", "go-module"} {
		t.Run(api, func(t *testing.T) {
			ir := numericalFamilyTranslate(t, api, pkg, file, bound)
			requireCRC32TargetFeatures(t, ir)
			if !strings.Contains(ir, "load volatile i8") || !strings.Contains(ir, "external global [") ||
				strings.Count(ir, "internal constant [") != 4 || !strings.Contains(ir, "align 32") {
				t.Fatal("original mutable CPU read/private literal roles differ", ir)
			}
			numericalLLVM22Axes(t, ir, options.TargetTriple, nil)
		})
	}
}

func TestGoX86SDKNumericalReadLiteralRequestBoundaries(t *testing.T) {
	ctx, request, observed := numericalSDKLiteralFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*GoX86NumericalReadCaptureRequest)
	}{
		{"different package", func(r *GoX86NumericalReadCaptureRequest) { r.PackagePath = "internal/chacha8rand" }},
		{"different directory", func(r *GoX86NumericalReadCaptureRequest) { r.Directory = filepath.Dir(r.Directory) }},
		{"different target", func(r *GoX86NumericalReadCaptureRequest) { r.Target = "linux/386" }},
		{"unselected assembly", func(r *GoX86NumericalReadCaptureRequest) { r.AssemblyFile = "unselected_amd64.s" }},
		{"different tool", func(r *GoX86NumericalReadCaptureRequest) { r.GoBinary += ".foreign" }},
		{"different profile", func(r *GoX86NumericalReadCaptureRequest) {
			r.Environment = append(append([]string(nil), r.Environment...), "GOFLAGS=-N")
		}},
		{"copied literal owner", func(r *GoX86NumericalReadCaptureRequest) {
			copy := reflect.New(reflect.TypeOf(r.ReadonlyLiterals).Elem())
			copy.Elem().Set(reflect.ValueOf(r.ReadonlyLiterals).Elem())
			r.ReadonlyLiterals = copy.Interface().(*GoX86SDKReadonlyLiteralDataOwner)
		}},
		{"uncaptured literal owner", func(r *GoX86NumericalReadCaptureRequest) {
			r.ReadonlyLiterals = new(GoX86SDKReadonlyLiteralDataOwner)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := request
			test.mutate(&changed)
			source, err := CaptureGoX86SDKNumericalReadSource(ctx, changed)
			if source != nil {
				closeNumericalConsumerSource(t, source)
			}
			if source != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("foreign source/profile/owner published a numerical token", err)
			}
			if err := request.ReadonlyLiterals.Verify(ctx); err != nil {
				t.Fatal("failed join revoked the independent original initializer", err)
			}
			if err := observed.Verify(ctx); err != nil {
				t.Fatal("failed join changed the independent SDK source", err)
			}
		})
	}
	if source, err := CaptureGoX86NumericalReadSource(ctx, request); source != nil || !errors.Is(err, ErrProbeNeedsContext) {
		if source != nil {
			closeNumericalConsumerSource(t, source)
		}
		t.Fatal("ordinary owned-main factory borrowed an SDK literal role", err)
	}
}

func TestGoX86SDKNumericalReadLiteralCompleteBindingBoundaries(t *testing.T) {
	ctx, request, observed := numericalSDKLiteralFixture(t)
	pkg, original, originalOptions := numericalSDKLiteralPackage(t, observed, request.AssemblyFile)
	// These cases mutate only caller-owned file/options copies, not the SDK
	// source, owners or capture profile. Keep one live observation and actually
	// reverify it per case instead of recapturing the complete SDK each time.
	source, err := CaptureGoX86SDKNumericalReadSource(ctx, request)
	if err != nil {
		t.Fatal("actual joined SDK source precondition", err)
	}
	defer closeNumericalConsumerSource(t, source)
	for _, test := range []struct {
		name   string
		mutate func(*File, *Options)
	}{
		{"missing DATA", func(f *File, _ *Options) { f.Data = f.Data[1:] }},
		{"missing GLOBL", func(f *File, _ *Options) { f.Globl = f.Globl[1:] }},
		{"extra DATA", func(f *File, _ *Options) { f.Data = append(f.Data, f.Data[0]) }},
		{"extra GLOBL", func(f *File, _ *Options) { f.Globl = append(f.Globl, f.Globl[0]) }},
		{"DATA bytes", func(f *File, _ *Options) { f.Data[0].Value ^= 1 }},
		{"DATA offset", func(f *File, _ *Options) { f.Data[0].Off++ }},
		{"DATA width", func(f *File, _ *Options) { f.Data[0].Width-- }},
		{"DATA pointer", func(f *File, _ *Options) { f.Data[0].Addr = "internal∕cpu·X86(SB)" }},
		{"DATA namespace", func(f *File, _ *Options) { f.Data[0].Sym = strings.TrimSuffix(f.Data[0].Sym, "<>") }},
		{"GLOBL extent", func(f *File, _ *Options) { f.Globl[0].Size++ }},
		{"GLOBL mutability", func(f *File, _ *Options) { f.Globl[0].Flags = "0" }},
		{"missing TEXT", func(f *File, _ *Options) { f.Funcs = f.Funcs[1:] }},
		{"DATA function alias", func(_ *File, o *Options) {
			resolve := o.ResolveSym
			o.ResolveSym = func(symbol string) string {
				if strings.HasSuffix(symbol, "<>") {
					return "hash/crc32.ieeeCLMUL"
				}
				return resolve(symbol)
			}
		}},
		{"DATA numerical alias", func(_ *File, o *Options) {
			resolve := o.ResolveSym
			o.ResolveSym = func(symbol string) string {
				if strings.HasSuffix(symbol, "<>") {
					return "internal/cpu.X86"
				}
				return resolve(symbol)
			}
		}},
		{"DATA identity collapse", func(_ *File, o *Options) {
			resolve := o.ResolveSym
			o.ResolveSym = func(symbol string) string {
				if strings.HasSuffix(symbol, "<>") {
					return "hash/crc32.collapsed<>"
				}
				return resolve(symbol)
			}
		}},
		{"function DATA alias", func(_ *File, o *Options) {
			resolve := o.ResolveSym
			o.ResolveSym = func(symbol string) string {
				if symbol == "·ieeeCLMUL" {
					return "hash/crc32.r2r1<>"
				}
				return resolve(symbol)
			}
		}},
		{"numerical DATA alias", func(_ *File, o *Options) {
			resolve := o.ResolveSym
			o.ResolveSym = func(symbol string) string {
				if numericalNativeName(symbol, "hash/crc32") == "internal/cpu.X86" {
					return "hash/crc32.r2r1<>"
				}
				return resolve(symbol)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := *original
			file.Data = append([]DataStmt(nil), original.Data...)
			file.Globl = append([]GloblStmt(nil), original.Globl...)
			file.Funcs = append([]Func(nil), original.Funcs...)
			options := originalOptions
			test.mutate(&file, &options)
			bound, err := source.BindNumericalReads(ctx, pkg, &file, options)
			// Bind already performs the complete live Verify. A failed Verify
			// permanently revokes the source; distinguish that failure from
			// rejecting this caller-only mutation without duplicating the I/O.
			source.mu.Lock()
			live := source.ready && source.identity == source
			source.mu.Unlock()
			if !live || ctx.Err() != nil {
				t.Fatal("actual joined SDK source expired or was revoked", err, ctx.Err())
			}
			if bound.NumericalReads != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed complete source/initializer/namespace acquired a binding", err)
			}
		})
	}
	bound, err := source.BindNumericalReads(ctx, pkg, original, originalOptions)
	if err != nil || bound.NumericalReads == nil {
		t.Fatal("unchanged original must still bind after all caller-only rejections", err)
	}
}

func TestGoX86SDKNumericalReadLiteralOwnerLifetime(t *testing.T) {
	ctx, request, observed := numericalSDKLiteralFixture(t)
	pkg, file, options := numericalSDKLiteralPackage(t, observed, request.AssemblyFile)
	for _, change := range []string{"initializer close", "initializer report", "source owner replacement", "source owner removed"} {
		t.Run(change, func(t *testing.T) {
			owner, err := CaptureGoX86SDKReadonlyLiteralDataOwner(ctx, observed)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			local := request
			local.ReadonlyLiterals = owner
			source, err := CaptureGoX86SDKNumericalReadSource(ctx, local)
			if err != nil {
				t.Fatal("actual joined SDK source precondition", err)
			}
			defer closeNumericalConsumerSource(t, source)
			bound, err := source.BindNumericalReads(ctx, pkg, file, options)
			if err != nil {
				t.Fatal("actual complete SDK binding precondition", err)
			}
			switch change {
			case "initializer close":
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
			case "initializer report":
				owner.report[0] ^= 1
			case "source owner replacement":
				source.request.ReadonlyLiterals = request.ReadonlyLiterals
			case "source owner removed":
				source.request.ReadonlyLiterals = nil
			}
			if ir, err := Translate(file, bound); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("closed or foreign initializer published numerical IR", err)
			}
			source.request.ReadonlyLiterals = owner
			if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("restoring the initializer revived a revoked numerical source")
			}
			if err := observed.Verify(ctx); err != nil {
				t.Fatal("derived-token failure revoked the independent original SDK observation", err)
			}
		})
	}
}

func TestGoX86SDKNumericalReadLiteralOriginalContextAndReentry(t *testing.T) {
	// Each bounded fixture belongs to one lifecycle role. Reusing a single
	// five-minute producer across every race-instrumented recapture couples
	// independent tests to accumulated work, not the contract under test.
	t.Run("invalid verification context", func(t *testing.T) {
		ctx, request, _ := numericalSDKLiteralFixture(t)
		for _, invalid := range []string{"nil", "canceled"} {
			t.Run(invalid, func(t *testing.T) {
				source, err := CaptureGoX86SDKNumericalReadSource(ctx, request)
				if err != nil {
					t.Fatal("actual joined SDK source precondition", err)
				}
				defer closeNumericalConsumerSource(t, source)
				var verification context.Context
				if invalid == "canceled" {
					canceled, cancel := context.WithCancel(ctx)
					cancel()
					verification = canceled
				}
				if err := source.Verify(verification); err == nil {
					t.Fatal("invalid verification context retained the numerical source")
				}
				if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
					t.Fatal("fresh context revived the revoked numerical source")
				}
				if err := request.ReadonlyLiterals.Verify(ctx); err != nil {
					t.Fatal("invalid consumer context revoked the independent initializer", err)
				}
			})
		}
	})
	for _, route := range []string{"original", "verification"} {
		t.Run(route, func(t *testing.T) {
			ctx, request, observed := numericalSDKLiteralFixture(t)
			for _, method := range []string{"Err", "Deadline", "Done"} {
				t.Run(method, func(t *testing.T) {
					callback := &sdkASMDataReentrantContext{Context: ctx, method: method}
					captureContext, verifyContext := ctx, ctx
					if route == "original" {
						captureContext = callback
					} else {
						verifyContext = callback
					}
					source, err := CaptureGoX86SDKNumericalReadSource(captureContext, request)
					if err != nil {
						t.Fatal("actual joined SDK source precondition", err)
					}
					defer closeNumericalConsumerSource(t, source)
					called, underLock := false, false
					var nested error
					callback.callback = func() {
						called = true
						// Detect the forbidden callback-under-lock without allowing
						// a broken implementation to strand a deadlocked test worker.
						if !source.mu.TryLock() {
							underLock = true
							return
						}
						source.mu.Unlock()
						nested = source.Close()
					}
					callback.armed.Store(true)
					err = source.Verify(verifyContext)
					if !called || underLock || nested != nil || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("joined numerical lifecycle borrowed a callback lock or published after Close", called, underLock, nested, err)
					}
					if err := observed.Verify(ctx); err != nil {
						t.Fatal("closing the numerical consumer disposed its independent SDK source", err)
					}
				})
			}
		})
	}
	t.Run("original numerical cancellation", func(t *testing.T) {
		ctx, request, _ := numericalSDKLiteralFixture(t)
		original, cancel := context.WithCancel(ctx)
		defer cancel()
		source, err := CaptureGoX86SDKNumericalReadSource(original, request)
		if err != nil {
			t.Fatal("actual joined SDK source precondition", err)
		}
		defer closeNumericalConsumerSource(t, source)
		cancel()
		if err := source.Verify(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("fresh verification context revived the canceled original numerical capture", err)
		}
		if err := request.ReadonlyLiterals.Verify(ctx); err != nil {
			t.Fatal("numerical context cancellation revoked the independent initializer", err)
		}
	})
}

func TestGoX86SDKNumericalReadLiteralConcurrentClose(t *testing.T) {
	ctx, request, observed := numericalSDKLiteralFixture(t)
	for _, role := range []string{"numerical source", "literal owner"} {
		t.Run(role, func(t *testing.T) {
			owner, err := CaptureGoX86SDKReadonlyLiteralDataOwner(ctx, observed)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			local := request
			local.ReadonlyLiterals = owner
			source, err := CaptureGoX86SDKNumericalReadSource(ctx, local)
			if err != nil {
				t.Fatal("actual joined SDK source precondition", err)
			}
			defer closeNumericalConsumerSource(t, source)
			start := make(chan struct{})
			var workers sync.WaitGroup
			for worker := 0; worker < 4; worker++ {
				workers.Add(1)
				go func() {
					defer workers.Done()
					<-start
					if err := source.Verify(ctx); err != nil && !errors.Is(err, ErrProbeNeedsContext) {
						t.Error("concurrent joined verification returned an unclassified error", err)
					}
				}()
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				var err error
				if role == "numerical source" {
					err = source.Close()
				} else {
					err = owner.Close()
				}
				if err != nil {
					t.Error("close joined lifecycle role", err)
				}
			}()
			close(start)
			workers.Wait()
			if raw, err := source.Readback(ctx); raw != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("concurrent close retained or revived a joined source", err)
			}
			if err := observed.Verify(ctx); err != nil {
				t.Fatal("consumer close revoked the independent SDK source", err)
			}
		})
	}
}

// Exercise the initializer/shape checks directly, without allowing the outer
// full-file fingerprint to be the only reason a changed initializer fails.
func TestGoX86SDKNumericalReadLiteralInitializerAndReadBoundaries(t *testing.T) {
	ctx, request, observed := numericalSDKLiteralFixture(t)
	joined, err := captureNumericalSDKLiteralJoin(ctx, request, numericalSBSDKSource)
	if err != nil {
		t.Fatal(err)
	}
	_, original, _ := numericalSDKLiteralPackage(t, observed, request.AssemblyFile)
	if err := joined.verifyFile(original, request.PackagePath); err != nil {
		t.Fatal("original complete initializer precondition", err)
	}
	for _, test := range []struct {
		name   string
		change func(*File)
	}{
		{"missing initializer", func(f *File) { f.Data = f.Data[1:] }},
		{"duplicate initializer", func(f *File) { f.Data = append(f.Data, f.Data[0]) }},
		{"changed payload", func(f *File) { f.Data[0].Value ^= 1 }},
		{"payload takes precedence", func(f *File) { f.Data[0].Payload = []byte{0xff} }},
		{"initializer relocation", func(f *File) { f.Data[0].Addr = "internal∕cpu·X86(SB)" }},
		{"fragment reordering", func(f *File) { f.Data[0], f.Data[1] = f.Data[1], f.Data[0] }},
		{"fragment width", func(f *File) { f.Data[0].Width++ }},
		{"fragment offset", func(f *File) { f.Data[0].Off++ }},
		{"missing extent", func(f *File) { f.Globl = f.Globl[1:] }},
		{"duplicate extent", func(f *File) { f.Globl = append(f.Globl, f.Globl[0]) }},
		{"unresolved extent", func(f *File) { f.Globl[0].SizeRaw = "unknown" }},
		{"extent shrink", func(f *File) { f.Globl[0].Size-- }},
		{"readonly extra flag", func(f *File) { f.Globl[0].Flags = "10" }},
		{"global private identity", func(f *File) { f.Globl[0].Sym = strings.TrimSuffix(f.Globl[0].Sym, "<>") }},
		{"fragment private identity", func(f *File) { f.Data[0].Sym = strings.TrimSuffix(f.Data[0].Sym, "<>") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			file := *original
			file.Data = append([]DataStmt(nil), original.Data...)
			file.Globl = append([]GloblStmt(nil), original.Globl...)
			test.change(&file)
			if err := joined.verifyFile(&file, request.PackagePath); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unbound initializer image was accepted", err)
			}
		})
	}
	source := &GoX86NumericalReadSource{request: request, literals: joined}
	for _, test := range []struct {
		instruction string
		operand     int
		admitted    bool
	}{
		{"MOVOU r2r1<>(SB), X0", 0, true},
		{"MOVOU r2r1<>+48(SB), X0", 0, true},
		{"VMOVDQU64 r2r1<>(SB), Z0", 0, true},
		{"PCLMULQDQ $1, r2r1<>(SB), X0", 1, true},
		{"PSRLQ r2r1<>(SB), X0", 0, true},
		{"MOVOU r2r1<>+49(SB), X0", 0, false},
		{"VMOVDQU64 r2r1<>+1(SB), Z0", 0, false},
		{"MOVOU r2r1<>-1(SB), X0", 0, false},
		{"VMOVDQU64 r4r3<>(SB), Z0", 0, false},
		{"MOVOU X0, r2r1<>(SB)", 1, false},
		{"LEAQ r2r1<>(SB), AX", 0, true},
		{"CALL r2r1<>(SB)", 0, false},
	} {
		t.Run(test.instruction, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT ·fixture(SB),4,$0-0\n"+test.instruction+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			local, err := source.sdkLiteralRead(file.Funcs[0].Instrs[1], test.operand, "amd64")
			if !local || test.admitted && err != nil || !test.admitted && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("private initializer read shape/direction/whole extent differs", local, err)
			}
		})
	}
}

func TestGoX86SDKNumericalReadLiteralListingObjectBoundaries(t *testing.T) {
	ctx, request, _ := numericalSDKLiteralFixture(t)
	joined, err := captureNumericalSDKLiteralJoin(ctx, request, numericalSBSDKSource)
	if err != nil {
		t.Fatal(err)
	}
	inputs := joined.Observation.ObjectInputs
	selected := inputs.Sources[joined.SourceOrdinal]
	for _, route := range []string{"original", "expanded"} {
		for _, mutation := range []string{"valid", "truncated", "private namespace", "text code", "DATA bytes"} {
			t.Run(route+"/"+mutation, func(t *testing.T) {
				original := append([]byte(nil), selected.OriginalObject...)
				expanded := append([]byte(nil), selected.ExpandedObject...)
				object := &original
				if route == "expanded" {
					object = &expanded
				}
				switch mutation {
				case "truncated":
					*object = (*object)[:len(*object)-1]
				case "private namespace":
					index := bytes.Index(*object, []byte("r2r1"))
					if index < 0 {
						t.Fatal("actual object lacks its original private namespace")
					}
					(*object)[index+3] = '2'
				case "text code":
					code := joined.Observation.Objects.Sources[joined.SourceOrdinal].Original.Texts[0].Code
					index := bytes.Index(*object, code)
					if index < 0 || len(code) == 0 {
						t.Fatal("actual object lacks its complete original text")
					}
					(*object)[index] ^= 1
				case "DATA bytes":
					image := joined.Initializers.Initializers[0].Initial
					index := bytes.Index(*object, image)
					if index < 0 || len(image) == 0 {
						t.Fatal("actual object lacks its complete literal payload")
					}
					(*object)[index] ^= 1
				}
				first, second, err := gostaticstorage.ObserveX86SDKASMDataListingObjects(inputs, joined.SourceOrdinal, original, expanded)
				if mutation == "valid" {
					if err != nil || len(first) != 3 || len(second) != 3 {
						t.Fatal("actual complete listing object join", err)
					}
				} else if first != nil || second != nil || err == nil {
					t.Fatal("changed whole listing object was accepted", err)
				}
			})
		}
	}
}
