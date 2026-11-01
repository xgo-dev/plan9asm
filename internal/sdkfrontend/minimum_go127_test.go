//go:build go1.27

package sdkfrontend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestSharedSDKLiteralMinimumOriginalCompleteMaps(t *testing.T) {
	ctx, request, pkg, file, options := sdkMinimumOriginalPackage(t, "internal/runtime/maps", "memhash_amd64.s")
	file, source, err := Capture(ctx, request, file)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	if !plan9asm.GoX86SDKLiteralAlignmentRequested(file, options) {
		t.Fatal("complete actual source lost its typed linked-minimum cost")
	}
	if _, err := source.Numerical.BindNumericalReads(ctx, pkg, file, options); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatal("default numerical binder manufactured a linked minimum", err)
	}
	bound, err := source.BindNumericalReads(ctx, pkg, file, options)
	if err != nil {
		t.Fatal("shared complete source lacks its genuine minimum handoff", err)
	}
	ir, err := plan9asm.Translate(file, bound)
	if err != nil || strings.Count(ir, "define ") != len(file.Funcs) || len(file.Funcs) != 2 || len(file.Globl) != 2 ||
		!strings.Contains(ir, "external global [128 x i8]") {
		t.Fatal("complete source/function/DATA/mutable-storage publication differs", err)
	}
	minimum := source.minimum
	first, err := minimum.Readback(ctx)
	if err != nil || sdkMinimumLinkCommands(t, first) != 1 {
		t.Fatal("genuine minimum needs exactly one original Go link receipt", err)
	}
	if _, err := source.BindNumericalReads(ctx, pkg, file, options); err != nil || source.minimum != minimum {
		t.Fatal("same live source unnecessarily recaptured a minimum", err)
	}
	second, err := minimum.Readback(ctx)
	if err != nil || !bytes.Equal(first, second) || sdkMinimumLinkCommands(t, second) != 1 {
		t.Fatal("cached minimum added commands or changed its exact report", err)
	}
	// The successful genuine producer stores its cache fields in sequence.
	// Model that publication boundary using the real cached minimum, not a
	// fabricated producer/floor. An active entrant must not inspect the cache.
	source.mu.Lock()
	source.active, source.originalMinimum = true, nil
	source.mu.Unlock()
	if err := source.Verify(ctx); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatal("concurrent active operation was accepted", err)
	}
	source.mu.Lock()
	changed := source.closePending
	source.active, source.originalMinimum = false, minimum
	source.mu.Unlock()
	if changed {
		t.Fatal("active entrant inspected a partially published genuine cache and revoked its owner")
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("active entrant permanently changed the genuine source", err)
	}
	foreignContext, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if _, err := source.BindNumericalReads(foreignContext, pkg, file, options); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatal("a new context acquired the original factory", err)
	}
	foreign := &Source{Numerical: source.Numerical, identity: source, cleanup: source.cleanup}
	if err := foreign.Close(); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatal("foreign handle closed borrowed resources", err)
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("foreign close revoked the original factory", err)
	}
	if err := minimum.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := source.BindNumericalReads(ctx, pkg, file, options); !errors.Is(err, plan9asm.ErrProbeNeedsContext) || source.minimum != minimum {
		t.Fatal("closed cached minimum was rebuilt or retained authority", err)
	}
	if _, err := plan9asm.Translate(file, bound); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatal("closed minimum retained publication authority", err)
	}
}

func TestSharedSDKLiteralMinimumCRC32NoAdditionalLink(t *testing.T) {
	ctx, request, pkg, file, options := sdkMinimumOriginalPackage(t, "hash/crc32", "crc32_amd64.s")
	file, source, err := Capture(ctx, request, file)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	before, err := source.Numerical.Readback(ctx)
	if err != nil || sdkMinimumLinkCommands(t, before) != 0 {
		t.Fatal("ordinary producer added a Go link", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		_, err := source.BindNumericalReads(ctx, pkg, file, options)
		if err != nil || source.minimumAttempted || source.minimum != nil {
			t.Fatal("ordinary CRC32 unnecessarily paid for a minimum", err)
		}
	}
	after, err := source.Numerical.Readback(ctx)
	if err != nil || !bytes.Equal(before, after) || sdkMinimumLinkCommands(t, after) != 0 {
		t.Fatal("ordinary repeated binding added commands or changed its complete receipt", err)
	}
}

// Repeated-binding cost and whole-publication lifetime are independent axes.
// Each retains a genuine capture and the original five-minute context budget.
func TestSharedSDKLiteralMinimumCRC32WholeSourceAndLifecycle(t *testing.T) {
	ctx, request, pkg, file, options := sdkMinimumOriginalPackage(t, "hash/crc32", "crc32_amd64.s")
	file, source, err := Capture(ctx, request, file)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	bound, err := source.BindNumericalReads(ctx, pkg, file, options)
	if err != nil || source.minimumAttempted || source.minimum != nil {
		t.Fatal("ordinary CRC32 whole source borrowed a linked minimum", err)
	}
	if _, err := plan9asm.Translate(file, bound); err != nil {
		t.Fatal(err)
	}
	resolve := options.ResolveSym
	closed := false
	var closes int32
	source.cleanup = append(source.cleanup, func() error { atomic.AddInt32(&closes, 1); return nil })
	options.ResolveSym = func(symbol string) string {
		if !closed {
			closed = true
			if _, err := source.BindNumericalReads(ctx, pkg, file, options); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Error("reentrant binder acquired the active source", err)
			}
			if err := source.Verify(ctx); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Error("reentrant verifier acquired the active source", err)
			}
			var workers sync.WaitGroup
			for i := 0; i < 2; i++ {
				workers.Add(1)
				go func() {
					defer workers.Done()
					if err := source.Close(); err != nil {
						t.Error(err)
					}
				}()
			}
			workers.Wait() // Close must return while this callback still owns the operation.
			if atomic.LoadInt32(&closes) != 0 {
				t.Error("concurrent Close cleaned resources during an active callback")
			}
		}
		return resolve(symbol)
	}
	if _, err := source.BindNumericalReads(ctx, pkg, file, options); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatal("callback Close published bound options", err)
	}
	if err := source.Verify(ctx); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatal("callback Close was not permanent", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal("owned callbacks were closed twice", err)
	}
	if atomic.LoadInt32(&closes) != 1 {
		t.Fatal("pending Close did not release its ownership exactly once", closes)
	}
}

func TestSharedSDKLiteralMinimumLateNumericalReplacement(t *testing.T) {
	for _, action := range []string{"before-begin", "callback-replacement", "callback-close"} {
		t.Run(action, func(t *testing.T) { sharedSDKLiteralMinimumLateMutation(t, action) })
	}
}

func sharedSDKLiteralMinimumLateMutation(t *testing.T, action string) {
	ctx, request, pkg, file, options := sdkMinimumOriginalPackage(t, "internal/runtime/maps", "memhash_amd64.s")
	file, source, err := Capture(ctx, request, file)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := source.BindNumericalReads(ctx, pkg, file, options); err != nil {
		t.Fatal(err)
	}
	if action == "before-begin" {
		original := source.Numerical
		source.Numerical = nil
		if _, err := source.BindNumericalReads(ctx, pkg, file, options); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
			t.Fatal("pre-operation numerical replacement accepted", err)
		}
		source.Numerical = original
		if err := source.Verify(ctx); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
			t.Fatal("restored pointer revived permanently changed source ownership", err)
		}
		return
	}
	resolve, calls := options.ResolveSym, 0
	acted := false
	options.ResolveSym = func(symbol string) string {
		calls++
		if calls > len(file.Funcs) && !acted {
			acted = true
			if action == "callback-close" {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			} else {
				source.Numerical = nil
			}
		}
		return resolve(symbol)
	}
	bound, err := source.BindNumericalReads(ctx, pkg, file, options)
	if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatal("late callback replacement escaped the shared original-source join", err)
	}
	if bound.NumericalReads != nil || len(bound.Sigs) != 0 {
		t.Fatal("deferred guard failure retained nonempty bound options")
	}
}

func sdkMinimumLinkCommands(t *testing.T, raw []byte) int {
	t.Helper()
	var report struct {
		Commands []struct{ Arguments []string }
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, command := range report.Commands {
		if len(command.Arguments) > 2 && command.Arguments[0] == "tool" && command.Arguments[1] == "link" && command.Arguments[2] != "-V" {
			count++
		}
	}
	return count
}

// This independently observes cmd/go's exact selected source and exports;
// gc-imported dependencies never replace the primary's complete original syntax.
func sdkMinimumOriginalPackage(t *testing.T, path, assembly string) (context.Context, CaptureRequest, plan9asm.GoPackage, *plan9asm.File, plan9asm.Options) {
	return sdkMinimumOriginalPackageContext(t, path, assembly, nil)
}

func sdkMinimumOriginalPackageContext(t *testing.T, path, assembly string, decorate func(context.Context) context.Context) (context.Context, CaptureRequest, plan9asm.GoPackage, *plan9asm.File, plan9asm.Options) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	var originalContext context.Context = ctx
	if decorate != nil {
		originalContext = decorate(ctx)
	}
	for key, value := range map[string]string{"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "", "GOEXPERIMENT": "", "GOPACKAGESDRIVER": "off", "GOPROXY": "off", "GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "GO386": "sse2"} {
		t.Setenv(key, value)
	}
	t.Setenv("CGO_ENABLED", "")
	if err := os.Unsetenv("CGO_ENABLED"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR"} {
		directory, err := sourcepath.Resolve(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv(key, directory)
	}
	root, err := sourcepath.Resolve(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = sourcepath.Resolve(binary)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "src", filepath.FromSlash(path))
	environment := os.Environ()
	cgo, stderr, err := gotoolprofile.RunBounded(ctx, directory, environment, binary, "env", "CGO_ENABLED")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual default CGO profile: %v\n%s", err, stderr)
	}
	values, err := EnvironmentValues(environment)
	if err != nil {
		t.Fatal(err)
	}
	values["CGO_ENABLED"] = strings.TrimSpace(string(cgo))
	environment = EncodeEnvironment(values)
	output, stderr, err := gotoolprofile.RunBounded(ctx, directory, environment, binary, "list", "-deps", "-export", "-compiled", "-mod=readonly", "-json", path)
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual original SDK selection: %v\n%s", err, stderr)
	}
	selected := make(map[string]gostaticstorage.Package)
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		var item gostaticstorage.Package
		if err := decoder.Decode(&item); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if !item.Standard || !item.Goroot || item.Module != nil || len(item.Error) != 0 || len(item.DepsErrors) != 0 {
			t.Fatal("actual selection is not an ordinary SDK graph", item.ImportPath)
		}
		selected[item.ImportPath] = item
	}
	primary, found := selected[path]
	if !found || len(primary.GoFiles) != len(primary.CompiledGoFiles) {
		t.Fatal("complete original primary source is absent")
	}
	fset := token.NewFileSet()
	var syntax []*ast.File
	for _, filename := range primary.GoFiles {
		file, err := parser.ParseFile(fset, filepath.Join(directory, filename), nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		syntax = append(syntax, file)
	}
	imports := importer.ForCompiler(fset, "gc", func(importPath string) (io.ReadCloser, error) {
		if mapped, ok := primary.ImportMap[importPath]; ok {
			importPath = mapped
		}
		dependency, found := selected[importPath]
		if !found || dependency.Export == "" {
			return nil, fmt.Errorf("missing actual SDK export: %s", importPath)
		}
		return os.Open(dependency.Export)
	})
	sizes := types.SizesFor("gc", "amd64")
	typed, err := (&types.Config{Sizes: sizes, Importer: imports, GoVersion: "go1.27"}).Check(path, fset, syntax, nil)
	if err != nil {
		t.Fatal("complete independently typed primary", err)
	}
	pkg := plan9asm.GoPackage{Path: path, Types: typed, Syntax: syntax, Imports: make(map[string]*types.Package)}
	view := &Package{Path: path, Types: typed, Sizes: sizes, Imports: make(map[string]*Package)}
	for _, dependency := range typed.Imports() {
		pkg.Imports[dependency.Path()] = dependency
		view.Imports[dependency.Path()] = &Package{Path: dependency.Path(), Types: dependency}
	}
	filename := filepath.Join(directory, assembly)
	raw, err := plan9asm.ReadGoAssemblySource(filename, directory)
	if err != nil {
		t.Fatal(err)
	}
	file, err := plan9asm.ParseWithDefines(plan9asm.ArchAMD64, string(raw), plan9asm.GoAssemblerDefines("linux", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	options := plan9asm.Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: func(symbol string) string { return Resolve(path, symbol) }, Sigs: make(map[string]plan9asm.FuncSig)}
	for _, fn := range file.Funcs {
		if strings.HasSuffix(fn.Sym, "<>") {
			continue // A private continuation has no Go entry declaration.
		}
		name := strings.TrimPrefix(Resolve("", fn.Sym), ".")
		declaration, valid := typed.Scope().Lookup(name).(*types.Func)
		if !valid {
			t.Fatal("original TEXT has no actual declaration", name)
		}
		sig, err := plan9asm.DeriveGoFuncABI0Signature(Resolve(path, fn.Sym), declaration, "amd64", sizes)
		if err != nil {
			t.Fatal(err)
		}
		options.Sigs[sig.Name] = sig
	}
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			if ins.Op != plan9asm.OpJMP || len(ins.Args) != 1 || ins.Args[0].Kind != plan9asm.OpSym {
				continue
			}
			symbol := strings.TrimSuffix(ins.Args[0].Sym, "(SB)")
			if strings.HasSuffix(symbol, "<>") {
				continue
			}
			name := strings.TrimPrefix(Resolve("", symbol), ".")
			declaration, valid := typed.Scope().Lookup(name).(*types.Func)
			if !valid {
				t.Fatal("ordinary tail lacks its actual Go declaration", name)
			}
			sig, err := plan9asm.DeriveGoFuncABI0Signature(Resolve(path, symbol), declaration, "amd64", sizes)
			if err != nil {
				t.Fatal(err)
			}
			options.Sigs[sig.Name] = sig
		}
	}
	return originalContext, CaptureRequest{GoBinary: binary, Root: root, Directory: directory, PackagePath: path, AssemblyFile: filename, Target: "linux/amd64", Environment: environment, Package: view}, pkg, file, options
}

type sdkMinimumCallbackContext struct {
	context.Context
	mu         sync.Mutex
	callback   func(string)
	inside     int32
	errSamples int32
	failure    error
}

func (ctx *sdkMinimumCallbackContext) invoke(method string) {
	ctx.mu.Lock()
	callback := ctx.callback
	ctx.mu.Unlock()
	if callback != nil && atomic.CompareAndSwapInt32(&ctx.inside, 0, 1) {
		defer atomic.StoreInt32(&ctx.inside, 0)
		callback(method)
	}
}
func (ctx *sdkMinimumCallbackContext) Err() error {
	atomic.AddInt32(&ctx.errSamples, 1)
	ctx.invoke("Err")
	ctx.mu.Lock()
	failure := ctx.failure
	ctx.mu.Unlock()
	if failure != nil {
		return failure
	}
	return ctx.Context.Err()
}
func (ctx *sdkMinimumCallbackContext) Deadline() (time.Time, bool) {
	ctx.invoke("Deadline")
	return ctx.Context.Deadline()
}
func (ctx *sdkMinimumCallbackContext) Done() <-chan struct{} {
	ctx.invoke("Done")
	return ctx.Context.Done()
}

func TestSharedSDKLiteralMinimumContextReentryBeforeCallbacks(t *testing.T) {
	var caller *sdkMinimumCallbackContext
	ctx, request, _, file, _ := sdkMinimumOriginalPackageContext(t, "hash/crc32", "crc32_amd64.s", func(base context.Context) context.Context {
		caller = &sdkMinimumCallbackContext{Context: base}
		return caller
	})
	_, source, err := Capture(ctx, request, file)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, method := range []string{"Err", "Deadline", "Done"} {
		var reached int32
		caller.mu.Lock()
		caller.callback = func(observed string) {
			if observed != method || !atomic.CompareAndSwapInt32(&reached, 0, 1) {
				return
			}
			before := atomic.LoadInt32(&caller.errSamples)
			err := source.begin(ctx)
			if err == nil {
				if endErr := source.end(); endErr != nil {
					t.Error(endErr)
				}
			}
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Error("same-context nested operation entered before callback guard", method, err)
			}
			if atomic.LoadInt32(&caller.errSamples) != before {
				t.Error("nested active operation resampled caller Err", method)
			}
		}
		caller.mu.Unlock()
		if err := source.Verify(ctx); err != nil {
			t.Fatal("non-mutating context reentry revoked original owner", method, err)
		}
		caller.mu.Lock()
		caller.callback = nil
		caller.mu.Unlock()
		if atomic.LoadInt32(&reached) != 1 {
			t.Fatal("real context callback was not reached", method)
		}
	}
}

func TestSharedSDKLiteralMinimumOriginalContextFailurePermanent(t *testing.T) {
	var caller *sdkMinimumCallbackContext
	ctx, request, _, file, _ := sdkMinimumOriginalPackageContext(t, "hash/crc32", "crc32_amd64.s", func(base context.Context) context.Context {
		caller = &sdkMinimumCallbackContext{Context: base}
		return caller
	})
	_, source, err := Capture(ctx, request, file)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	caller.mu.Lock()
	caller.failure = context.Canceled
	caller.mu.Unlock()
	if err := source.Verify(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("original caller cancellation cause was lost", err)
	}
	caller.mu.Lock()
	caller.failure = nil
	caller.mu.Unlock()
	if err := source.Verify(ctx); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatal("restored original Err callback revived a failed source lifetime", err)
	}
}

func TestSharedSDKLiteralMinimumConcurrentActualCapture(t *testing.T) {
	var caller *sdkMinimumCallbackContext
	ctx, request, pkg, file, options := sdkMinimumOriginalPackageContext(t, "internal/runtime/maps", "memhash_amd64.s", func(base context.Context) context.Context {
		caller = &sdkMinimumCallbackContext{Context: base}
		return caller
	})
	file, source, err := Capture(ctx, request, file)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	var reached int32
	caller.mu.Lock()
	caller.callback = func(method string) {
		// Test-only phase observation, never an SDK ownership/caller proof.
		var pcs [32]uintptr
		frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs[:])])
		capture := false
		for {
			frame, more := frames.Next()
			if strings.HasSuffix(frame.Function, ".CaptureGoX86SDKLiteralAlignment") {
				capture = true
			}
			if !more {
				break
			}
		}
		if !capture || !atomic.CompareAndSwapInt32(&reached, 0, 1) {
			return
		}
		errors := make(chan error, 2)
		go func() { _, err := source.BindNumericalReads(ctx, pkg, file, options); errors <- err }()
		go func() { errors <- source.Verify(ctx) }()
		for i := 0; i < 2; i++ {
			if err := <-errors; !errorsIsSDKContext(err) {
				t.Error("concurrent caller entered actual minimum capture", method, err)
			}
		}
	}
	caller.mu.Unlock()
	if _, err := source.BindNumericalReads(ctx, pkg, file, options); err != nil {
		t.Fatal("genuine minimum capture did not retain its exclusive owner", err)
	}
	caller.mu.Lock()
	caller.callback = nil
	caller.mu.Unlock()
	if atomic.LoadInt32(&reached) != 1 {
		t.Fatal("actual original producer capture callback was not observed")
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("rejected concurrent entry revoked captured owner", err)
	}
}

func errorsIsSDKContext(err error) bool { return errors.Is(err, plan9asm.ErrProbeNeedsContext) }

func TestSharedSDKLiteralMinimumCloseRevokesPreviouslyBoundOptions(t *testing.T) {
	for _, path := range []string{"hash/crc32", "internal/runtime/maps"} {
		t.Run(path, func(t *testing.T) { sharedSDKMinimumClosePreviousOptions(t, path) })
	}
}

func sharedSDKMinimumClosePreviousOptions(t *testing.T, path string) {
	assembly := "crc32_amd64.s"
	if path == "internal/runtime/maps" {
		assembly = "memhash_amd64.s"
	}
	ctx, request, pkg, file, options := sdkMinimumOriginalPackage(t, path, assembly)
	file, source, err := Capture(ctx, request, file)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	previous, err := source.BindNumericalReads(ctx, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	resolve, closed := options.ResolveSym, false
	original, err := os.ReadFile(request.AssemblyFile)
	if err != nil {
		t.Fatal(err)
	}
	options.ResolveSym = func(symbol string) string {
		if !closed {
			closed = true
			if err := source.Close(); err != nil {
				t.Error(err)
			}
			if _, err := plan9asm.Translate(file, previous); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Error("Close retained old text publication during active callback", err)
			}
			func() {
				context := llvm.NewContext()
				defer context.Dispose()
				module, err := plan9asm.TranslateModuleInContext(context, file, previous)
				if !module.IsNil() {
					module.Dispose()
				}
				if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
					t.Error("Close retained old module publication during active callback", err)
				}
			}()
			result, err := plan9asm.TranslateGoModule(pkg, original, plan9asm.GoModuleOptions{GOARCH: "amd64", GOOS: "linux", TargetTriple: previous.TargetTriple, FileName: filepath.Base(request.AssemblyFile), NumericalReads: previous.NumericalReads, ResolveSym: previous.ResolveSym})
			if result != nil && !result.Module.IsNil() {
				result.Module.Dispose()
			}
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Error("Close retained old Go-module publication during active callback", err)
			}
		}
		return resolve(symbol)
	}
	if _, err := source.BindNumericalReads(ctx, pkg, file, options); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatal("active Close accepted outer binding", err)
	}
}
