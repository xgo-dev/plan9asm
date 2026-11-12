//go:build go1.27

package plan9asm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/xgo-dev/llvm"
)

// The callback route is observed only by this regression. It grants no source,
// caller, entry or read authority; all inputs come from the complete SDK owner.
type numericalRevokeCallbackContext struct {
	context.Context
	mu       sync.Mutex
	callback func()
}

func (ctx *numericalRevokeCallbackContext) Err() error {
	ctx.mu.Lock()
	callback := ctx.callback
	ctx.mu.Unlock()
	if callback != nil {
		callback()
	}
	return ctx.Context.Err()
}

func TestGoX86NumericalReadRevokeDuringFinalSDKCallback(t *testing.T) {
	for _, api := range []string{"Verify", "Readback", "CheckReadback", "text", "module", "go-module"} {
		t.Run(api, func(t *testing.T) { numericalRevokeDuringFinalSDKCallback(t, api) })
	}
}

func numericalRevokeDuringFinalSDKCallback(t *testing.T, api string) {
	base, request := sdkASMDataRequest(t, "amd64", "hash/crc32")
	ctx := &numericalRevokeCallbackContext{Context: base}
	owner, err := CaptureGoNumericalStorageOwner(ctx, GoNumericalStorageCaptureRequest{
		GoBinary:    request.GoBinary,
		Directory:   filepath.Join(filepath.Dir(filepath.Dir(request.GoBinary)), "src", "internal", "cpu"),
		PackagePath: "internal/cpu", Target: request.Target, Environment: request.Environment, SDKCPU: true,
		Variables: []GoNumericalStorageReference{{PackagePath: "internal/cpu", Name: "X86"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	data, err := CaptureGoX86SDKASMDataSource(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := data.Close(); err != nil {
			t.Error(err)
		}
	})
	literal, err := CaptureGoX86SDKReadonlyLiteralDataOwner(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := literal.Close(); err != nil {
			t.Error(err)
		}
	})
	source, err := CaptureGoX86SDKNumericalReadSource(ctx, GoX86NumericalReadCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, PackagePath: request.PackagePath,
		Target: request.Target, Environment: request.Environment, AssemblyFile: "crc32_amd64.s", ReadonlyLiterals: literal,
		Owners: []*GoNumericalStorageOwner{owner},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeNumericalConsumerSource(t, source) })
	pkg, file, options := numericalSDKLiteralPackage(t, data, "crc32_amd64.s")
	bound, err := source.BindNumericalReads(ctx, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	report, err := source.Readback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(request.Directory, "crc32_amd64.s"))
	if err != nil {
		t.Fatal(err)
	}
	invoke := func() (bool, error) {
		switch api {
		case "Verify":
			return false, source.Verify(ctx)
		case "Readback":
			raw, err := source.Readback(ctx)
			return len(raw) != 0, err
		case "CheckReadback":
			return false, source.CheckReadback(ctx, report)
		case "text":
			ir, err := Translate(file, bound)
			return ir != "", err
		case "module":
			context := llvm.NewContext()
			defer context.Dispose()
			module, err := TranslateModuleInContext(context, file, bound)
			published := !module.IsNil()
			if published {
				module.Dispose()
			}
			return published, err
		case "go-module":
			result, err := TranslateGoModule(pkg, original, GoModuleOptions{GOARCH: "amd64", GOOS: "linux", TargetTriple: bound.TargetTriple,
				FileName: "crc32_amd64.s", NumericalReads: bound.NumericalReads, ResolveSym: bound.ResolveSym})
			published := result != nil && !result.Module.IsNil()
			if published {
				result.Module.Dispose()
			}
			return published, err
		}
		return false, fmt.Errorf("unknown API %s", api)
	}
	var mu sync.Mutex
	recording, reached, finalCallback := true, false, ""
	var goSites numericalFinalSDKCallbackSites
	ctx.mu.Lock()
	ctx.callback = func() {
		key := numericalFinalSDKCallbackKey(api)
		if key == "" {
			return
		}
		mu.Lock()
		if api == "go-module" {
			// Observe the complete actual outer final guard in one API call:
			// two binding verifies, each with entry and final source verifies.
			// Repeated Err samples within a source defer are the same site.
			if !goSites.observe(key) {
				mu.Unlock()
				return
			}
			reached, finalCallback = true, key
			mu.Unlock()
			if err := source.Revoke(); err != nil {
				t.Error(err)
			}
			return
		}
		if recording {
			finalCallback = key
			mu.Unlock()
			return
		}
		if reached || key != finalCallback {
			mu.Unlock()
			return
		}
		reached = true
		mu.Unlock()
		if err := source.Revoke(); err != nil {
			t.Error(err)
		}
	}
	ctx.mu.Unlock()
	if api != "go-module" {
		baselineArtifact, err := invoke()
		wantsArtifact := api == "Readback" || api == "text" || api == "module"
		if err != nil || wantsArtifact && !baselineArtifact {
			t.Fatal("complete original baseline API failed or lost its artifact", baselineArtifact, err)
		}
		mu.Lock()
		if finalCallback == "" {
			mu.Unlock()
			t.Fatal("actual final SDK callback route was not observed")
		}
		recording = false
		mu.Unlock()
	}
	published, err := invoke()
	mu.Lock()
	observed := reached
	goCount := len(goSites.seen)
	mu.Unlock()
	if !observed {
		t.Fatal("actual final callback was not reached")
	}
	if api == "go-module" && goCount != 4 {
		t.Fatal("complete actual outer Go-module final guard lost a source-verification site", goCount)
	}
	if !errors.Is(err, ErrProbeNeedsContext) || published {
		t.Fatal("revocation during the last genuine SDK callback published", api, published, err)
	}
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("final callback revocation was not permanent", err)
	}
}

// Test-only route accounting: a repeated context sample is not a new source
// verification. These keys never grant source or binding authority.
type numericalFinalSDKCallbackSites struct {
	seen map[string]bool
}

func (sites *numericalFinalSDKCallbackSites) observe(key string) bool {
	if key == "" || len(sites.seen) == 4 || sites.seen[key] {
		return false
	}
	if sites.seen == nil {
		sites.seen = make(map[string]bool)
	}
	sites.seen[key] = true
	return len(sites.seen) == 4
}

func TestGoX86NumericalReadFinalSDKCallbackSiteControl(t *testing.T) {
	var sites numericalFinalSDKCallbackSites
	if sites.observe("") || len(sites.seen) != 0 {
		t.Fatal("an unrelated callback acquired a final-guard site")
	}
	for _, key := range []string{"binding-one/source-entry", "binding-one/source-final", "binding-two/source-entry"} {
		if sites.observe(key) || sites.observe(key) {
			t.Fatal("an early or repeated context sample triggered late revocation", key)
		}
	}
	if len(sites.seen) != 3 || !sites.observe("binding-two/source-final") {
		t.Fatal("the fourth distinct final-guard site was not reached", len(sites.seen))
	}
	for _, key := range []string{"binding-two/source-final", "unexpected-extra-site", ""} {
		if sites.observe(key) || len(sites.seen) != 4 {
			t.Fatal("a repeated or excess sample changed the one-shot bounded route", key)
		}
	}
}

func numericalFinalSDKCallbackKey(api string) string {
	var pcs [64]uintptr
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs[:])])
	var key strings.Builder
	joined, finish, goFinish := false, false, false
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, ".verifySDKLiteralNumericalSource.func1") {
			joined = true
		}
		if joined {
			fmt.Fprintf(&key, "%s:%x/", frame.Function, frame.PC)
		}
		if api == "go-module" && strings.Contains(frame.Function, ".translateGoModuleInContext.func") {
			goFinish = true
			break
		}
		if api != "go-module" && strings.HasSuffix(frame.Function, ".finishNumericalReads") {
			finish = true
			break
		}
		if joined && (api == "Verify" || api == "Readback" || api == "CheckReadback") && strings.HasSuffix(frame.Function, ").Verify") {
			break
		}
		if !more {
			break
		}
	}
	if !joined || (api == "text" || api == "module") && !finish || api == "go-module" && !goFinish {
		return ""
	}
	return key.String()
}
