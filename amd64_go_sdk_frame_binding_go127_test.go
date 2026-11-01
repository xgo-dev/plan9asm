//go:build go1.27

package plan9asm

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoAMD64SDKFrameReadonlyDataComposition(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "crypto/internal/fips140/sha512")
	observed, err := CaptureGoAMD64SDKFrameObservation(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer observed.Close()
	pkg := sdkAMD64FrameActualPackage(t, observed.source)
	source, err := CaptureGoAMD64SDKFrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, AssemblyFile: "sha512block_amd64.s",
		Target: request.Target, Environment: request.Environment,
	})
	if err != nil {
		t.Fatal("complete original frame and readonly DATA observation", err)
	}
	defer source.Close()
	expanded := source.sdkFrame.owner.source.observation.CPP[0].Output
	file, err := Parse(ArchAMD64, expanded)
	if err != nil || len(file.Globl) == 0 || len(file.Funcs) != len(source.functions) {
		t.Fatal("complete original source inventory", err)
	}
	resolve := func(symbol string) string { return pkg.Path + "." + strings.TrimPrefix(symbol, "·") }
	source.mu.Lock()
	data, names, err := source.fixedLocalData(file, expanded, resolve)
	source.mu.Unlock()
	if err != nil || len(data) != len(file.Globl) || len(names) != len(file.Globl) {
		t.Fatal("readonly DATA lost its same-source extent/symbol projection", err)
	}
	for _, changed := range []struct{ name, expanded string }{
		{"missing_amd64.s", expanded},
		{source.request.AssemblyFile, expanded + "\n"},
	} {
		if _, err := source.fixedLocalDataObservation(changed.name, changed.expanded); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("unmatched source borrowed the complete SDK DATA observation", err)
		}
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("complete live frame/DATA source", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("closed frame/DATA source revived", err)
	}
	t.Logf("%d complete source functions and %d readonly definitions; not a full translation result", len(file.Funcs), len(data))
}

func TestGoAMD64SDKFrameOriginalSourceCapture(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "crypto/md5")
	observed, err := CaptureGoAMD64SDKFrameObservation(ctx, request)
	if err != nil {
		t.Fatal("complete original SDK source/native frame precondition", err)
	}
	defer observed.Close()
	pkg := sdkAMD64FrameActualPackage(t, observed.source)
	const assembly = "md5block_amd64.s"
	source, err := CaptureGoAMD64SDKFrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, AssemblyFile: assembly,
		Target: request.Target, Environment: request.Environment,
	})
	if err != nil {
		t.Fatal("independent SDK-primary native frame handoff is absent", err)
	}
	defer source.Close()
	fn, found := source.functions[request.PackagePath+".block"]
	if !found || len(source.functions) != 1 || fn.locals != 16 || fn.args != 32 {
		t.Fatal("complete original SDK frame/declaration/native layout", fn)
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("live SDK-primary native frame", err)
	}
	// Even a fresh outer identity cannot borrow the SDK origin's live owner.
	copy := &GoAMD64FrameSource{sdkFrame: source.sdkFrame}
	copy.identity = copy
	if err := copy.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("copied SDK frame acquired the original native source", err)
	}
	if err := copy.Close(); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("copied SDK frame removed original artifacts", err)
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("copied SDK frame revoked the authentic original", err)
	}
	// Capture supplies source/layout facts, not a completed body proof. Do not
	// freeze an obsolete unsupported-op diagnostic as a successful observation:
	// valid new typed families may subsequently make BindFixedLocal succeed.
	if fn.signature.x86FixedLocal != nil {
		t.Fatal("capturing a frame implicitly supplied a complete body proof")
	}
	original := observed.source.observation.ObjectInputs.Sources[0].Original
	after, err := os.ReadFile(filepath.Join(request.Directory, assembly))
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("SDK source was replaced or cropped", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal("SDK frame artifact cleanup", err)
	}
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("closed SDK frame retained its native source lifetime", err)
	}
}

func TestGoAMD64SDKFrameRejectsChangedProfile(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "crypto/md5")
	observed, err := CaptureGoAMD64SDKFrameObservation(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer observed.Close()
	pkg := sdkAMD64FrameActualPackage(t, observed.source)
	source, err := CaptureGoAMD64SDKFrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{GoBinary: request.GoBinary,
		Directory: request.Directory, AssemblyFile: "md5block_amd64.s", Target: request.Target, Environment: request.Environment})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	// The factory owns an independent environment copy; mutating the caller's
	// request must neither update its sealed profile nor revoke its lifetime.
	request.Environment[0] += "changed"
	if err := source.Verify(ctx); err != nil {
		t.Fatal("caller environment aliases the private SDK profile", err)
	}
	original := source.request.Target
	source.request.Target = "windows/amd64"
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("changed target retained the original SDK frame", err)
	}
	source.request.Target = original
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("restoring a changed SDK profile revived its frame", err)
	}
}

func TestGoAMD64SDKFrameRejectsChangedNativeWitness(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "crypto/md5")
	observed, err := CaptureGoAMD64SDKFrameObservation(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer observed.Close()
	pkg := sdkAMD64FrameActualPackage(t, observed.source)
	source, err := CaptureGoAMD64SDKFrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{GoBinary: request.GoBinary,
		Directory: request.Directory, AssemblyFile: "md5block_amd64.s", Target: request.Target, Environment: request.Environment})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	name := request.PackagePath + ".block"
	original := source.functions[name]
	changed := original
	changed.locals++
	source.functions[name] = changed
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("changed private native frame supplied backing", err)
	}
	source.functions[name] = original
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("restoring native metadata revived a revoked frame", err)
	}
}
