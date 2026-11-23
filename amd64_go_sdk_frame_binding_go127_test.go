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
	for _, goos := range []string{"linux", "windows"} {
		t.Run(goos, func(t *testing.T) {
			checkSDKAMD64FrameReadonlyDataComposition(t, goos)
		})
	}
}

func checkSDKAMD64FrameReadonlyDataComposition(t *testing.T, goos string) {
	t.Helper()
	ctx, request := sdkASMDataRequest(t, "amd64", "crypto/internal/fips140/sha512")
	setSDKAMD64FrameTestProfile(&request, goos, "v1")
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

func setSDKAMD64FrameTestProfile(request *GoX86SDKASMDataCaptureRequest, goos, cpu string) {
	request.Target = goos + "/amd64"
	for index, pair := range request.Environment {
		key, _, _ := strings.Cut(pair, "=")
		switch key {
		case "GOOS":
			request.Environment[index] = "GOOS=" + goos
		case "GOAMD64":
			request.Environment[index] = "GOAMD64=" + cpu
		}
	}
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

func TestGoAMD64SDKFrameRejectsDifferentArtifactOwner(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "crypto/md5")
	observed, err := CaptureGoAMD64SDKFrameObservation(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer observed.Close()
	pkg := sdkAMD64FrameActualPackage(t, observed.source)
	source, err := CaptureGoAMD64SDKFrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, AssemblyFile: "md5block_amd64.s",
		Target: request.Target, Environment: request.Environment,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	// A valid directory and its actual stat still belong to a different owner.
	source.owned = t.TempDir()
	source.ownedInfo, err = os.Lstat(source.owned)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("frame accepted an artifact directory outside its SDK owner's inventory", err)
	}
}

func TestGoAMD64SDKFrameOriginalRegisterEntry(t *testing.T) {
	for _, profile := range []struct{ goos, triple, cpu string }{
		{"linux", "x86_64-unknown-linux-gnu", "v1"},
		{"linux", "x86_64-unknown-linux-gnu", "v2"},
		{"windows", "x86_64-pc-windows-msvc", "v1"},
		{"windows", "x86_64-pc-windows-msvc", "v2"},
	} {
		t.Run(profile.goos+"-"+profile.cpu, func(t *testing.T) {
			ctx, request := sdkASMDataRequest(t, "amd64", "internal/chacha8rand")
			setSDKAMD64FrameTestProfile(&request, profile.goos, profile.cpu)
			observed, err := CaptureGoAMD64SDKFrameObservation(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { observed.Close() })
			pkg := sdkAMD64FrameActualPackage(t, observed.source)
			source, err := CaptureGoAMD64SDKFrameSource(ctx, pkg, GoAMD64FrameCaptureRequest{
				GoBinary: request.GoBinary, Directory: request.Directory, AssemblyFile: "chacha8_amd64.s",
				Target: request.Target, Environment: request.Environment,
			})
			if err != nil {
				t.Fatal("could not join the original register entry to its fixed frame", err)
			}
			defer source.Close()
			name := request.PackagePath + ".block"
			fn, found := source.functions[name]
			if !found || len(source.functions) != 1 || fn.nativeABI != 1 || fn.privateLeaf ||
				fn.sourceSymbol != "·block<ABIInternal>" || fn.locals != 24 || fn.split ||
				fn.signature.Name != name || fn.signature.Ret != Void || len(fn.signature.Args) != 3 ||
				fn.signature.Args[0] != Ptr || fn.signature.Args[1] != Ptr || fn.signature.Args[2] != I32 ||
				fn.signature.x86FixedLocal != nil {
				t.Fatalf("wrong original register entry, frame or typed declaration: name=%s found=%t ABI=%d locals=%d signature=%+v",
					name, found, fn.nativeABI, fn.locals, fn.signature)
			}
			if err := source.Verify(ctx); err != nil {
				t.Fatal("could not verify the original register entry", err)
			}
			assembly := observed.source.observation.CPP[0].Output
			file, err := Parse(ArchAMD64, assembly)
			if err != nil {
				t.Fatal(err)
			}
			resolve := testResolveSym(pkg.Path)
			options := Options{
				Goarch: "amd64", TargetTriple: profile.triple,
				ResolveSym: func(symbol string) string {
					name := resolve(symbol)
					if strings.HasSuffix(symbol, "<>") {
						name += "$local"
					}
					return name
				},
				Sigs: map[string]FuncSig{name: fn.signature},
			}
			if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("an unbound register signature acquired private stack storage", err)
			}
			if profile.goos == "linux" && profile.cpu == "v1" {
				changed := options
				changed.ResolveSym = func(symbol string) string {
					if symbol == "·block" {
						return pkg.Path + ".other"
					}
					return options.ResolveSym(symbol)
				}
				if bound, err := source.BindFixedLocal(ctx, pkg, file, changed); bound.Sigs != nil || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("conflicting raw and logical symbol resolution acquired the original entry", err)
				}
			}
			options, err = source.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatal("could not prove the complete Go register entry and its local accesses", err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("required LLVM 22 llc")
			}
			for _, api := range []string{"Translate", "Module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					fixedLocalAPI(t, pkg, file, options, api, func(t *testing.T, ir string, err error) {
						if err != nil || ir == "" {
							t.Fatal("original register entry translation failed", err)
						}
						compileLLVMToObject(t, llc, options.TargetTriple, "register-frame.ll", "register-frame.o", ir)
					}, assembly)
				})
			}
			if profile.goos == "windows" && profile.cpu == "v1" {
				unwind := source.sdkFrame.owner.source.observation.Frames[0].Unwind
				if unwind == nil || len(unwind.Unwind) != 1 {
					t.Fatal("the original Windows frame must retain its SEH record")
				}
				record := &unwind.Unwind[0]
				if record.PrologueEnd != 4 || record.PushEnd != 1 || len(record.Data) != 12 {
					t.Fatalf("unexpected original PUSHQ BP and MOVQ SP,BP metadata: %+v", record)
				}
				record.Data[6] ^= 1
				if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("changed original unwind bytes retained the frame binding", err)
				}
			}
		})
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
