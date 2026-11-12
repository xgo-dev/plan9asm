//go:build go1.27

package plan9asm

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGoX86NumericalAssemblyOriginalCompleteThreeOS(t *testing.T) {
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			ctx, profile := sdkASMDataRequest(t, "amd64", "internal/bytealg")
			profile.Target = target
			goos, _, _ := strings.Cut(target, "/")
			for index, pair := range profile.Environment {
				if strings.HasPrefix(pair, "GOOS=") {
					profile.Environment[index] = "GOOS=" + goos
				}
			}
			metadata, err := CaptureGoX86SDKASMDataSource(ctx, profile)
			if err != nil {
				t.Fatal("complete selected SDK source/object precondition", err)
			}
			t.Cleanup(func() {
				if err := metadata.Close(); err != nil {
					t.Error(err)
				}
			})
			owner, err := CaptureGoNumericalStorageOwner(ctx, GoNumericalStorageCaptureRequest{
				GoBinary: profile.GoBinary, Directory: filepath.Join(filepath.Dir(profile.Directory), "cpu"),
				PackagePath: "internal/cpu", Target: target, Environment: profile.Environment, SDKCPU: true,
				Variables: []GoNumericalStorageReference{{PackagePath: "internal/cpu", Name: "X86"}},
			})
			if err != nil {
				t.Fatal("independent actual target CPU storage precondition", err)
			}
			t.Cleanup(owner.Close)
			source, err := CaptureGoX86SDKNumericalReadSource(ctx, GoX86NumericalReadCaptureRequest{
				GoBinary: profile.GoBinary, Directory: profile.Directory, PackagePath: profile.PackagePath,
				AssemblyFile: "count_amd64.s", Target: target, Environment: profile.Environment,
				AssemblySource: metadata, Owners: []*GoNumericalStorageOwner{owner},
			})
			if err != nil {
				t.Fatal("actual target source/NUM original-node join", err)
			}
			defer closeNumericalConsumerSource(t, source)
			if source.assembly == nil || source.literals != nil || len(source.file.Funcs) != 3 || len(source.reads) == 0 {
				t.Fatal("complete original nodes were replaced by an initializer or cropped source")
			}
			for _, read := range source.reads {
				if read.instruction < 0 || read.pc < 0 || read.variable.NativeName != "internal/cpu.X86" {
					t.Fatal("original instruction/native storage association was lost", read)
				}
			}
			if err := source.Verify(ctx); err != nil {
				t.Fatal("whole selected source no longer authenticates its original nodes", err)
			}
		})
	}
}

func numericalSDKAssemblyFixture(t *testing.T) (context.Context, GoX86NumericalReadCaptureRequest, *GoX86SDKASMDataSource, *GoNumericalStorageOwner) {
	t.Helper()
	ctx, request, owner := numericalSDKCPURequest(t, "amd64")
	request.Directory = filepath.Join(filepath.Dir(filepath.Dir(request.GoBinary)), "src", "internal", "bytealg")
	request.PackagePath, request.AssemblyFile = "internal/bytealg", "count_amd64.s"
	metadata, err := CaptureGoX86SDKASMDataSource(ctx, GoX86SDKASMDataCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, PackagePath: request.PackagePath,
		Target: request.Target, Environment: request.Environment,
	})
	if err != nil {
		t.Fatal("actual whole SDK source/CPP/object precondition", err)
	}
	t.Cleanup(func() {
		if err := metadata.Close(); err != nil {
			t.Error(err)
		}
	})
	request.AssemblySource = metadata
	return ctx, request, metadata, owner
}

func TestGoX86NumericalAssemblyOriginalMetadataRequestAndLifetime(t *testing.T) {
	ctx, request, metadata, owner := numericalSDKAssemblyFixture(t)
	for name, mutate := range map[string]func(*GoX86NumericalReadCaptureRequest){
		"target":    func(r *GoX86NumericalReadCaptureRequest) { r.Target = "windows/amd64" },
		"mode":      func(r *GoX86NumericalReadCaptureRequest) { r.Target = "linux/386" },
		"tool":      func(r *GoX86NumericalReadCaptureRequest) { r.GoBinary += ".different" },
		"directory": func(r *GoX86NumericalReadCaptureRequest) { r.Directory = filepath.Dir(r.Directory) },
		"package":   func(r *GoX86NumericalReadCaptureRequest) { r.PackagePath = "internal/cpu" },
		"environment": func(r *GoX86NumericalReadCaptureRequest) {
			r.Environment = append(append([]string(nil), r.Environment...), "GOAMD64=v3")
		},
		"member": func(r *GoX86NumericalReadCaptureRequest) { r.AssemblyFile = "unselected_amd64.s" },
		"copied source": func(r *GoX86NumericalReadCaptureRequest) {
			copy := new(GoX86SDKASMDataSource)
			reflect.ValueOf(copy).Elem().Set(reflect.ValueOf(metadata).Elem())
			r.AssemblySource = copy
		},
		"manual source": func(r *GoX86NumericalReadCaptureRequest) { r.AssemblySource = &GoX86SDKASMDataSource{} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			mutate(&changed)
			source, err := CaptureGoX86SDKNumericalReadSource(ctx, changed)
			if source != nil {
				t.Cleanup(func() { source.Close() })
			}
			if source != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("another profile/member/public value borrowed original metadata", err)
			}
			if err := metadata.Verify(ctx); err != nil {
				t.Fatal("request rejection revoked independent original metadata", err)
			}
		})
	}
	if source, err := CaptureGoX86NumericalReadSource(ctx, request); source != nil || !errors.Is(err, ErrProbeNeedsContext) {
		if source != nil {
			t.Cleanup(func() { source.Close() })
		}
		t.Fatal("owned-main route inherited SDK metadata permission", err)
	}
	for _, borrowed := range []bool{false, true} {
		source, err := CaptureGoX86SDKNumericalReadSource(ctx, request)
		if err != nil {
			t.Fatal("actual metadata-only numerical source", err)
		}
		t.Cleanup(func() {
			if err := source.Close(); err != nil {
				t.Error(err)
			}
		})
		if source.assembly == nil || source.literals != nil || source.assembly.source != metadata ||
			len(source.file.Funcs) != 3 || len(source.file.Data)+len(source.file.Globl) != 0 {
			t.Fatal("metadata-only route manufactured initializer/helper state or cropped source")
		}
		if !borrowed {
			if err := source.Close(); err != nil {
				t.Fatal(err)
			}
			if err := metadata.Verify(ctx); err != nil {
				t.Fatal("numerical Close closed its borrowed metadata", err)
			}
			if err := owner.Verify(ctx); err != nil {
				t.Fatal("numerical Close closed its independent storage owner", err)
			}
			continue
		}
		if err := metadata.Close(); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) || !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
			t.Fatal("closed metadata revived a numerical original-node observation")
		}
		if err := owner.Verify(ctx); err != nil {
			t.Fatal("metadata Close revoked independent numerical storage", err)
		}
	}
}

func TestGoX86NumericalAssemblyOriginalContextsCannotRevive(t *testing.T) {
	for _, kind := range []string{"nil", "canceled", "deadline", "original canceled"} {
		t.Run(kind, func(t *testing.T) {
			ctx, request, metadata, owner := numericalSDKAssemblyFixture(t)
			original, cancel := context.WithCancel(ctx)
			defer cancel()
			source, err := CaptureGoX86SDKNumericalReadSource(original, request)
			if err != nil {
				t.Fatal("actual joined source precondition", err)
			}
			defer closeNumericalConsumerSource(t, source)
			var verify context.Context
			want := ErrProbeNeedsContext
			switch kind {
			case "canceled":
				var stop context.CancelFunc
				verify, stop = context.WithCancel(ctx)
				stop()
				want = context.Canceled
			case "deadline":
				var stop context.CancelFunc
				verify, stop = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer stop()
				want = context.DeadlineExceeded
			case "original canceled":
				cancel()
				verify, want = ctx, context.Canceled
			}
			if err := source.Verify(verify); !errors.Is(err, want) || want != ErrProbeNeedsContext && errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("joined source lost its genuine context cause", kind, err)
			}
			if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("new context revived revoked numerical source")
			}
			if err := metadata.Verify(ctx); err != nil {
				t.Fatal("consumer context revoked independent metadata", err)
			}
			if err := owner.Verify(ctx); err != nil {
				t.Fatal("consumer context revoked independent storage", err)
			}
		})
	}
}

func TestGoX86NumericalAssemblyCallbacksRemainOutsideNumericalLock(t *testing.T) {
	for _, route := range []string{"original", "verification"} {
		for _, method := range []string{"Err", "Deadline", "Done"} {
			t.Run(route+"/"+method, func(t *testing.T) {
				ctx, request, metadata, owner := numericalSDKAssemblyFixture(t)
				callback := &sdkASMDataReentrantContext{Context: ctx, method: method}
				captureContext, verifyContext := ctx, ctx
				if route == "original" {
					captureContext = callback
				} else {
					verifyContext = callback
				}
				source, err := CaptureGoX86SDKNumericalReadSource(captureContext, request)
				if err != nil {
					t.Fatal("actual metadata join precondition", err)
				}
				defer closeNumericalConsumerSource(t, source)
				called, locked := false, false
				var nested error
				callback.callback = func() {
					called = true
					if !source.mu.TryLock() {
						locked = true
						return
					}
					source.mu.Unlock()
					nested = source.Close()
				}
				callback.armed.Store(true)
				if err := source.Verify(verifyContext); !called || locked || nested != nil || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("metadata join called user context under lock or published after Close", called, locked, nested, err)
				}
				if err := metadata.Verify(ctx); err != nil {
					t.Fatal("reentrant Close disposed borrowed metadata", err)
				}
				if err := owner.Verify(ctx); err != nil {
					t.Fatal("reentrant Close disposed independent numerical owner", err)
				}
			})
		}
	}
}

func TestGoX86NumericalAssemblyConcurrentVerifyCloseHasNoRevival(t *testing.T) {
	ctx, request, metadata, owner := numericalSDKAssemblyFixture(t)
	source, err := CaptureGoX86SDKNumericalReadSource(ctx, request)
	if err != nil {
		t.Fatal("actual metadata-only numerical join", err)
	}
	defer closeNumericalConsumerSource(t, source)
	var workers sync.WaitGroup
	for index := 0; index < 2; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := source.Verify(ctx); err != nil && !errors.Is(err, ErrProbeNeedsContext) {
				t.Error(err)
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	}()
	workers.Wait()
	if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
		t.Fatal("concurrent Close revived numerical source")
	}
	if err := metadata.Verify(ctx); err != nil {
		t.Fatal("concurrent Close revoked borrowed metadata", err)
	}
	if err := owner.Verify(ctx); err != nil {
		t.Fatal("concurrent Close revoked independent storage", err)
	}
}
