//go:build go1.27

package plan9asm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// These are two different actual SDK packages, not library-name allowlists.
// Complete source/header/CPP/object observation must close before the new
// initializer factory is asked to establish its independent role.
func TestGoX86SDKReadonlyLiteralDataActualSources(t *testing.T) {
	for _, selected := range []struct{ arch, pkg string }{
		{"amd64", "hash/crc32"},
		{"amd64", "internal/chacha8rand"},
		{"386", "internal/runtime/maps"},
	} {
		t.Run(selected.pkg+"/"+selected.arch, func(t *testing.T) {
			pkg := selected.pkg
			ctx, request := sdkASMDataRequest(t, selected.arch, pkg)
			source, err := CaptureGoX86SDKASMDataSource(ctx, request)
			if err != nil {
				t.Fatal("actual complete SDK observation precondition", err)
			}
			t.Cleanup(func() { source.Close() })
			sdkASMDataRetain(t, source)
			owner, err := CaptureGoX86SDKReadonlyLiteralDataOwner(ctx, source)
			if err != nil || owner == nil {
				t.Fatal("actual SDK private readonly literal initializer is not certified", err)
			}
			t.Cleanup(func() { owner.Close() })
			raw, err := owner.Readback(ctx)
			if err != nil || owner.CheckReadback(ctx, raw) != nil {
				t.Fatal("live exact initializer readback is not closed", err)
			}
			var report sdkReadonlyLiteralDataReport
			if json.Unmarshal(raw, &report) != nil || report.Protocol != sdkReadonlyLiteralDataProtocol ||
				report.Target != request.Target || report.PackagePath != pkg || report.SourceReportSHA256 != source.seal ||
				report.SourceGeneration != source.generation || len(report.Initializers) == 0 {
				t.Fatal("initializer omitted the whole actual SDK source identity")
			}
			count := 0
			for _, observed := range source.observation.Objects.Sources {
				count += len(observed.ExpandedLayouts)
			}
			if len(report.Initializers) != count {
				t.Fatal("initializer omitted selected source private DATA")
			}
			for _, image := range report.Initializers {
				member := source.observation.Objects.Members[image.MemberOrdinal]
				found := false
				for _, definition := range member.Definitions {
					if definition.Namespace == image.Definition.Namespace && definition.Index == image.Definition.Index {
						found = true
						if !reflect.DeepEqual(definition, image.Definition) || int(definition.Size) != len(image.Initial) ||
							!bytes.Equal(definition.Data, image.Initial[:len(definition.Data)]) {
							t.Fatal("initializer selected another source/object-local definition")
						}
						for _, value := range image.Initial[len(definition.Data):] {
							if value != 0 {
								t.Fatal("initializer tail is not exact Go zero padding")
							}
						}
					}
				}
				if !found {
					t.Fatal("initializer object identity is absent from the whole archive")
				}
			}
			for _, name := range []string{"Bind", "BindNumericalReads", "Options", "Pointer", "Read", "Variable", "Owners", "GoPackage"} {
				if _, present := reflect.TypeOf(owner).MethodByName(name); present {
					t.Fatal("literal initialization borrowed another authority", name)
				}
			}
			if folder := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR"); folder != "" {
				name := strings.ReplaceAll(t.Name(), "/", "-")
				if err := os.WriteFile(filepath.Join(folder, name+".readonly-literal.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func readonlyLiteralCapture(t *testing.T) (context.Context, *GoX86SDKASMDataSource, *GoX86SDKReadonlyLiteralDataOwner) {
	t.Helper()
	ctx, request := sdkASMDataRequest(t, "amd64", "hash/crc32")
	source, err := CaptureGoX86SDKASMDataSource(ctx, request)
	if err != nil {
		t.Fatal("actual SDK source precondition", err)
	}
	t.Cleanup(func() { source.Close() })
	owner, err := CaptureGoX86SDKReadonlyLiteralDataOwner(ctx, source)
	if err != nil {
		t.Fatal("actual literal owner precondition", err)
	}
	t.Cleanup(func() { owner.Close() })
	return ctx, source, owner
}

func readonlyLiteralInvoke(t *testing.T, api string, owner *GoX86SDKReadonlyLiteralDataOwner, ctx context.Context, raw []byte) ([]byte, error) {
	t.Helper()
	switch api {
	case "Verify":
		return nil, owner.Verify(ctx)
	case "Readback":
		return owner.Readback(ctx)
	case "CheckReadback":
		return nil, owner.CheckReadback(ctx, raw)
	}
	t.Fatal("unknown initializer API")
	return nil, nil
}

func TestGoX86SDKReadonlyLiteralDataCopyCloseAndBytes(t *testing.T) {
	ctx, source, owner := readonlyLiteralCapture(t)
	copy := reflect.New(reflect.TypeOf(owner).Elem())
	copy.Elem().Set(reflect.ValueOf(owner).Elem())
	copied := copy.Interface().(*GoX86SDKReadonlyLiteralDataOwner)
	if !errors.Is(copied.Verify(ctx), ErrProbeNeedsContext) || !errors.Is(copied.Close(), ErrProbeNeedsContext) {
		t.Fatal("copied initializer borrowed or revoked its original token")
	}
	if err := owner.Verify(ctx); err != nil {
		t.Fatal("copied initializer affected its original owner", err)
	}
	raw, err := owner.Readback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if owner.CheckReadback(ctx, append(raw, ' ')) == nil || !errors.Is(owner.Verify(ctx), ErrProbeNeedsContext) {
		t.Fatal("public bytes recreated an initializer or restoration revived it")
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("initializer byte mismatch revoked its independently owned source", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(source.guard.owned); err != nil {
		t.Fatal("initializer cleanup deleted the source artifacts", err)
	}
	if source.guard.ready || source.guard.request.NumericalReads != nil {
		t.Fatal("literal initializer granted frame or numerical-read permission")
	}
}

func TestGoX86SDKReadonlyLiteralDataSourceAndOwnerMutations(t *testing.T) {
	for name, mutate := range map[string]func(*GoX86SDKASMDataSource, *GoX86SDKReadonlyLiteralDataOwner){
		"source-close":            func(s *GoX86SDKASMDataSource, _ *GoX86SDKReadonlyLiteralDataOwner) { s.Close() },
		"owner-close":             func(_ *GoX86SDKASMDataSource, o *GoX86SDKReadonlyLiteralDataOwner) { o.Close() },
		"source-generation":       func(s *GoX86SDKASMDataSource, _ *GoX86SDKReadonlyLiteralDataOwner) { s.generation++ },
		"owner-source-generation": func(_ *GoX86SDKASMDataSource, o *GoX86SDKReadonlyLiteralDataOwner) { o.sourceGeneration++ },
		"source-bytes":            func(s *GoX86SDKASMDataSource, _ *GoX86SDKReadonlyLiteralDataOwner) { s.report[0] ^= 1 },
		"object-index": func(s *GoX86SDKASMDataSource, _ *GoX86SDKReadonlyLiteralDataOwner) {
			s.observation.Objects.Members[2].Definitions[0].Index++
		},
		"object-data": func(s *GoX86SDKASMDataSource, _ *GoX86SDKReadonlyLiteralDataOwner) {
			s.observation.Objects.Members[2].Definitions[0].Data[0] ^= 1
		},
		"original-ASM": func(s *GoX86SDKASMDataSource, _ *GoX86SDKReadonlyLiteralDataOwner) {
			s.observation.ObjectInputs.Sources[0].Original[0] ^= 1
		},
		"header": func(s *GoX86SDKASMDataSource, _ *GoX86SDKReadonlyLiteralDataOwner) {
			s.observation.Header.Actual[0] ^= 1
		},
		"source-selection": func(s *GoX86SDKASMDataSource, _ *GoX86SDKReadonlyLiteralDataOwner) { s.guard.selection.SFiles = nil },
		"archive": func(s *GoX86SDKASMDataSource, _ *GoX86SDKReadonlyLiteralDataOwner) {
			s.observation.ObjectInputs.Archive[0] ^= 1
		},
		"foreign-source": func(_ *GoX86SDKASMDataSource, o *GoX86SDKReadonlyLiteralDataOwner) {
			o.source = &GoX86SDKASMDataSource{}
		},
		"owner-bytes":   func(_ *GoX86SDKASMDataSource, o *GoX86SDKReadonlyLiteralDataOwner) { o.report[0] ^= 1 },
		"owner-context": func(_ *GoX86SDKASMDataSource, o *GoX86SDKReadonlyLiteralDataOwner) { o.context = context.Background() },
	} {
		t.Run(name, func(t *testing.T) {
			ctx, source, owner := readonlyLiteralCapture(t)
			mutate(source, owner)
			if err := owner.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed whole source or exact initializer verified", err)
			}
			if owner.ready || !errors.Is(owner.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("revoked literal initializer revived")
			}
		})
	}
}

func TestGoX86SDKReadonlyLiteralDataContextReentry(t *testing.T) {
	for _, route := range []string{"original", "verification"} {
		for _, method := range []string{"Err", "Deadline", "Done"} {
			t.Run(route+"/"+method, func(t *testing.T) {
				// Bound one independent callback role, not the cumulative
				// race-instrumented work of all 24 owner/API combinations.
				ctx, source, _ := readonlyLiteralCapture(t)
				for _, api := range []string{"Verify", "Readback", "CheckReadback", "Close"} {
					t.Run(api, func(t *testing.T) {
						verification, cancel := context.WithCancel(ctx)
						defer cancel()
						callback := &sdkASMDataReentrantContext{Context: verification, method: method}
						captureContext := verification
						if route == "original" {
							captureContext = callback
						}
						owner, err := CaptureGoX86SDKReadonlyLiteralDataOwner(captureContext, source)
						if err != nil {
							t.Fatal(err)
						}
						defer owner.Close()
						raw, err := owner.Readback(ctx)
						if err != nil {
							t.Fatal(err)
						}
						var nested error
						callback.callback = func() {
							if api == "Close" {
								nested = owner.Close()
							} else {
								_, nested = readonlyLiteralInvoke(t, api, owner, verification, raw)
							}
						}
						callback.armed.Store(true)
						finished := make(chan error, 1)
						go func() { finished <- errors.Join(owner.Verify(callback), nested) }()
						select {
						case err := <-finished:
							if api == "Close" {
								if !errors.Is(err, ErrProbeNeedsContext) || owner.ready {
									t.Fatal("reentrant Close published a revoked initializer", err)
								}
							} else if err != nil {
								t.Fatal("initializer validation callback deadlocked or rejected its actual owner", err)
							}
						case <-ctx.Done():
							// Actual SDK validation can take longer under the race
							// detector. Use the existing producer/test deadline,
							// cancel and join this worker before ending the case.
							cancel()
							err := <-finished
							t.Fatal("initializer callback exceeded its existing bounded context", ctx.Err(), err)
						}
						if err := source.Verify(ctx); err != nil {
							t.Fatal("initializer callback disposed its source", err)
						}
					})
				}
			})
		}
	}
}

func TestGoX86SDKReadonlyLiteralDataOriginalDeadlineAndCancellation(t *testing.T) {
	ctx, source, _ := readonlyLiteralCapture(t)
	for _, change := range []string{"earlier", "later", "lost", "cancel", "expired"} {
		for _, api := range []string{"Verify", "Readback", "CheckReadback"} {
			t.Run(change+"/"+api, func(t *testing.T) {
				original, cancel := context.WithCancel(ctx)
				defer cancel()
				mutable := &sdkASMDataReentrantContext{Context: original}
				owner, err := CaptureGoX86SDKReadonlyLiteralDataOwner(mutable, source)
				if err != nil {
					t.Fatal(err)
				}
				defer owner.Close()
				raw, err := owner.Readback(ctx)
				if err != nil {
					t.Fatal(err)
				}
				want := ErrProbeNeedsContext
				verification := ctx
				switch change {
				case "earlier":
					mutable.shift.Store(-int64(time.Minute))
				case "later":
					mutable.shift.Store(int64(time.Minute))
				case "lost":
					mutable.lost.Store(true)
				case "cancel":
					cancel()
					want = context.Canceled
				case "expired":
					verification, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
					defer cancel()
					want = context.DeadlineExceeded
				}
				returned, err := readonlyLiteralInvoke(t, api, owner, verification, raw)
				if !errors.Is(err, want) || len(returned) != 0 {
					t.Fatal("changed lifecycle published initialized bytes or lost actual cause", err)
				}
				mutable.shift.Store(0)
				mutable.lost.Store(false)
				if !errors.Is(owner.Verify(ctx), ErrProbeNeedsContext) {
					t.Fatal("restoring the original deadline revived the initializer")
				}
			})
		}
	}
}

func TestGoX86SDKReadonlyLiteralDataConcurrentClose(t *testing.T) {
	ctx, source, owner := readonlyLiteralCapture(t)
	var workers sync.WaitGroup
	for index := 0; index < 4; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := owner.Verify(ctx); err != nil && !errors.Is(err, ErrProbeNeedsContext) {
				t.Error(err)
			}
		}()
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if !errors.Is(owner.Verify(ctx), ErrProbeNeedsContext) || source.Verify(ctx) != nil {
		t.Fatal("concurrent initializer close revived it or deleted independent source")
	}
}

func TestGoX86SDKReadonlyLiteralDataNoJSONOrOtherRole(t *testing.T) {
	ctx, source := sdkASMDataCapture(t)
	owner, err := CaptureGoX86SDKReadonlyLiteralDataOwner(ctx, source)
	if owner != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("SDK source without literal DATA acquired initializer permission", err)
	}
	var zero GoX86SDKReadonlyLiteralDataOwner
	if !errors.Is(zero.Verify(ctx), ErrProbeNeedsContext) || !errors.Is(zero.Close(), ErrProbeNeedsContext) {
		t.Fatal("zero public token recreated a private initializer owner")
	}
	for _, input := range []*GoX86SDKASMDataSource{nil, {}} {
		if owner, err := CaptureGoX86SDKReadonlyLiteralDataOwner(ctx, input); owner != nil || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("unbound source or public JSON could construct a live literal owner", err)
		}
	}
	// Go storage types are still observations, not substitutes for this token.
	if _, present := reflect.TypeOf((*gostaticstorage.Variable)(nil)).MethodByName("Initializers"); present {
		t.Fatal("literal initialization replaced the original Go Variable role")
	}
}

func TestGoX86SDKReadonlyLiteralDataExactSourceIdentity(t *testing.T) {
	ctx, source, owner := readonlyLiteralCapture(t)
	other, err := CaptureGoX86SDKASMDataSource(ctx, source.request)
	if err != nil {
		t.Fatal("second independent actual SDK source", err)
	}
	defer other.Close()
	owner.source = other
	if err := owner.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("another real same-package source replaced the exact original owner", err)
	}
	owner.source = source
	if !errors.Is(owner.Verify(ctx), ErrProbeNeedsContext) || other.Verify(ctx) != nil || source.Verify(ctx) != nil {
		t.Fatal("source restoration revived the initializer or affected the independent owners")
	}
	copy := reflect.New(reflect.TypeOf(source).Elem())
	copy.Elem().Set(reflect.ValueOf(source).Elem())
	copied := copy.Interface().(*GoX86SDKASMDataSource)
	if owner, err := CaptureGoX86SDKReadonlyLiteralDataOwner(ctx, copied); owner != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("whole copied real source minted a fresh initializer identity", err)
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("copied factory input revoked its original source", err)
	}
}

func TestGoX86SDKReadonlyLiteralDataPhysicalHeaderTOCTOU(t *testing.T) {
	ctx, source, owner := readonlyLiteralCapture(t)
	file := filepath.Join(source.guard.owned, "go_asm.h")
	original, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, append(original, []byte("#define initializer_foreign 7\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if err := owner.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("changed physical original compiler header preserved initialized bytes", err)
	}
	if err := os.WriteFile(file, original, 0600); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(owner.Verify(ctx), ErrProbeNeedsContext) {
		t.Fatal("physical header restoration revived the initializer")
	}
}

func TestGoX86SDKReadonlyLiteralDataCallbackCannotPublish(t *testing.T) {
	ctx, source, _ := readonlyLiteralCapture(t)
	for _, route := range []string{"original", "verification"} {
		for _, api := range []string{"Verify", "Readback", "CheckReadback"} {
			t.Run(route+"/"+api, func(t *testing.T) {
				original := &sdkASMDataReentrantContext{Context: ctx}
				owner, err := CaptureGoX86SDKReadonlyLiteralDataOwner(original, source)
				if err != nil {
					t.Fatal(err)
				}
				defer owner.Close()
				raw, err := owner.Readback(ctx)
				if err != nil {
					t.Fatal(err)
				}
				callback := &sdkASMDataReentrantContext{Context: ctx, method: "Done"}
				verification := context.Context(callback)
				if route == "original" {
					callback, verification = original, ctx
					callback.method = "Done"
				}
				callback.callback = func() { original.shift.Store(int64(time.Minute)) }
				callback.armed.Store(true)
				returned, err := readonlyLiteralInvoke(t, api, owner, verification, raw)
				if !errors.Is(err, ErrProbeNeedsContext) || len(returned) != 0 {
					t.Fatal("caller callback published a changed original initializer generation", err)
				}
				original.shift.Store(0)
				if !errors.Is(owner.Verify(ctx), ErrProbeNeedsContext) {
					t.Fatal("callback deadline restoration revived the initializer")
				}
			})
		}
	}
}

func TestGoX86SDKReadonlyLiteralDataConcurrentSourceRevocation(t *testing.T) {
	for _, api := range []string{"Verify", "Readback", "CheckReadback"} {
		t.Run(api, func(t *testing.T) {
			ctx, source, owner := readonlyLiteralCapture(t)
			verification, cancel := context.WithCancel(ctx)
			defer cancel()
			raw, err := owner.Readback(ctx)
			if err != nil {
				t.Fatal(err)
			}
			entered, resume := make(chan struct{}), make(chan struct{})
			callback := &sdkASMDataReentrantContext{Context: verification, method: "Done"}
			callback.callback = func() { close(entered); <-resume }
			callback.armed.Store(true)
			finished := make(chan error, 1)
			go func() {
				returned, err := readonlyLiteralInvoke(t, api, owner, callback, raw)
				if len(returned) != 0 {
					err = errors.Join(err, errors.New("revoked source published an initializer report"))
				}
				finished <- err
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				cancel()
				close(resume)
				err := <-finished
				t.Fatal("source revocation control exceeded its existing context before caller callback", ctx.Err(), err)
			}
			closed := source.Close()
			close(resume)
			select {
			case err := <-finished:
				if closed != nil || !errors.Is(err, ErrProbeNeedsContext) || owner.ready {
					t.Fatal("concurrent source Close published a stale initializer", err, closed)
				}
			case <-ctx.Done():
				cancel()
				err := <-finished
				t.Fatal("source Close and initializer callback exceeded their existing context", ctx.Err(), err)
			}
		})
	}
}
