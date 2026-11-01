//go:build go1.27

package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGoX86SDKLiteralAlignmentActualOriginalSource(t *testing.T) {
	for _, target := range []string{"linux/amd64", "linux/386", "darwin/amd64", "windows/amd64", "windows/386"} {
		t.Run(target, func(t *testing.T) {
			const pkg = "internal/runtime/maps"
			goos, arch, _ := strings.Cut(target, "/")
			ctx, request := sdkASMDataRequest(t, arch, pkg)
			request.Target = target
			for index, pair := range request.Environment {
				if strings.HasPrefix(pair, "GOOS=") {
					request.Environment[index] = "GOOS=" + goos
				}
			}
			source, err := CaptureGoX86SDKASMDataSource(ctx, request)
			if err != nil {
				t.Fatal("complete actual SDK source precondition", err)
			}
			defer source.Close()
			owner, err := CaptureGoX86SDKReadonlyLiteralDataOwner(ctx, source)
			if err != nil {
				t.Fatal("independent literal initializer precondition", err)
			}
			defer owner.Close()
			observed, err := CaptureGoX86SDKLiteralAlignment(ctx, owner)
			if err != nil || observed == nil {
				t.Fatal("real original linker cannot establish a separate minimum alignment role", err)
			}
			defer observed.Close()
			raw, err := observed.Readback(ctx)
			if err != nil || !json.Valid(raw) || !bytes.Contains(raw, []byte("MinimumAlignment")) {
				t.Fatal("linked rule omitted minimum alignment", err)
			}
			if bytes.Contains(raw, []byte("Address\"")) {
				t.Fatal("alignment report exports a numerical linked address")
			}
			var report sdkLiteralAlignmentReport
			if json.Unmarshal(raw, &report) != nil || report.Protocol != sdkLiteralAlignmentProtocol || report.Target != target ||
				report.InitializerSHA256 != owner.seal || len(report.Minima) != 2 {
				t.Fatal("link producer lost original exact complete table join", report)
			}
			for _, minimum := range report.Minima {
				if minimum.MinimumAlignment != 32 || minimum.Size != 256 || minimum.Namespace != gostaticstorage.TextSymbolSelf {
					t.Fatal("original source/linker rule minimum differs", minimum)
				}
			}
			program, err := os.ReadFile(filepath.Join(observed.guard.owned, "main.go"))
			if err != nil || string(program) != "package main\nfunc main() {}\n" {
				t.Fatal("link witness bypassed internal imports", err, string(program))
			}
			for _, name := range []string{"Bind", "BindNumericalReads", "Options", "Pointer", "Read", "Execute", "Variable"} {
				if _, exists := reflect.TypeOf(observed).MethodByName(name); exists {
					t.Fatal("alignment observation granted another role", name)
				}
			}
			if source.guard.ready || source.guard.request.NumericalReads != nil {
				t.Fatal("link observation created frame/read permission")
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(observed.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("closed initializer retained link authority")
			}
			if err := source.Verify(ctx); err != nil {
				t.Fatal("link token borrowed ownership of its original source", err)
			}
		})
	}
}

func sdkLiteralAlignmentCapture(t *testing.T) (context.Context, *GoX86SDKASMDataSource, *GoX86SDKReadonlyLiteralDataOwner, *GoX86SDKLiteralAlignment) {
	t.Helper()
	ctx, request := sdkASMDataRequest(t, "amd64", "internal/runtime/maps")
	source, err := CaptureGoX86SDKASMDataSource(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	owner, err := CaptureGoX86SDKReadonlyLiteralDataOwner(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close() })
	observed, err := CaptureGoX86SDKLiteralAlignment(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { observed.Close() })
	return ctx, source, owner, observed
}

func TestGoX86SDKLiteralAlignmentCGOProfileAndCopyClose(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "internal/runtime/maps")
	for index, pair := range request.Environment {
		if strings.HasPrefix(pair, "CGO_ENABLED=") {
			request.Environment[index] = "CGO_ENABLED=1"
		}
	}
	source, err := CaptureGoX86SDKASMDataSource(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	owner, err := CaptureGoX86SDKReadonlyLiteralDataOwner(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	observed, err := CaptureGoX86SDKLiteralAlignment(ctx, owner)
	if err != nil {
		t.Fatal("actual CGO=1 pure SDK graph/link precondition", err)
	}
	defer observed.Close()
	if observed.observation.CGOEnabled != "1" {
		t.Fatal("link producer forced a diagnostic CGO=0 profile")
	}
	copy := reflect.New(reflect.TypeOf(observed).Elem())
	copy.Elem().Set(reflect.ValueOf(observed).Elem())
	cloned := copy.Interface().(*GoX86SDKLiteralAlignment)
	if !errors.Is(cloned.Verify(ctx), ErrProbeNeedsContext) || !errors.Is(cloned.Close(), ErrProbeNeedsContext) {
		t.Fatal("copied linker token disposed/borrowed original artifacts")
	}
	owned, originalOwned := observed.guard.owned, source.guard.owned
	if err := observed.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if err := observed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Fatal("linker-owned artifacts were not released", err)
	}
	if _, err := os.Stat(originalOwned); err != nil {
		t.Fatal("linker Close disposed original source", err)
	}
	if err := owner.Verify(ctx); err != nil {
		t.Fatal("linker close revoked initializer", err)
	}
}

func TestGoX86SDKLiteralAlignmentSealedIdentityAndLifetime(t *testing.T) {
	for name, mutate := range map[string]func(*GoX86SDKLiteralAlignment){
		"public-report":     func(o *GoX86SDKLiteralAlignment) { o.report[0] ^= 1 },
		"minimum-injection": func(o *GoX86SDKLiteralAlignment) { o.observation.Minima[0].MinimumAlignment = 64 },
		"source-ordinal":    func(o *GoX86SDKLiteralAlignment) { o.observation.Minima[0].SourceOrdinal++ },
		"object-index":      func(o *GoX86SDKLiteralAlignment) { o.observation.Minima[0].Index++ },
		"link-binary-digest": func(o *GoX86SDKLiteralAlignment) {
			o.guard.inputs[filepath.Join(o.guard.env["GOTOOLDIR"], "link")] = sha256.Sum256([]byte("forged tool"))
		},
		"input-profile":          func(o *GoX86SDKLiteralAlignment) { o.guard.env["CGO_ENABLED"] = "0-unobserved" },
		"initializer-generation": func(o *GoX86SDKLiteralAlignment) { o.ownerGeneration++ },
		"initializer-closed":     func(o *GoX86SDKLiteralAlignment) { o.owner.Close() },
		"source-closed":          func(o *GoX86SDKLiteralAlignment) { o.owner.source.Close() },
		"guard-role":             func(o *GoX86SDKLiteralAlignment) { o.guard.ready = true },
		"linked-object-bytes": func(o *GoX86SDKLiteralAlignment) {
			name := filepath.Join(o.guard.owned, "original-linked")
			data, err := os.ReadFile(name)
			if err != nil {
				panic(err)
			}
			data[len(data)-1] ^= 1
			if err := os.WriteFile(name, data, 0600); err != nil {
				panic(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, _, _, observed := sdkLiteralAlignmentCapture(t)
			mutate(observed)
			if raw, err := observed.Readback(ctx); raw != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed link source/tool/object/profile/lifetime published minima", err)
			}
			if !errors.Is(observed.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("restored/changed link token revived")
			}
		})
	}
}

func TestGoX86SDKLiteralAlignmentOriginalContextDeadline(t *testing.T) {
	ctx, source, owner, _ := sdkLiteralAlignmentCapture(t)
	for _, change := range []string{"earlier", "later", "lost", "cancel"} {
		t.Run(change, func(t *testing.T) {
			original, cancel := context.WithCancel(ctx)
			defer cancel()
			mutable := &sdkASMDataReentrantContext{Context: original}
			observed, err := CaptureGoX86SDKLiteralAlignment(mutable, owner)
			if err != nil {
				t.Fatal(err)
			}
			defer observed.Close()
			want := ErrProbeNeedsContext
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
			}
			if raw, err := observed.Readback(ctx); raw != nil || !errors.Is(err, want) {
				t.Fatal("changed original context published alignment facts", err)
			}
			mutable.shift.Store(0)
			mutable.lost.Store(false)
			if !errors.Is(observed.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("restored deadline revived revoked alignment")
			}
			if err := source.Verify(ctx); err != nil {
				t.Fatal("link lifetime revoked original source", err)
			}
		})
	}
}

func TestGoX86SDKLiteralAlignmentNoInventedRetainedWinner(t *testing.T) {
	for _, pkg := range []string{"internal/chacha8rand"} {
		t.Run(pkg, func(t *testing.T) {
			ctx, request := sdkASMDataRequest(t, "amd64", pkg)
			source, err := CaptureGoX86SDKASMDataSource(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			owner, err := CaptureGoX86SDKReadonlyLiteralDataOwner(ctx, source)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			observed, err := CaptureGoX86SDKLiteralAlignment(ctx, owner)
			if observed != nil || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "uniquely retained") {
				if observed != nil {
					observed.Close()
				}
				t.Fatal("deadstripped/ambiguous original literals acquired a linked winner", observed != nil, err)
			}
			if err := owner.Verify(ctx); err != nil {
				t.Fatal("failed independent link role revoked its initializer", err)
			}
		})
	}
}

func TestGoX86SDKLiteralAlignmentPublicPackageDifferentExtents(t *testing.T) {
	ctx, source, owner := readonlyLiteralCapture(t)
	observed, err := CaptureGoX86SDKLiteralAlignment(ctx, owner)
	if err != nil {
		t.Fatal("real ordinary public SDK import/link precondition", err)
	}
	defer observed.Close()
	if len(observed.observation.Minima) != 4 {
		t.Fatal("naturally initialized public SDK literals omitted", len(observed.observation.Minima))
	}
	alignments := make(map[uint32]bool)
	for _, minimum := range observed.observation.Minima {
		want := goAssemblyDataAlignment(ArchAMD64, int64(minimum.Size))
		if int64(minimum.MinimumAlignment) != want {
			t.Fatal("public source's actual size-dependent minimum differs", minimum)
		}
		alignments[minimum.MinimumAlignment] = true
	}
	if !alignments[8] || !alignments[16] || !alignments[32] {
		t.Fatal("minimum alignment was hardcoded to the maps tables")
	}
	program, err := os.ReadFile(filepath.Join(observed.guard.owned, "main.go"))
	if err != nil || string(program) != "package main\nimport _ \"hash/crc32\"\nfunc main() {}\n" {
		t.Fatal("public SDK link changed its permitted original import", err)
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestGoX86SDKLiteralAlignmentBytesAreNotProducer(t *testing.T) {
	if result, err := CaptureGoX86SDKLiteralAlignment(nil, nil); result != nil || !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "alignment") {
		t.Fatal("public bytes/empty token supplied linked address facts", result, err)
	}
}
