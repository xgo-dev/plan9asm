//go:build go1.27

package plan9asm

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestGoAMD64FrameOrdinaryCallKeepsPrivateLeafAndPrototypeBoundaries(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	t.Run("existing-private-asm", func(t *testing.T) {
		assembly := fixedLocalPrivateLeafSource("CALL leaf<>(SB)", "MOVQ (BP),AX")
		pkg, request, options := fixedLocalPrivateLeafFixture(t, assembly)
		ordinaryGoFrameCallOriginalPackage(t, request)
		fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
			func(t *testing.T, ir string, err error) {
				if err != nil || strings.Count(ir, "define ") != 1 || strings.Contains(ir, "call void @\"leaf") {
					t.Fatal("the established same-file private leaf acquired an ordinary callable ABI", err, ir)
				}
				fixedLocalPrivateLeafObjects(t, ir)
			})
	})
	for _, test := range []struct{ name, declaration string }{
		{"unknown-callee", "func Value(a uint64) uint64\n"},
		{"bodyless-prototype-only", "func Value(a uint64) uint64\nfunc Callee(a uint64) uint64\n"},
		{"pointer-callee", "func Value(a uint64) uint64\nfunc Callee(a *uint64) uint64 { return *a }\n"},
		{"floating-callee", "func Value(a uint64) uint64\nfunc Callee(a float64) float64 { return a }\n"},
		{"variadic-callee", "func Value(a uint64) uint64\nfunc Callee(a ...uint64) uint64 { return uint64(len(a)) }\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var pkg GoPackage
			var request GoAMD64FrameCaptureRequest
			var options Options
			if test.name == "variadic-callee" {
				// The actual source producer must reject this role. Do not ask
				// the independent nonvariadic ABI builder to accept it first.
				pkg, request = goAMD64FrameTypedFixture(t, test.declaration, ordinaryGoFrameCallAssembly)
			} else {
				pkg, request, _, options = ordinaryGoFrameCallFixture(t, test.declaration, ordinaryGoFrameCallAssembly)
			}
			frameRelocationOriginal(t, pkg, request)
			if test.name == "bodyless-prototype-only" && options.Sigs[pkg.Path+".Callee"].Name == "" {
				t.Fatal("the negative lost its caller-supplied typed signature")
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if owner != nil {
				defer func() {
					if err := owner.Close(); err != nil {
						t.Error(err)
					}
				}()
			}
			if test.name == "pointer-callee" {
				if err != nil {
					t.Fatal("actual typed pointer callee source was rejected", err)
				}
				file, err := Parse(ArchAMD64, ordinaryGoFrameCallAssembly)
				if err != nil {
					t.Fatal(err)
				}
				t.Run("signatures-alone", func(t *testing.T) {
					fixedLocalAPIs(t, pkg, file, options, func(t *testing.T, ir string, err error) {
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("a pointer callee signature granted an unobserved physical caller frame", err, ir)
						}
					})
				})
				t.Run("source-bound", func(t *testing.T) {
					fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
						func(t *testing.T, ir string, err error) {
							if err != nil || !strings.Contains(ir, "call i64 "+llvmGlobal(pkg.Path+".Callee")+"(ptr ") {
								t.Fatal("an initialized word did not retain its exact opaque-pointer call", err, ir)
							}
							ordinaryGoFrameCallObjects(t, ir)
						})
				})
				return
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("an unresolved target or prototype alone granted a callee/source contract", err)
			}
		})
	}
}

func TestGoAMD64FrameOrdinaryCallObjectRejectsRelocationAndABIChanges(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	pkg, request, file, _ := ordinaryGoFrameCallFixture(t,
		ordinaryGoFrameCallDeclarations, ordinaryGoFrameCallAssembly)
	ordinaryGoFrameCallOriginalPackage(t, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	objectPath := filepath.Join(t.TempDir(), "original.o")
	env := append(append([]string(nil), request.Environment...),
		"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOTOOLCHAIN=local",
		"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOPROXY=off")
	listing, err := goasmcmd.Run(ctx, request.Directory, env, request.GoBinary,
		"tool", "asm", "-S", "-p", pkg.Path, "-o", objectPath, request.AssemblyFile)
	if err != nil {
		t.Fatalf("original call object: %v\n%s", err, listing)
	}
	object, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	builtin, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(request.GoBinary)), "src/cmd/internal/goobj/builtinlist.go"))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := gostaticstorage.ObserveAMD64AssemblyData([]byte(ordinaryGoFrameCallAssembly), object, builtin, pkg.Path, request.Target)
	if err != nil || len(observed.Member.Texts) != 1 || len(observed.Member.Texts[0].Relocations) != 1 {
		t.Fatal("the independent object lost its single complete CALL", err)
	}
	original := observed.Member.Texts[0].Relocations[0]
	if !original.Target.ABIKnown || original.Target.ABI != 0 || original.Target.Name != pkg.Path+".Callee" ||
		!bytes.Contains(listing, []byte("t=R_CALL "+original.Target.Name+"+0")) ||
		goAMD64FrameDataRelocationLine(original, &observed) == "" {
		t.Fatal("canonical ordinary CALL no longer has an exact ABI0 object/listing observation", original)
	}
	for _, test := range []struct {
		name string
		edit func(*gostaticstorage.TextRelocation)
	}{
		{"wrong-ABI", func(r *gostaticstorage.TextRelocation) { r.Target.ABI = 1 }},
		{"unknown-ABI", func(r *gostaticstorage.TextRelocation) { r.Target.ABIKnown = false }},
		{"wrong-relocation", func(r *gostaticstorage.TextRelocation) { r.Type = 10 }},
		{"wrong-width", func(r *gostaticstorage.TextRelocation) { r.Size = 8 }},
		{"nonzero-addend", func(r *gostaticstorage.TextRelocation) { r.Add = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := original
			test.edit(&changed)
			if goAMD64FrameDataRelocationLine(changed, &observed) != "" {
				t.Fatal("a changed object role retained its ordinary ABI0 CALL observation", changed)
			}
		})
	}
	// Independently reject changed raw relocation text against the unchanged
	// actual object. The formatter above is not the permission/admission test.
	line := []byte("\t" + goAMD64FrameDataRelocationLine(original, &observed) + "\n")
	if bytes.Count(listing, line) != 1 {
		t.Fatal("the raw listing does not contain exactly one canonical CALL record")
	}
	for name, changed := range map[string][]byte{
		"raw-foreign-target": bytes.Replace(line, []byte(pkg.Path+".Callee"), []byte("foreign.Callee"), 1),
		"raw-width":          bytes.Replace(line, []byte("+4 t="), []byte("+8 t="), 1),
		"raw-relocation":     bytes.Replace(line, []byte("R_CALL"), []byte("R_PCREL"), 1),
		"raw-addend":         bytes.Replace(line, []byte("Callee+0"), []byte("Callee+1"), 1),
		"raw-missing":        nil,
		"raw-duplicate":      append(append([]byte(nil), line...), line...),
	} {
		t.Run(name, func(t *testing.T) {
			mutated := bytes.Replace(listing, line, changed, 1)
			if bytes.Equal(mutated, listing) {
				t.Fatal("the negative did not change the producer's raw relocation")
			}
			_, err := goAMD64FrameListingWithDataObject(mutated, file, pkg,
				map[string]int{request.AssemblyFile: strings.Count(ordinaryGoFrameCallAssembly, "\n") + 1},
				&observed, nil, request.Target, request.Directory, "")
			if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "object/listing relocation") {
				t.Fatal("changed raw CALL listing was not rejected by the exact-object join", err)
			}
		})
	}
}
