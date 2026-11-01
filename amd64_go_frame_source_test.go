package plan9asm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

func requireGoAMD64FrameCapture(t *testing.T, pkg GoPackage, request GoAMD64FrameCaptureRequest) *GoAMD64FrameSource {
	t.Helper()
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	return source
}

func goAMD64FrameSourceFixture(t *testing.T) (GoPackage, GoAMD64FrameCaptureRequest) {
	t.Helper()
	// Keep AST positions, the caller's request and strict original-file reads
	// bound to the same physical fixture, including aliased temporary roots.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("cannot resolve original frame fixture directory", err)
	}
	source := []byte("package framefixture\nfunc Value(a uint64) uint64\n")
	files := map[string][]byte{
		"go.mod":        []byte("module example.invalid/framefixture\ngo 1.20\n"),
		"value.go":      source,
		"value_amd64.s": []byte("#include \"textflag.h\"\nTEXT ·Value(SB),NOSPLIT,$160-16\nMOVQ a+0(FP),AX\nMOVQ AX,16(SP)\nMOVQ 16(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, filepath.Join(dir, "value.go"), source, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", "amd64")
	pkg, err := (&types.Config{Sizes: sizes}).Check("example.invalid/framefixture", fset, []*ast.File{syntax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	// This independent pure-Go module does not inherit the translator test
	// binary's build tags (notably Windows' LLVM byollvm tag). Remove rather
	// than shadow them: production capture rejects repeated forbidden flags.
	var env []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GOFLAGS=") {
			env = append(env, entry)
		}
	}
	env = append(env, "GOFLAGS=")
	for _, key := range []string{"GOPATH", "GOMODCACHE", "GOCACHE", "TMPDIR", "GOTMPDIR"} {
		if !filepath.IsAbs(os.Getenv(key)) {
			env = append(env, key+"="+t.TempDir())
		}
	}
	return GoPackage{Path: pkg.Path(), Types: pkg, Syntax: []*ast.File{syntax}}, GoAMD64FrameCaptureRequest{
		GoBinary: binary, Directory: dir, AssemblyFile: "value_amd64.s", Target: "linux/amd64", Environment: env,
	}
}

func TestGoAMD64FrameSourceActualCaptureAndSealedLifecycle(t *testing.T) {
	pkg, request := goAMD64FrameSourceFixture(t)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	// Independent original-Go acceptance precedes the proposed token. This
	// object observation is not itself a native-memory authorization.
	raw, err := os.ReadFile(filepath.Join(request.Directory, request.AssemblyFile))
	if err != nil {
		t.Fatal(err)
	}
	listing := x86InsertExtractGoListing(t, "amd64", strings.Replace(string(raw), "#include \"textflag.h\"", "#define NOSPLIT 4", 1))
	t.Logf("actual stock-Go original nonzero TEXT listing:\n%s", listing)
	source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := source.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if len(source.functions) != 1 || source.functions["example.invalid/framefixture.Value"].locals != 168 {
		t.Fatalf("missing actual Go frame witness: %+v", source.functions)
	}
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var restored GoAMD64FrameSource
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(restored.Verify(ctx), ErrProbeNeedsContext) {
		t.Fatal("JSON recreated private frame authority")
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
		t.Fatal("closed witness retained authority")
	}
}

func TestGoAMD64FrameSourceRefusesSelfReportedSelection(t *testing.T) {
	for _, mutation := range []string{"wrong types", "missing sibling", "dependency", "generated header", "source changed", "same width signedness", "target", "custom flags", "conditional CPP", "raw RET", "zero frame", "pointer", "unknown tool"} {
		t.Run(mutation, func(t *testing.T) {
			pkg, request := goAMD64FrameSourceFixture(t)
			switch mutation {
			case "wrong types":
				pkg.Types = types.NewPackage(pkg.Path, "forged")
			case "missing sibling":
				if err := os.WriteFile(filepath.Join(request.Directory, "sibling_amd64.s"), []byte("TEXT ·Other(SB),4,$8-0\nRET\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "dependency":
				if err := os.WriteFile(filepath.Join(request.Directory, "dep.go"), []byte("package framefixture\nimport _ \"unsafe\"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "generated header":
				if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte("#include \"go_asm.h\"\nTEXT ·Value(SB),4,$160-16\nRET\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "source changed":
				if err := os.WriteFile(filepath.Join(request.Directory, "value.go"), []byte("package framefixture\nfunc Value(a uint32) uint32\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "target":
				request.Target = "linux/386"
			case "same width signedness":
				if err := os.WriteFile(filepath.Join(request.Directory, "value.go"), []byte("package framefixture\nfunc Value(a int64) int64\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "custom flags":
				request.Environment = append(request.Environment, "GOFLAGS=-tags=custom")
			case "conditional CPP":
				if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte("#ifdef GOARCH_amd64\n#include \"go_asm.h\"\nTEXT ·Value(SB),4,$160-16\nRET\n#endif\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "raw RET":
				if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte("TEXT ·Value(SB),4,$160-16\nBYTE $0xc3\nRET\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "zero frame":
				if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte("TEXT ·Value(SB),4,$0-16\nRET\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "pointer":
				if err := os.WriteFile(filepath.Join(request.Directory, "value.go"), []byte("package framefixture\nfunc Value(a *uint64) *uint64\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown tool":
				request.GoBinary = filepath.Join(request.Directory, "not-a-go-driver")
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			proof, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if proof != nil {
				proof.Close()
				t.Fatal("unsupported/incomplete source produced token")
			}
			if err == nil {
				t.Fatal("self-reported typed selection was accepted")
			}
		})
	}
}

func TestGoAMD64FrameSourceActualTargetAndFullSiblingInventory(t *testing.T) {
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			pkg, request := goAMD64FrameSourceFixture(t)
			request.Target = target
			data, err := os.ReadFile(filepath.Join(request.Directory, request.AssemblyFile))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(request.Directory, "sibling_amd64.s"), bytes.ReplaceAll(data, []byte("Value"), []byte("Other")), 0600); err != nil {
				t.Fatal(err)
			}
			declarations := []byte("package framefixture\nfunc Value(a uint64) uint64\nfunc Other(a uint64) uint64\n")
			if err := os.WriteFile(filepath.Join(request.Directory, "value.go"), declarations, 0600); err != nil {
				t.Fatal(err)
			}
			fset := token.NewFileSet()
			syntax, err := parser.ParseFile(fset, "value.go", declarations, 0)
			if err != nil {
				t.Fatal(err)
			}
			pkg.Types, err = (&types.Config{Sizes: types.SizesFor("gc", "amd64")}).Check(pkg.Path, fset, []*ast.File{syntax}, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if target == "windows/amd64" && errors.Is(err, ErrProbeNeedsContext) && strings.Contains(err.Error(), "SSEHUNWINDINFO") {
				if source != nil {
					t.Fatal("unsupported generated unwind role returned a token")
				}
				t.Logf("actual Windows auxiliary object role remains unbound: %v", err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			})
			if len(source.selection.SFiles) != 2 || len(source.functions) != 2 || source.env["GOOS"]+"/"+source.env["GOARCH"] != target {
				t.Fatalf("incomplete actual target/sibling observation: %+v", source.selection)
			}
		})
	}
}

func TestGoAMD64FrameSourceInputMutationPermanentlyRevokes(t *testing.T) {
	for _, kind := range []string{"Go", "ASM", "unused header", "include", "inventory", "object", "listing", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			pkg, request := goAMD64FrameSourceFixture(t)
			header := filepath.Join(request.Directory, "fixture.h")
			if err := os.WriteFile(header, []byte("#define FRAME 160\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "include" {
				assembly := filepath.Join(request.Directory, request.AssemblyFile)
				original, err := os.ReadFile(assembly)
				if err != nil {
					t.Fatal(err)
				}
				original = append([]byte("#include \"fixture.h\"\n"), bytes.Replace(original, []byte("$160-16"), []byte("$FRAME-16"), 1)...)
				if err := os.WriteFile(assembly, original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			source := requireGoAMD64FrameCapture(t, pkg, request)
			if kind == "include" && source.origins[filepath.Join(source.request.Directory, "fixture.h")] == 0 {
				t.Fatal("active original CPP header was not captured")
			}
			filename := filepath.Join(source.request.Directory, "value.go")
			switch kind {
			case "ASM":
				filename = filepath.Join(source.request.Directory, request.AssemblyFile)
			case "unused header", "include":
				filename = filepath.Join(source.request.Directory, "fixture.h")
			case "inventory":
				filename = filepath.Join(source.request.Directory, "new.h")
			case "object":
				filename = filepath.Join(source.owned, request.AssemblyFile+".o")
			case "listing":
				filename = filepath.Join(source.owned, request.AssemblyFile+".o.listing")
			}
			ctx := context.Background()
			if kind == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			} else if err := os.WriteFile(filename, []byte("changed\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) || source.ready {
				t.Fatalf("changed input retained observation: %v", err)
			}
			if !errors.Is(source.Verify(context.Background()), ErrProbeNeedsContext) {
				t.Fatal("revoked observation was reopened")
			}
		})
	}
}

func TestGoAMD64FrameSourceObjectListingMutations(t *testing.T) {
	pkg, request := goAMD64FrameSourceFixture(t)
	source := requireGoAMD64FrameCapture(t, pkg, request)
	listing, err := os.ReadFile(filepath.Join(source.owned, request.AssemblyFile+".o.listing"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(source.request.Directory, request.AssemblyFile))
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := source.preprocess(request.AssemblyFile, raw)
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, expanded)
	if err != nil {
		t.Fatal(err)
	}
	fn := source.functions[pkg.Path+".Value"]
	var pcs []int
	for pc := range fn.positions {
		if pc > 0 {
			pcs = append(pcs, pc)
		}
	}
	sort.Ints(pcs)
	for _, change := range []string{"source path", "source line", "interior PC", "partial bytes", "frame", "symbol", "duplicate", "relocation"} {
		t.Run(change, func(t *testing.T) {
			mutated := append([]byte(nil), listing...)
			switch change {
			case "source path":
				mutated = bytes.ReplaceAll(mutated, []byte(request.AssemblyFile), []byte("unbound.s"))
			case "source line":
				mutated = bytes.ReplaceAll(mutated, []byte(".s:2)"), []byte(".s:999999)"))
			case "interior PC":
				before := fmt.Sprintf("0x%04x %05d", pcs[0], pcs[0])
				after := fmt.Sprintf("0x%04x %05d", pcs[0]+1, pcs[0]+1)
				mutated = bytes.Replace(mutated, []byte(before), []byte(after), 1)
			case "partial bytes":
				mutated = mutated[:bytes.LastIndex(mutated, []byte("\n\t0x"))+1]
			case "frame":
				mutated = bytes.Replace(mutated, []byte("locals=0xa8"), []byte("locals=0xa0"), 1)
			case "symbol":
				mutated = bytes.ReplaceAll(mutated, []byte(fn.listingSymbol), []byte("forged.Value"))
			case "duplicate":
				mutated = append(mutated, listing...)
			case "relocation":
				mutated = append(mutated, []byte("rel 0+4 t=R_CALL forged\n")...)
			}
			if _, err := goAMD64FrameListing(mutated, file, pkg, source.origins); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("mutated %s listing accepted: %v", change, err)
			}
		})
	}
	for _, locals := range []string{"fffffffffffffff8", "80000000", "ffffffff", "10000000000000000"} {
		t.Run("foreign-locals-"+locals, func(t *testing.T) {
			if bytes.Count(listing, []byte("locals=0xa8")) != 1 {
				t.Fatal("actual positive-frame precondition changed")
			}
			mutated := bytes.Replace(listing, []byte("locals=0xa8"), []byte("locals=0x"+locals), 1)
			if _, err := goAMD64FrameListing(mutated, file, pkg, source.origins); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("negative, noncanonical or oversized metadata replaced the actual positive frame", locals, err)
			}
		})
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	object := filepath.Join(source.owned, request.AssemblyFile+".o")
	disassembly, err := source.run(ctx, "tool", "objdump", object)
	if err != nil {
		t.Fatal(err)
	}
	if err := goAMD64FrameObjectBytes(disassembly, source.functions); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"bytes", "symbol", "missing", "gap", "extra"} {
		t.Run("object "+change, func(t *testing.T) {
			mutated := append([]byte(nil), disassembly...)
			switch change {
			case "bytes":
				rows := strings.Split(string(mutated), "\n")
				fields := strings.Fields(rows[1])
				rows[1] = strings.Replace(rows[1], fields[2], "90", 1)
				mutated = []byte(strings.Join(rows, "\n"))
			case "symbol":
				mutated = bytes.ReplaceAll(mutated, []byte(fn.objectSymbol), []byte("forged.Value"))
			case "missing":
				mutated = mutated[:bytes.LastIndex(mutated, []byte("\n  "))+1]
			case "gap":
				rows := strings.Split(string(mutated), "\n")
				fields := strings.Fields(rows[2])
				rows[2] = strings.Replace(rows[2], fields[1], "0x0", 1)
				mutated = []byte(strings.Join(rows, "\n"))
			case "extra":
				mutated = append(mutated, disassembly...)
			}
			if err := goAMD64FrameObjectBytes(mutated, source.functions); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("mutated %s object accepted: %v", change, err)
			}
		})
	}
}

func TestGoAMD64FrameSourceConcurrentVerifyClose(t *testing.T) {
	pkg, request := goAMD64FrameSourceFixture(t)
	source := requireGoAMD64FrameCapture(t, pkg, request)
	owned := source.owned
	var workers sync.WaitGroup
	for i := 0; i < 3; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := source.Verify(context.Background()); err != nil && !errors.Is(err, ErrProbeNeedsContext) {
				t.Error(err)
			}
		}()
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Fatalf("factory-owned artifacts survived Close: %v", err)
	}
	if _, err := os.Stat(filepath.Join(request.Directory, request.AssemblyFile)); err != nil {
		t.Fatalf("Close removed original source: %v", err)
	}
}

func TestGoAMD64FrameSourceFailedSiblingCleansOnlyOwnedObjects(t *testing.T) {
	pkg, request := goAMD64FrameSourceFixture(t)
	temporary := t.TempDir()
	t.Setenv("TMPDIR", t.TempDir())
	request.Environment = append(request.Environment, "TMPDIR="+temporary, "GOTMPDIR="+temporary)
	// The first object succeeds. The later selected sibling cannot be bound
	// to any actual declaration; its failure must not leak the earlier object.
	sibling := filepath.Join(request.Directory, "z_sibling_amd64.s")
	if err := os.WriteFile(sibling, []byte("TEXT ·Other(SB),4,$160-0\nRET\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if source != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("partial complete-file observation accepted: %v", err)
	}
	entries, err := os.ReadDir(temporary)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "plan9asm-go-frame-object-") {
			t.Fatalf("partial capture leaked %s", entry.Name())
		}
	}
	if _, err := os.Stat(sibling); err != nil {
		t.Fatalf("cleanup removed an original selected source: %v", err)
	}
}

func TestGoAMD64FrameSourceRejectsIndirectedOriginalAndCacheFallback(t *testing.T) {
	for _, change := range []string{"source symlink", "package subtree", "implicit cache"} {
		t.Run(change, func(t *testing.T) {
			pkg, request := goAMD64FrameSourceFixture(t)
			switch change {
			case "source symlink":
				target := filepath.Join(t.TempDir(), "source.go")
				if err := os.WriteFile(target, []byte("package framefixture\nfunc Value(a uint64) uint64\n"), 0600); err != nil {
					t.Fatal(err)
				}
				original := filepath.Join(request.Directory, "value.go")
				if err := os.Remove(original); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, original); err != nil {
					t.Fatal(err)
				}
			case "package subtree":
				if err := os.Mkdir(filepath.Join(request.Directory, "nested"), 0700); err != nil {
					t.Fatal(err)
				}
			case "implicit cache":
				request.Environment = nil
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if source != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unsupported original source/cache origin captured: %v", err)
			}
		})
	}
}

func TestGoAMD64FrameSourceRejectsSelectedSystemObjects(t *testing.T) {
	pkg, request := goAMD64FrameSourceFixture(t)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	// A genuine Go object renamed .syso is still selected by the actual driver
	// and packed into its export. It must not be silently treated as an ASM/H
	// source role merely because the directory and file bytes were hashed.
	env := append(append([]string(nil), request.Environment...), "GOOS=linux", "GOARCH=amd64", "GOTOOLCHAIN=local")
	object := filepath.Join(request.Directory, "system_amd64.syso")
	include := filepath.Join(filepath.Dir(filepath.Dir(request.GoBinary)), "pkg", "include")
	if _, err := goasmcmd.Run(ctx, request.Directory, env, request.GoBinary, "tool", "asm", "-p", pkg.Path, "-I", include, "-o", object, request.AssemblyFile); err != nil {
		t.Fatal(err)
	}
	source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if source != nil {
		if closeErr := source.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		t.Fatal("actual selected .syso role was omitted from complete observation")
	}
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("unknown system-object transport did not retain Context: %v", err)
	}
}
