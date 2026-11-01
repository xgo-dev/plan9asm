//go:build go1.27

package plan9asm

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// This is an unpublished CPP-stage query of original SDK bytes. The owned
// empty go_asm.h is explicitly NOT a compiler artifact or a Go layout proof.
// Missing live context stops captureAssembly before it can run any Go tool.
// Complete real generated-header/object validation remains a separate gate.
func TestSDKX86RelativeIncludeActualRuntimeCPPQuery(t *testing.T) {
	root, err := sourcepath.Resolve(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	version, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		t.Fatal("actual SDK version is required", err)
	}
	header := filepath.Join(root, "src", "runtime", "cgo", "abi_amd64.h")
	headerBytes, err := os.ReadFile(header)
	if err != nil {
		t.Fatalf("this CPP owner requires the actual SDK header; version=%q: %v", version, err)
	}
	owned, err := sourcepath.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(owned, "go_asm.h"),
		[]byte("// CPP query placeholder; never compiler-generated layout evidence.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	request := GoX86SDKASMDataCaptureRequest{
		Directory:   filepath.Join(root, "src", "runtime"),
		PackagePath: "runtime", Target: "linux/amd64",
	}
	source := &GoX86SDKASMDataSource{
		request:     request,
		guard:       newGoOriginalInputGuard(GoAMD64FrameCaptureRequest{Directory: request.Directory}),
		directories: make(map[string]os.FileInfo), misses: make(map[string]bool),
	}
	source.identity, source.originalGuard = source, source.guard
	source.guard.env = map[string]string{
		"GOROOT": root, "GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1",
	}
	if err := source.verifySDKDirectory(); err != nil {
		t.Fatal("query must use the exact physical SDK package", err)
	}
	if err := source.snapshotSDKPrimaryDirectory(); err != nil {
		t.Fatal(err)
	}
	source.guard.owned = owned
	source.guard.ownedInfo, err = sourcepath.Lstat(owned)
	if err != nil {
		t.Fatal(err)
	}

	_, cpp, err := source.captureAssembly(context.Background(), 0, "sys_linux_amd64.s")
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("unpublished query must stop without a live execution context", err)
	}
	if len(source.observation.Positions) != 1 || cpp.Output == "" {
		t.Fatal("actual runtime relative include did not close the CPP stage", err)
	}
	wantDigest := sha256.Sum256(headerBytes)
	if got, exists := source.guard.inputs[header]; !exists || got != wantDigest {
		t.Fatal("actual relative header bytes were not retained as guarded inputs")
	}
	found := false
	for _, observed := range cpp.Sources {
		if observed.File == header {
			found = observed.Bytes == len(headerBytes) && observed.SHA256 == fmt.Sprintf("%x", wantDigest)
		}
	}
	if !found || source.directories[filepath.Dir(header)] == nil {
		t.Fatal("actual header source or its physical parent identity was omitted")
	}
	if source.ready || source.guard.ready || source.generation != 0 ||
		len(source.observation.Commands) != 0 || source.observation.Objects != nil {
		t.Fatal("partial CPP query acquired a source, command, object or frame certificate")
	}
}

// This exercises actual header macros under explicit target definitions; it
// does not authenticate SDK selection or claim that a Windows runtime file
// was compiled on the host. In this amd64 owner, -shared and the special
// runtime/386 -dynlink GOBUILDMODE_shared macro are distinct inputs.
func TestSDKX86RelativeIncludeHeaderTargetProfileQuery(t *testing.T) {
	root, err := sourcepath.Resolve(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	header := filepath.Join(root, "src", "runtime", "cgo", "abi_amd64.h")
	headerBytes, err := os.ReadFile(header)
	if err != nil {
		t.Fatal("actual SDK header is required for this version-bound owner", err)
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			const query = "#include \"cgo/abi_amd64.h\"\nTEXT ·Probe(SB),4,$0-0\nMOVQ $REGS_HOST_TO_ABI0_STACK,AX\nRET\n"
			cpp, _, err := observeSDKAssemblyCPP(query, AssemblyPreprocessOptions{
				FileName: "profile-query.s",
				Defines:  GoAssemblerDefinesWithEnv(goos, "amd64", map[string]string{"GOAMD64": "v1"}),
				ReadInclude: func(parent, name string) (string, []byte, error) {
					if parent != "profile-query.s" || name != "cgo/abi_amd64.h" {
						return "", nil, fmt.Errorf("unbound query include %q from %q", name, parent)
					}
					return header, headerBytes, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			file, err := Parse(ArchAMD64, cpp.Output)
			if err != nil || len(file.Funcs) != 1 {
				t.Fatal("actual target macro expression did not parse", err)
			}
			want := int64(6 * 8)
			if goos == "windows" {
				want = 28*8 + 8
			}
			moves := 0
			for _, ins := range file.Funcs[0].Instrs {
				if ins.Op == "MOVQ" {
					moves++
					if len(ins.Args) != 2 || ins.Args[0].Kind != OpImm || ins.Args[0].Imm != want {
						t.Fatal("actual target header selected the wrong saved-stack extent", ins)
					}
				}
			}
			if moves != 1 {
				t.Fatal("query lost its one observable macro result")
			}
			scratch := &GoX86SDKASMDataSource{request: GoX86SDKASMDataCaptureRequest{PackagePath: "runtime"},
				guard: newGoOriginalInputGuard(GoAMD64FrameCaptureRequest{})}
			scratch.guard.env = map[string]string{
				"GOROOT": root, "GOOS": goos, "GOARCH": "amd64", "GOAMD64": "v1",
			}
			args := scratch.asmArguments("owned-query")
			shared := false
			for _, arg := range args {
				shared = shared || arg == "-shared"
			}
			if shared != (goos == "darwin") || strings.Contains(strings.Join(args, " "), "GOBUILDMODE_shared") {
				t.Fatal("amd64 profile conflated target -shared with runtime/386 -dynlink", args)
			}
		})
	}
}

// An owned SDK-shaped tree permits physical mutation tests without changing
// the installed SDK. This is only an unpublished input query: no Go driver,
// generated header, commands, source certificate or ready state is supplied.
func sdkRelativeIncludeQuerySource(t *testing.T, fallback bool) (*GoX86SDKASMDataSource, string) {
	t.Helper()
	base, err := sourcepath.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "sdk")
	directory := filepath.Join(root, "src", "runtime")
	owned := filepath.Join(base, "owned")
	for _, name := range []string{filepath.Join(directory, "headers"), filepath.Join(root, "pkg", "include", "headers"), owned} {
		if err := os.MkdirAll(name, 0700); err != nil {
			t.Fatal(err)
		}
	}
	header := filepath.Join(directory, "headers", "value.h")
	contents := "#include \"second.h\"\n"
	if fallback {
		header = filepath.Join(root, "pkg", "include", "headers", "value.h")
		contents = "#define VALUE 41\n"
	}
	for name, data := range map[string]string{
		filepath.Join(directory, "source.s"):            "#include \"headers/value.h\"\nTEXT ·Probe(SB),4,$0-0\nMOVL $VALUE,AX\nRET\n",
		filepath.Join(directory, "second.h"):            "#define VALUE 41\n",
		filepath.Join(directory, "headers", "second.h"): "#define VALUE 99\n",
		header: contents,
	} {
		if err := os.WriteFile(name, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	request := GoX86SDKASMDataCaptureRequest{Directory: directory, PackagePath: "runtime", Target: "linux/amd64"}
	source := &GoX86SDKASMDataSource{request: request,
		guard:       newGoOriginalInputGuard(GoAMD64FrameCaptureRequest{Directory: directory}),
		directories: make(map[string]os.FileInfo), misses: make(map[string]bool)}
	source.identity, source.originalGuard = source, source.guard
	source.guard.env = map[string]string{"GOROOT": root, "GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1"}
	if err := source.snapshotSDKPrimaryDirectory(); err != nil {
		t.Fatal(err)
	}
	source.guard.owned = owned
	source.guard.ownedInfo, err = sourcepath.Lstat(owned)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	return source, header
}

func TestSDKX86RelativeIncludeQueryMutationAndLifetime(t *testing.T) {
	for _, change := range []string{"bytes", "same-byte-parent", "symlink", "nonregular", "oversize", "closed"} {
		t.Run(change, func(t *testing.T) {
			source, header := sdkRelativeIncludeQuerySource(t, false)
			_, original, err := source.readAssemblyInclude("source.s", "headers/value.h")
			if err != nil {
				t.Fatal("initial bounded input query", err)
			}
			for repeat := 0; repeat < 3; repeat++ {
				if _, _, err := source.readAssemblyInclude("unrelated-parent.h", "headers/value.h"); err != nil {
					t.Fatal("repeated selected header gained a new lookup origin", err)
				}
			}
			if len(source.guard.directoryInventory.View().Hashes) != 1 {
				t.Fatal("repeated include consumed duplicate source-budget entries")
			}
			switch change {
			case "bytes":
				err = os.WriteFile(header, []byte("#define VALUE 42\n"), 0600)
			case "same-byte-parent":
				parent := filepath.Dir(header)
				saved := filepath.Join(t.TempDir(), "original")
				err = os.Rename(parent, saved)
				if err == nil {
					err = os.Mkdir(parent, 0700)
				}
				if err == nil {
					// Keep both original file inodes and complete membership;
					// only the containing directory's identity changes.
					err = os.Link(filepath.Join(saved, "value.h"), header)
				}
				if err == nil {
					err = os.Link(filepath.Join(saved, "second.h"), filepath.Join(parent, "second.h"))
				}
			case "symlink":
				err = os.Remove(header)
				if err == nil {
					err = os.Symlink(filepath.Join(source.request.Directory, "second.h"), header)
				}
			case "nonregular":
				err = os.Remove(header)
				if err == nil {
					err = os.Mkdir(header, 0700)
				}
			case "oversize":
				err = os.Truncate(header, 16<<20+1)
			case "closed":
				err = source.Close()
			}
			if err != nil {
				t.Fatal("owned mutation setup", err)
			}
			if _, _, err := source.readAssemblyInclude("source.s", "headers/value.h"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed or closed include input query remained usable", change, err)
			}
			if change == "bytes" {
				// A failed factory capture closes its owned generation. Restoring
				// physical bytes must not reopen that aborted input lifetime.
				if err := source.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(header, original, 0600); err != nil {
					t.Fatal(err)
				}
				if _, _, err := source.readAssemblyInclude("source.s", "headers/value.h"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("restored bytes reopened an aborted include lifetime", err)
				}
			}
			if source.ready || source.guard.ready || len(source.observation.Commands) != 0 {
				t.Fatal("input query manufactured a compiler/source certificate")
			}
		})
	}
}

func TestSDKX86RelativeIncludeFixedOriginsAndMisses(t *testing.T) {
	t.Run("nested-fixed-CWD", func(t *testing.T) {
		source, _ := sdkRelativeIncludeQuerySource(t, false)
		raw, err := os.ReadFile(filepath.Join(source.request.Directory, "source.s"))
		if err != nil {
			t.Fatal(err)
		}
		cpp, _, err := observeSDKAssemblyCPP(string(raw), AssemblyPreprocessOptions{
			FileName: filepath.Join(source.request.Directory, "source.s"), ReadInclude: source.readAssemblyInclude,
		})
		if err != nil || !strings.Contains(cpp.Output, "$41") || strings.Contains(cpp.Output, "$99") {
			t.Fatal("nested header switched the actual fixed CWD lookup to its parent", err, cpp.Output)
		}
	})
	t.Run("preferred-miss-appears", func(t *testing.T) {
		source, header := sdkRelativeIncludeQuerySource(t, true)
		selected, _, err := source.readAssemblyInclude("source.s", "headers/value.h")
		if err != nil || selected != header || len(source.misses) != 2 {
			t.Fatal("fallback lost its two preferred fixed-origin absences", selected, err, len(source.misses))
		}
		preferred := filepath.Join(source.request.Directory, "headers", "value.h")
		if err := os.WriteFile(preferred, []byte("#define VALUE 99\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := source.readAssemblyInclude("source.s", "headers/value.h"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("new preferred candidate changed an already observed fallback", err)
		}
	})
	for _, header := range []string{"../second.h", "headers/../second.h", "headers//value.h", "headers\\value.h"} {
		t.Run(header, func(t *testing.T) {
			source, _ := sdkRelativeIncludeQuerySource(t, false)
			if _, _, err := source.readAssemblyInclude("source.s", header); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("noncanonical/escaping include acquired a selected SDK route", err)
			}
		})
	}
	t.Run("absolute", func(t *testing.T) {
		source, header := sdkRelativeIncludeQuerySource(t, false)
		if _, _, err := source.readAssemblyInclude("source.s", header); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("absolute header borrowed a selected SDK relative route", err)
		}
	})
	t.Run("unverified-package", func(t *testing.T) {
		source, _ := sdkRelativeIncludeQuerySource(t, false)
		source.request.PackagePath = "other"
		if _, _, err := source.readAssemblyInclude("source.s", "headers/value.h"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("a child directory identity replaced the exact SDK package route", err)
		}
	})
}
