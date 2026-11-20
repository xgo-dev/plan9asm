//go:build go1.27

package plan9asm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func sdkCallPathEnvironment(environment []string, root string) []string {
	var result []string
	for _, value := range environment {
		if !strings.HasPrefix(value, "GOROOT=") {
			result = append(result, value)
		}
	}
	return append(result, "GOROOT="+root)
}

func sdkCallPathFixture(t *testing.T) (GoPackage, GoAMD64FrameCaptureRequest, *File, Options) {
	t.Helper()
	fixture := foreignABI0CallFixtures()[0]
	pkg, request, file, options := foreignABI0Fixture(t, fixture, foreignABI0CallAssembly(fixture))
	root, err := sourcepath.Resolve(filepath.Dir(filepath.Dir(request.GoBinary)))
	if err != nil {
		t.Fatal(err)
	}
	request.Environment = sdkCallPathEnvironment(request.Environment, root)
	return pkg, request, file, options
}

func requireSDKCallPathDeclaration(t *testing.T, declarations map[string]goAMD64FrameDeclaration, err error) {
	t.Helper()
	if err != nil {
		t.Fatal("actual SDK ABI0 declaration:", err)
	}
	sig := declarations["runtime.memmove"].signature
	if sig.Name != "runtime.memmove" || sig.Ret != Void || len(sig.Frame.Params) != 3 || len(sig.Frame.Results) != 0 {
		t.Fatalf("lost actual Go memmove signature: %#v", sig)
	}
	for index, typ := range []LLVMType{Ptr, Ptr, I64} {
		slot := sig.Frame.Params[index]
		if slot.Type != typ || slot.Offset != int64(8*index) || slot.Index != index || slot.Field != -1 {
			t.Fatalf("SDK ABI0 slot %d: %#v", index, slot)
		}
	}
}

func TestGoAMD64SDKCallDeclarationDirectorySpelling(t *testing.T) {
	pkg, request, _, _ := sdkCallPathFixture(t)
	foreignABI0OriginalLink(t, request)
	ctx, cancel := runtimeOracleProofContext(t)
	defer cancel()
	owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal("complete actual owned/SDK source baseline:", err)
	}
	defer owner.Close()
	if err := owner.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	entries := map[string]bool{"memmove": true}
	for _, mutation := range []string{"physical", "directory alias", "retarget", "wrong SDK", "non SDK", "unknown callee"} {
		t.Run(mutation, func(t *testing.T) {
			// A declaration query view is deliberately not an owner/capability.
			// It keeps actual compiler exports and Go bytes, without replacing
			// the live owner's sealed graph or authorizing a frame from the view.
			view := newGoOriginalInputGuard(owner.request)
			view.env = make(map[string]string)
			for key, value := range owner.env {
				view.env[key] = value
			}
			view.imports = make(map[string]goAMD64FrameSelection)
			for path, selected := range owner.imports {
				view.imports[path] = selected
			}
			selected := view.imports["runtime"]
			alias := ""
			if mutation == "directory alias" || mutation == "retarget" {
				alias = goAMD64FrameDriverDirectoryAlias(t, ctx, owner.env["GOROOT"])
				selected.Dir = filepath.Join(alias, "src", "runtime")
			}
			if mutation == "non SDK" {
				selected.Standard = false
			}
			view.imports["runtime"] = selected
			if mutation == "wrong SDK" {
				view.env["GOROOT"] = t.TempDir()
			}
			wanted := entries
			if mutation == "unknown callee" {
				wanted = map[string]bool{"notAnActualGoFunction": true}
			}
			declarations, err := view.ordinarySDKCallDeclarations("runtime", wanted)
			if mutation == "wrong SDK" || mutation == "non SDK" || mutation == "unknown callee" {
				if !errors.Is(err, ErrProbeNeedsContext) || len(declarations) != 0 {
					t.Fatal("unproved declaration/source role was accepted:", err)
				}
				return
			}
			requireSDKCallPathDeclaration(t, declarations, err)
			if err := view.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("declaration query created a live source capability:", err)
			}
			if mutation == "retarget" {
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
				goAMD64FrameDriverDirectoryLink(t, ctx, alias, t.TempDir())
				if declarations, err := view.ordinarySDKCallDeclarations("runtime", entries); !errors.Is(err, ErrProbeNeedsContext) || len(declarations) != 0 {
					t.Fatal("retargeted SDK directory supplied actual declarations:", err)
				}
			}
		})
	}
	if err := owner.Verify(ctx); err != nil {
		t.Fatal("query view changed the actual owner's sealed raw graph:", err)
	}
}

func TestGoAMD64FrameForeignABI0SDKParentAlias(t *testing.T) {
	pkg, request, file, options := sdkCallPathFixture(t)
	ctx, cancel := runtimeOracleProofContext(t)
	defer cancel()
	alias := goAMD64FrameDriverDirectoryAlias(t, ctx, filepath.Dir(filepath.Dir(request.GoBinary)))
	request.Environment = sdkCallPathEnvironment(request.Environment, alias)
	foreignABI0OriginalLink(t, request)
	owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal("original owned frame with the actual SDK command alias:", err)
	}
	defer owner.Close()
	requireSDKCallPathDeclaration(t, owner.callees, nil)
	bound, err := owner.BindFixedLocal(ctx, pkg, file, options)
	if err != nil || bound.Sigs[pkg.Path+".Value"].x86FixedLocal == nil {
		t.Fatal("actual closed SDK caller did not retain its fixed frame:", err)
	}
}
