package plan9asm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

// Complete package inputs remain live observations even when only one assembly
// member is requested for a frame binding. These ordinary Go formats work on
// both supported endpoint SDKs; no current-only object decoder is called here.
func TestGoAMD64FrameRequestedMemberRetainsSiblingInventory(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		for _, change := range []string{"ASM", "CPP"} {
			t.Run(target+"/"+change, func(t *testing.T) {
				const declarations = "func Value(a uint64) uint64\nfunc Unused(dst,src *byte,n uintptr)\nfunc External(dst,src *byte,n uintptr)\n"
				const value = "TEXT ·Value(SB),4,$24-16\nMOVQ a+0(FP),AX\nMOVQ AX,0(SP)\nMOVQ 0(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n"
				const unused = "#include \"textflag.h\"\n#include \"sibling.h\"\nTEXT ·Unused(SB),NOSPLIT,$24-24\nMOVQ dst+0(FP),AX\nMOVQ AX,0(SP)\nMOVQ src+8(FP),AX\nMOVQ AX,8(SP)\nMOVQ n+16(FP),AX\nMOVQ AX,16(SP)\nADDQ $EXTRA,AX\nCALL ·External(SB)\nRET\n"
				pkg, request := goAMD64FrameTypedFixture(t, declarations, value)
				request.Target = target
				sibling := filepath.Join(request.Directory, "a_unused_amd64.s")
				header := filepath.Join(request.Directory, "sibling.h")
				if err := os.WriteFile(sibling, []byte(unused), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(header, []byte("#define EXTRA 0\n"), 0600); err != nil {
					t.Fatal(err)
				}
				callRequest := request
				callRequest.AssemblyFile = filepath.Base(sibling)
				ctx, cancel := runtimeOracleStageContext(t)
				defer cancel()
				env := append(append([]string(nil), request.Environment...),
					"GOOS="+strings.Split(target, "/")[0], "GOARCH=amd64", "CGO_ENABLED=0",
					"GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=")
				for _, member := range []string{request.AssemblyFile, callRequest.AssemblyFile} {
					object := filepath.Join(t.TempDir(), member+".o")
					listing, err := goasmcmd.Run(ctx, request.Directory, env, request.GoBinary,
						"tool", "asm", "-S", "-p", pkg.Path,
						"-I", filepath.Join(filepath.Dir(filepath.Dir(request.GoBinary)), "pkg", "include"),
						"-o", object, member)
					if err != nil {
						t.Fatalf("independent original member %s: %v\n%s", member, err, listing)
					}
					if info, err := os.Stat(object); err != nil || info.Size() == 0 {
						t.Fatal("original member lacks its complete Go object", member, err)
					}
				}
				owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
				if err != nil {
					t.Fatal("unrequested valid assembly sibling acquired a frame-proof obligation", err)
				}
				defer func() {
					if err := owner.Close(); err != nil {
						t.Error(err)
					}
				}()
				if len(owner.selection.SFiles) != 2 || len(owner.functions) != 1 ||
					owner.functions[pkg.Path+".Value"].sourceSymbol != "·Value" {
					t.Fatal("frame observation lost the complete selection or exact requested member")
				}
				toolHeader := filepath.Join(owner.env["GOROOT"], "pkg", "include", "textflag.h")
				for _, name := range []string{sibling, header, toolHeader} {
					if _, found := owner.inputs[name]; !found {
						t.Fatal("unrequested sibling input escaped live source verification", name)
					}
				}
				if owner.origins[toolHeader] == 0 || owner.origins[header] == 0 {
					t.Fatal("sibling-only CPP dependencies lost their actual source association")
				}
				if err := owner.Verify(ctx); err != nil {
					t.Fatal(err)
				}
				callOwner, err := CaptureGoAMD64FrameSource(ctx, pkg, callRequest)
				if callOwner != nil {
					if closeErr := callOwner.Close(); closeErr != nil {
						t.Error(closeErr)
					}
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("a requested ordinary CALL acquired a callee/frame contract", err)
				}
				expanded, err := owner.preprocess(callRequest.AssemblyFile, []byte(unused))
				if err != nil {
					t.Fatal(err)
				}
				file, err := Parse(ArchAMD64, expanded)
				if err != nil {
					t.Fatal(err)
				}
				triple := map[string]string{"linux/amd64": "x86_64-unknown-linux-gnu", "darwin/amd64": "x86_64-apple-darwin", "windows/amd64": "x86_64-pc-windows-msvc"}[target]
				name := pkg.Path + ".Unused"
				_, err = owner.BindFixedLocal(ctx, pkg, file, Options{Goarch: "amd64", TargetTriple: triple,
					Sigs:       map[string]FuncSig{name: owner.declarations[name].signature},
					ResolveSym: func(symbol string) string { return pkg.Path + "." + strings.TrimPrefix(symbol, "·") }})
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("requested member owner authorized a different sibling's source", err)
				}
				if err := owner.Verify(ctx); err != nil {
					t.Fatal("negative sibling binding invalidated the positive mutation control", err)
				}
				changed, data := sibling, unused+"\n"
				if change == "CPP" {
					changed, data = header, "#define EXTRA 1\n"
				}
				if err := os.WriteFile(changed, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				if err := owner.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("unrequested selected sibling mutation retained source ownership", err)
				}
			})
		}
	}
}
