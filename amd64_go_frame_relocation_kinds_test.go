package plan9asm

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

func frameRelocationOriginal(t *testing.T, pkg GoPackage, request GoAMD64FrameCaptureRequest) []byte {
	t.Helper()
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	env := append(append([]string(nil), request.Environment...),
		"GOOS="+strings.Split(request.Target, "/")[0], "GOARCH=amd64", "CGO_ENABLED=0",
		"GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=")
	object := filepath.Join(t.TempDir(), "original.o")
	listing, err := goasmcmd.Run(ctx, request.Directory, env, request.GoBinary,
		"tool", "asm", "-S", "-p", pkg.Path, "-o", object, request.AssemblyFile)
	if err != nil {
		t.Fatalf("original Go assembly failed: %v\n%s", err, listing)
	}
	info, err := os.Stat(object)
	if err != nil || info.Size() == 0 {
		t.Fatal("successful original assembler did not produce a complete object", err)
	}
	t.Logf("original Go %s %s listing:\n%s", runtime.Version(), request.Target, listing)
	return listing
}

func TestGoAMD64FrameOrdinaryCallDoesNotMintPermission(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			const assembly = "TEXT ·Caller(SB),4,$24-24\nMOVQ dst+0(FP),AX\nMOVQ AX,0(SP)\n" +
				"MOVQ src+8(FP),AX\nMOVQ AX,8(SP)\nMOVQ n+16(FP),AX\nMOVQ AX,16(SP)\nCALL ·External(SB)\nRET\n"
			pkg, request := goAMD64FrameTypedFixture(t, "func Caller(dst,src *byte,n uintptr)\nfunc External(dst,src *byte,n uintptr)\n", assembly)
			request.Target = target
			listing := frameRelocationOriginal(t, pkg, request)
			call := "t=R_CALL " + pkg.Path + ".External+0"
			if !gotoolchain.AuditedGo127(runtime.Version()) {
				call = "t=7 \"\".External+0"
			}
			if !strings.Contains(string(listing), call) {
				t.Fatal("original ordinary direct CALL relocation was not observed", string(listing))
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if owner != nil {
				if closeErr := owner.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("an ordinary relocation acquired a private-call or callee frame contract", err)
			}
		})
	}
}
