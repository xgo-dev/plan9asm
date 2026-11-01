//go:build go1.23

package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

func TestGoAMD64WindowsUnwindActualSourceFamily(t *testing.T) {
	goAMD64WindowsUnwindActualSourceFamily(t)
}

// A temporary-directory alias is an ordinary host configuration, not permission
// to relax the original object reader's canonical physical-path contract.
func TestGoAMD64WindowsUnwindTemporaryParentAlias(t *testing.T) {
	goAMD64WindowsUnwindTemporaryParentAlias(t)
	goAMD64WindowsUnwindActualSourceFamily(t)
}

func goAMD64WindowsUnwindTemporaryParentAlias(t *testing.T) {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	physical := filepath.Join(parent, "physical")
	alias := filepath.Join(parent, "alias")
	if err := os.Mkdir(physical, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(physical, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", alias)
	t.Setenv("GOTMPDIR", alias)
}

func goAMD64WindowsUnwindActualSourceFamily(t *testing.T) {
	t.Helper()
	for _, role := range []string{"numeric", "void", "shared numeric and void"} {
		t.Run(role, func(t *testing.T) {
			declaration := "func Value(a uint64) uint64"
			assembly := "TEXT ·Value(SB),4,$160-16\nMOVQ a+0(FP),AX\nMOVQ AX,16(SP)\nMOVQ 16(SP),AX\nMOVQ AX,ret+8(FP)\nRET\n"
			if role == "void" {
				declaration = "func Value(a uint64)"
				assembly = "TEXT ·Value(SB),4,$160-8\nMOVQ a+0(FP),AX\nMOVQ AX,16(SP)\nRET\n"
			} else if role == "shared numeric and void" {
				declaration += "\nfunc Other(a uint64)"
				assembly += "TEXT ·Other(SB),4,$160-8\nMOVQ a+0(FP),AX\nMOVQ AX,16(SP)\nRET\n"
			}
			pkg, request := goAMD64FrameTypedFixture(t, declaration, assembly)
			request.Target = "windows/amd64"
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			var environment []string
			for _, value := range request.Environment {
				key, _, _ := strings.Cut(value, "=")
				if key != "GOOS" && key != "GOARCH" && key != "CGO_ENABLED" {
					environment = append(environment, value)
				}
			}
			environment = append(environment, "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
			request.Environment = environment
			objectDirectory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal("cannot resolve original Windows output directory", err)
			}
			object := filepath.Join(objectDirectory, "original-windows.o")
			listing, err := goasmcmd.Run(ctx, request.Directory, environment, request.GoBinary,
				"tool", "asm", "-S", "-p", pkg.Path, "-o", object, request.AssemblyFile)
			if err != nil {
				t.Fatal("actual original Windows assembler control failed", err)
			}
			info, err := os.Stat(object)
			if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
				t.Fatal("actual original Windows object was not produced", err)
			}
			original, err := os.ReadFile(object)
			if err != nil || int64(len(original)) != info.Size() ||
				!bytes.Contains(listing, []byte("SSEHUNWINDINFO")) ||
				!bytes.Contains(original, []byte("go:sehuw.12.")) {
				t.Fatal("independent original Windows object precondition failed", err)
			}
			t.Logf("ACTUAL_WINDOWS_ORIGINAL_OUTPUT_EXISTS bytes=%d sha256=%x hex=%x\nACTUAL_WINDOWS_ORIGINAL_LISTING\n%s",
				len(original), sha256.Sum256(original), original, listing)
			data, err := goAMD64FrameRead(object)
			if err != nil || !bytes.Equal(data, original) || !bytes.Contains(listing, []byte("SSEHUNWINDINFO")) ||
				!bytes.Contains(data, []byte("go:sehuw.12.")) {
				t.Fatal("actual original Windows object/listing lacks its unwind metadata", err)
			}
			t.Logf("ACTUAL_WINDOWS_ORIGINAL_OBJECT bytes=%d sha256=%x hex=%x\nACTUAL_WINDOWS_ORIGINAL_LISTING\n%s",
				len(data), sha256.Sum256(data), data, listing)
			if !t.Run("PlainParserRefusesUnboundMetadata", func(t *testing.T) {
				file, err := Parse(ArchAMD64, assembly)
				if err != nil {
					t.Fatal(err)
				}
				origins := map[string]int{request.AssemblyFile: strings.Count(assembly, "\n") + 1}
				if _, err := goAMD64FrameListing(listing, file, pkg, origins); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("plain listing parser borrowed Windows binary metadata authority", err)
				}
			}) {
				return
			}
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if err != nil {
				t.Fatal("actual ordinary Windows numeric/void source requires its complete SEH join", err)
			}
			t.Cleanup(func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			})
			want := 1
			if role == "shared numeric and void" {
				want = 2
			}
			if len(source.functions) != want || source.Verify(ctx) != nil {
				t.Fatal("complete Windows numeric/void original source did not verify")
			}
			copied := new(GoAMD64FrameSource)
			reflect.ValueOf(copied).Elem().Set(reflect.ValueOf(source).Elem())
			if !errors.Is(copied.Verify(ctx), ErrProbeNeedsContext) ||
				!errors.Is(copied.Close(), ErrProbeNeedsContext) || source.Verify(ctx) != nil {
				t.Fatal("Windows metadata route bypassed exact source owner identity")
			}
			if _, err := os.Stat(request.Directory); err != nil {
				t.Fatal("source owner identity control changed the original tree", err)
			}
		})
	}
}
