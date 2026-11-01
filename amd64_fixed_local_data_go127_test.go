//go:build go1.27

package plan9asm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixedLocalLiteralData = "DATA literal<>+0(SB)/8,$0x0102030405060708\n" +
	"DATA literal<>+8(SB)/8,$0x1112131415161718\nGLOBL literal<>(SB),8,$32\n"

func fixedLocalDataFixture(t *testing.T, operation, data string) (GoPackage, GoAMD64FrameCaptureRequest, *File, Options, string) {
	t.Helper()
	pkg, request, _, options := fixedLocalFrameFixture(t, operation)
	name := filepath.Join(request.Directory, request.AssemblyFile)
	original, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	assembly := data + string(original)
	if err := os.WriteFile(name, []byte(assembly), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	return pkg, request, file, options, assembly
}

func fixedLocalDataCLIOptions(options Options) Options {
	resolve := options.ResolveSym
	options.ResolveSym = func(symbol string) string {
		name := resolve(symbol)
		if strings.HasSuffix(symbol, "<>") {
			return strings.TrimSuffix(name, "<>") + "$local"
		}
		return name
	}
	return options
}

func TestGoAMD64FixedLocalReadonlyDataThreeTargetObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			for _, spelling := range []string{"source", "CLI"} {
				t.Run(spelling, func(t *testing.T) {
					pkg, request, _, options, assembly := fixedLocalDataFixture(t,
						"MOVOU literal<>(SB),X0\nPADDQ 16(SP),X0", fixedLocalLiteralData)
					request.Target, options.TargetTriple = target.name, target.triple
					if spelling == "CLI" {
						options = fixedLocalDataCLIOptions(options)
					}
					x86LEAActualTargetGoObject(t, "amd64", target.triple, assembly)
					fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
						if err != nil || !strings.Contains(ir, "internal constant [32 x i8]") || !strings.Contains(ir, "fixed_local_native") {
							t.Fatal("missing joined private DATA/frame translation", err)
						}
						compileLLVMToObject(t, llc, target.triple, "data-frame.ll", "data-frame.o", ir)
						compileLLVMToObject(t, llc, target.triple, "data-frame-opt.ll", "data-frame-opt.o", x86MulDivRoundOptimize(t, ir))
					})
				})
			}
		})
	}
}

func fixedLocalDataAPIs(t *testing.T, pkg GoPackage, file *File, assembly string, options Options, check func(*testing.T, string, error)) {
	t.Helper()
	// Negative/mutation callers deliberately keep their supplied binding. Never
	// renew an expired or revoked observation while testing its rejection.
	for _, api := range []string{"Translate", "Module", "GoModule"} {
		t.Run(api, func(t *testing.T) {
			fixedLocalAPI(t, pkg, file, options, api, check, assembly)
		})
	}
}
