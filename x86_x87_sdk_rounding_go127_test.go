//go:build go1.27

package plan9asm

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86X87Mode32CompleteSDKRoundingObjects(t *testing.T) {
	directory := filepath.Join(runtime.GOROOT(), "src", "math")
	source, err := os.ReadFile(filepath.Join(directory, "floor_386.s"))
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := os.ReadFile(filepath.Join(directory, "floor_asm.go"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("complete SDK rounding assembly sha256=%x declarations sha256=%x",
		sha256.Sum256(source), sha256.Sum256(declarations))
	pkg := mustGoPackage(t, "math", string(declarations))
	file, err := Parse(ArchAMD64, string(source))
	if err != nil || len(file.Funcs) != 3 {
		t.Fatal("complete SDK rounding source lost its three TEXTs", err)
	}
	names := []string{"archCeil", "archFloor", "archTrunc"}
	for index, function := range file.Funcs {
		if function.Sym != "·"+names[index] || function.FrameSize != 0 {
			t.Fatal("the original zero-frame SDK source changed", function.Sym, function.FrameSize)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete SDK rounding objects require LLVM22 llc")
	}
	for _, triple := range []string{
		"i386-unknown-linux-gnu", "i686-pc-windows-msvc", "i686-w64-windows-gnu",
	} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "386", triple, string(source))
			context := llvm.NewContext()
			defer context.Dispose()
			translated, err := translateGoModuleInContext(context, pkg, source, GoModuleOptions{
				GOARCH: "386", TargetTriple: triple, ResolveSym: testResolveSym("math"),
			})
			if translated != nil && !translated.Module.IsNil() {
				defer translated.Module.Dispose()
			}
			if err != nil || translated == nil || translated.Module.IsNil() {
				t.Fatal("complete actual SDK rounding source cannot translate", err)
			}
			for _, name := range names {
				function := translated.Module.NamedFunction("math." + name)
				if function.IsNil() || function.IsDeclaration() || function.BasicBlocksCount() == 0 {
					t.Fatal("complete SDK rounding module lost a definition", name)
				}
			}
			if err := llvm.VerifyModule(translated.Module, llvm.ReturnStatusAction); err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				x86PackedStringCompileObject(t, llc, triple, translated.Module.String(), level)
			}
		})
	}
}
