package plan9asm

import (
	"runtime"
	"testing"
)

func TestX86PrivatePointerStackOriginalGThreeTargetObjects(t *testing.T) {
	source, _ := x86PrivatePointerStackOriginalGFixture(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, "func galias(input *byte) uint64", "amd64", triple, api)
					if ir == "" || err != nil {
						t.Fatal("unchanged initialized g program lost its private pointer cell", err)
					}
					for _, pipeline := range []struct{ name, text, level string }{
						{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"},
						{"IR_O2_backend_O2", x86DwordProductIROptimize(t, ir), "-O2"},
					} {
						t.Run(pipeline.name, func(t *testing.T) {
							x86CompactExpandRequireAllDefinitions(t, pipeline.text, []string{"galias"})
							x86PackedStringCompileObject(t, llc, triple, pipeline.text, pipeline.level)
						})
					}
				})
			}
		})
	}
}

// The original ASM has an explicit incoming pointer and its original C only
// observes integer memory. Actual-host LLVM execution is a portable numerical
// companion, not original-Go execution or an assertion about native runtime g.
func TestX86PrivatePointerStackOriginalGPortableLLVMCompanion(t *testing.T) {
	source, mainC := x86PrivatePointerStackOriginalGFixture(t)
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, "func galias(input *byte) uint64", "amd64", triple, api)
			if ir == "" || err != nil {
				t.Fatal("unchanged original explicit-pointer g program rejected", err)
			}
			for _, pipeline := range []struct {
				name, text string
				level      int
			}{
				{"backend_O0", ir, 0}, {"backend_O2", ir, 2},
				{"IR_O2_backend_O2", x86DwordProductIROptimize(t, ir), 2},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "private-pointer-g",
						triple, pipeline.text, mainC, nil, pipeline.level)
				})
			}
		})
	}
	t.Log("unchanged original logical ASM/C executed on actual host; not original Go/native-g ABI qualification")
}
