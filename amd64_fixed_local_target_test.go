package plan9asm

import (
	"errors"
	"testing"
)

func TestGoAMD64FixedLocalDarwinTripleClosure(t *testing.T) {
	pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	request.Target = "darwin/amd64"
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-apple-macosx"} {
		t.Run(triple, func(t *testing.T) {
			options.TargetTriple = triple
			bound, err := source.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatalf("actual Darwin frame rejected its exact LLVM target spelling: %v", err)
			}
			if bound.TargetTriple != triple {
				t.Fatal("binding rewrote the consumer's actual triple")
			}
			fixedLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "triple.ll", "triple.o", ir)
				compileLLVMToObject(t, llc, triple, "triple-opt.ll", "triple-opt.o", x86MulDivRoundOptimize(t, ir))
			})
			// Equivalent initial target spellings cannot mutate an already
			// bound consumer. Every certificate still pins its exact options.
			changed := bound
			changed.TargetTriple = "x86_64-apple-macosx"
			if changed.TargetTriple == triple {
				changed.TargetTriple = "x86_64-apple-darwin"
			}
			if _, err := Translate(file, changed); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("retargeted fixed-local certificate survived: %v", err)
			}
		})
	}
	for _, triple := range []string{
		"", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
		"arm64-apple-macosx", "i386-apple-macosx", "aarch64-apple-darwin",
		"x86_64-unknown-macosx", "x86_64-apple-ios", "x86_64-apple-macosx-junk",
		"x86_64-apple-darwin-junk", "x86_64-apple-macosx11.0.0", "x86_64-apple-darwin20.0.0",
		"prefix-x86_64-apple-macosx", "x86_64-apple-macosx ",
	} {
		t.Run("reject/"+triple, func(t *testing.T) {
			options.TargetTriple = triple
			if _, err := source.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("foreign or unregistered triple acquired a Darwin native frame: %q: %v", triple, err)
			}
		})
	}
}
