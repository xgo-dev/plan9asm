package plan9asm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fixedLocalCountingContext struct {
	context.Context
	deadlines  atomic.Int64
	onDeadline func(int64)
}

func (ctx *fixedLocalCountingContext) Deadline() (time.Time, bool) {
	samples := ctx.deadlines.Add(1)
	if ctx.onDeadline != nil {
		ctx.onDeadline(samples)
	}
	return ctx.Context.Deadline()
}

func TestGoAMD64FixedLocalSnapshotFinalCallbackMutationRevokes(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, api := range []string{"Translate", "Module", "GoModule"} {
		t.Run(api, func(t *testing.T) {
			pkg, request, file, options := fixedLocalSnapshotFixture(t, 4)
			source := requireGoAMD64FrameCapture(t, pkg, request)
			stage, cancel := runtimeOracleStageContext(t)
			defer cancel()
			ctx := &fixedLocalCountingContext{Context: stage}
			bound, err := source.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatal(err)
			}
			ctx.deadlines.Store(0)
			if err := bound.Sigs[pkg.Path+".Value0"].x86FixedLocal.verify(); err != nil {
				t.Fatal(err)
			}
			perRound := ctx.deadlines.Swap(0)
			if perRound == 0 {
				t.Fatal("live source verification omitted its caller lifetime")
			}
			mutated := false
			ctx.onDeadline = func(samples int64) {
				if samples == 2*perRound {
					// With a call-local snapshot this is the terminal callback in
					// module completion, after IR emission and the locked commands.
					path := filepath.Join(request.Directory, request.AssemblyFile)
					if err := os.WriteFile(path, []byte("changed original source\n"), 0600); err != nil {
						t.Fatal(err)
					}
					mutated = true
				}
			}
			fixedLocalAPI(t, pkg, file, bound, api, func(t *testing.T, ir string, err error) {
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatalf("late source mutation returned translated IR: %v", err)
				}
			})
			if !mutated || source.ready {
				t.Fatal("terminal callback was omitted or its mutated source remained live")
			}
		})
	}
}

func fixedLocalSnapshotFixture(t *testing.T, functions int) (GoPackage, GoAMD64FrameCaptureRequest, *File, Options) {
	t.Helper()
	var assembly, declarations strings.Builder
	for index := 0; index < functions; index++ {
		fmt.Fprintf(&declarations, "func Value%d(a uint64) uint64\n", index)
		fmt.Fprintf(&assembly, `TEXT ·Value%d(SB),4,$64-16
MOVQ a+0(FP),AX
MOVQ AX,0(SP)
ADDQ $1,0(SP)
MOVQ 0(SP),AX
MOVQ AX,ret+8(FP)
RET
`, index)
	}
	return fixedLocalTransportFixture(t, assembly.String(), declarations.String(),
		"linux/amd64", "x86_64-unknown-linux-gnu")
}

func TestGoAMD64FixedLocalSnapshotVerificationDoesNotScaleWithFunctions(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, api := range []string{"Translate", "Module", "GoModule"} {
		t.Run(api, func(t *testing.T) {
			for _, functions := range []int{1, 4} {
				t.Run(fmt.Sprint(functions), func(t *testing.T) {
					pkg, request, file, options := fixedLocalSnapshotFixture(t, functions)
					source := requireGoAMD64FrameCapture(t, pkg, request)
					stage, cancel := runtimeOracleStageContext(t)
					defer cancel()
					ctx := &fixedLocalCountingContext{Context: stage}
					bound, err := source.BindFixedLocal(ctx, pkg, file, options)
					if err != nil {
						t.Fatal(err)
					}
					// Calibrate one real verification round. Only this source owns
					// the original context; subprocesses use private standard ones.
					// These samples measure rounds, not elapsed time or tool bytes.
					ctx.deadlines.Store(0)
					binding := bound.Sigs[pkg.Path+".Value0"].x86FixedLocal
					if err := binding.verify(); err != nil {
						t.Fatal(err)
					}
					perRound := ctx.deadlines.Swap(0)
					if perRound == 0 {
						t.Fatal("live source verification did not sample its caller lifetime")
					}
					started := time.Now()
					fixedLocalAPI(t, pkg, file, bound, api, func(t *testing.T, ir string, err error) {
						if err != nil || ir == "" {
							t.Fatalf("complete fixed-local translation: %v", err)
						}
						for index := 0; index < functions; index++ {
							name := fmt.Sprintf("%s.Value%d", pkg.Path, index)
							if !strings.Contains(ir, llvmGlobal(name)) {
								t.Fatalf("translation omitted %s", name)
							}
						}
					})
					t.Logf("%d functions: API duration %s, %d caller lifetime samples (%d per live verification round)",
						functions, time.Since(started), ctx.deadlines.Load(), perRound)
					if samples := ctx.deadlines.Load(); samples != 2*perRound {
						t.Fatalf("%d functions sampled %d lifetimes, want two live module boundaries (%d samples per round)",
							functions, samples, perRound)
					}
				})
			}
		})
	}
}
