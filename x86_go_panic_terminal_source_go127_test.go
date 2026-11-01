//go:build go1.27

package plan9asm

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Pure file reads only: this root executes no Go, LLVM, object or SDK command.
func TestX86GoPanicTerminalActualSelected386CompilerSchema(t *testing.T) {
	env := map[string]string{"GOVERSION": "go1.27.2", "GOOS": "linux", "GOARCH": "386", "GO386": "sse2"}
	read := func(role string) ([]byte, error) {
		return os.ReadFile(filepath.Join(runtime.GOROOT(), filepath.FromSlash(role)))
	}
	if err := x86GoPanicTerminalCompilerSources(env, read); err != nil {
		t.Fatal("actual selected SDK compiler/linker source schema differs", err)
	}
	for role := range x86GoPanicTerminalCompilerSourceRoles() {
		t.Run(role, func(t *testing.T) {
			if err := x86GoPanicTerminalCompilerSources(env, func(name string) ([]byte, error) {
				data, err := read(name)
				if name == role && err == nil {
					data[0] ^= 1
				}
				return data, err
			}); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed actual producer bytes retained their registered source role", err)
			}
		})
	}
}

// Close only at the final verification, after the private association has been
// computed. An in-flight query owns one lease; its nested Verify owns another.
type x86PanicTerminalPublicationContext struct {
	context.Context
	source *GoX86SDKASMDataSource
	closed bool
}

func (ctx *x86PanicTerminalPublicationContext) Err() error {
	ctx.source.mu.Lock()
	final := ctx.source.active >= 2
	ctx.source.mu.Unlock()
	if final && !ctx.closed {
		ctx.closed = true
		if err := ctx.source.Close(); err != nil {
			return err
		}
	}
	return ctx.Context.Err()
}

func TestX86GoPanicTerminalOriginal386CompilerAndCALLAssociations(t *testing.T) {
	for _, name := range []string{"complete-42-TEXT", "owned-source-artifact-revocation", "close-at-final-publication"} {
		t.Run(name, func(t *testing.T) {
			ctx, request := sdkASMDataRequest(t, "386", "internal/runtime/atomic")
			source, err := captureGoX86SDKASMDataSourceRole(ctx, request, sdkASMDataOriginalSourceRole)
			if err != nil {
				t.Fatal("complete actual original386 source/compiler/ASM observation", err)
			}
			defer source.Close()
			sdkASMDataDiagnosticRetainNamed(t, "-complete-original", source)
			if len(source.observation.CPP) != 1 || len(source.observation.Objects.Sources) != 1 ||
				strings.Count(string(source.observation.ObjectInputs.Sources[0].Original), "\nTEXT ") != 42 ||
				len(source.observation.Objects.Sources[0].Original.Texts) != 42 {
				t.Fatal("actual discovering source was truncated or had a different complete selection")
			}
			verification := ctx
			var publication *x86PanicTerminalPublicationContext
			if name == "close-at-final-publication" {
				publication = &x86PanicTerminalPublicationContext{Context: ctx, source: source}
				verification = publication
			}
			if name == "owned-source-artifact-revocation" {
				file := filepath.Join(source.guard.owned, "go_asm.h")
				original, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, append(append([]byte(nil), original...), []byte("\n// changed source artifact\n")...), 0600); err != nil {
					t.Fatal(err)
				}
				observed, err := source.panicTerminalObservation(verification, &x86ResultFlowBudget{})
				if observed != nil || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("changed compiler/source artifact retained an association", observed, err)
				}
				if err := os.WriteFile(file, original, 0600); err != nil {
					t.Fatal(err)
				}
				if observed, err := source.panicTerminalObservation(ctx, &x86ResultFlowBudget{}); observed != nil || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("restoring source artifact bytes revived a revoked association", err)
				}
				return
			}
			observed, err := source.panicTerminalObservation(verification, &x86ResultFlowBudget{})
			if publication != nil {
				if !publication.closed || observed != nil || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("Close during final callback published a partial original-source association", observed, err)
				}
				return
			}
			if err != nil || observed == nil || len(observed.bodies) != 1 || len(observed.calls) != 5 ||
				observed.bodies[0].declaration.name != "panicUnaligned" || observed.bodies[0].text.ABI != 1 || observed.bodies[0].assemblyABI != 0 {
				t.Fatal("actual complete42TEXT/SymABI/compiler/ABI0 CALL association differs", observed, err)
			}
			wanted := map[string]bool{"·Cas64": true, "·Xadd64": true, "·Xchg64": true, "·Load64": true, "·Store64": true}
			for _, call := range observed.calls {
				if !wanted[call.function] || call.target != "internal/runtime/atomic.panicUnaligned" {
					t.Fatal("original actual CALL inventory lost its source owner/target", call)
				}
				delete(wanted, call.function)
			}
			if len(wanted) != 0 || source.guard.ready || len(source.observation.Frames) != 0 {
				t.Fatal("association omitted an original CALL or acquired native frame authority", wanted)
			}
			t.Logf("complete original compiler/archive=%s, header=%x,42TEXT/5CALL, compilerABI1/sourceABI0; no capability/CFG/LLVM/runtime qualification",
				source.observation.Objects.ArchiveSHA256, sha256.Sum256(source.observation.Header.CompilerObject))
		})
	}
}
