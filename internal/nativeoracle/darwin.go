// Package nativeoracle configures test-only native C drivers. Its SDK selection
// supplies no translator source, frame, ABI or numerical-state permission.
package nativeoracle

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

// DarwinClangFlags uses the actual developer selection, not SDKROOT or a guessed
// SDK version. LLVM's default configuration may override both environment and
// ordinary compiler flags, so disable it explicitly before selecting the SDK.
// The caller retains its independent LLVM 22 version and command ownership checks.
func DarwinClangFlags(ctx context.Context, environment []string) ([]string, error) {
	if ctx == nil {
		return nil, fmt.Errorf("native macOS SDK query requires a bounded context")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, fmt.Errorf("native macOS SDK query requires a bounded context")
	}
	observed, err := goasmcmd.Observe(ctx, "", environment, "/usr/bin/xcrun",
		"--sdk", "macosx", "--show-sdk-path")
	if err != nil {
		return nil, fmt.Errorf("required actual macOS SDK query: %w; stdout=%q stderr=%q",
			err, observed.Stdout, observed.Stderr)
	}
	if len(observed.Stderr) != 0 {
		return nil, fmt.Errorf("required actual macOS SDK query emitted diagnostics: stdout=%q stderr=%q",
			observed.Stdout, observed.Stderr)
	}
	return darwinClangFlagsFromSDKOutput(observed.Stdout)
}

func darwinClangFlagsFromSDKOutput(output []byte) ([]string, error) {
	text := string(output)
	if !strings.HasSuffix(text, "\n") {
		return nil, fmt.Errorf("actual macOS SDK query did not return one complete absolute path")
	}
	requested := strings.TrimSuffix(text, "\n")
	if !filepath.IsAbs(requested) || strings.ContainsAny(requested, "\r\n\x00") {
		return nil, fmt.Errorf("actual macOS SDK query did not return one complete absolute path")
	}
	root, err := filepath.EvalSymlinks(requested)
	if err != nil {
		return nil, fmt.Errorf("resolve actual macOS SDK directory: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("actual macOS SDK path is not a directory: %q: %v", root, err)
	}
	return []string{"--no-default-config", "-isysroot", root}, nil
}
