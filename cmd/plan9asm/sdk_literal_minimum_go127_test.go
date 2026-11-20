//go:build go1.27

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestSimpleCLIOriginalSDKMapsLiteralMinimumSource(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			setSimpleSDKProfile(t) // Retain the actual default CGO profile, not a diagnostic CGO0 override.
			input := filepath.Join(runtime.GOROOT(), "src", "internal", "runtime", "maps", "memhash_amd64.s")
			original, err := os.ReadFile(input)
			if err != nil {
				t.Fatal(err)
			}
			folder := t.TempDir()
			output, meta := filepath.Join(folder, "maps.ll"), filepath.Join(folder, "maps.json")
			if err := runTranspile([]string{"-goos=" + goos, "-goarch=amd64", "-i=" + input, "-o=" + output, "-meta=" + meta}); err != nil {
				t.Fatal("complete original SDK minimum-demand publication", err)
			}
			ir, err := os.ReadFile(output)
			if err != nil || strings.Count(string(ir), "define ") != 2 || !strings.Contains(string(ir), "external global [128 x i8]") ||
				!strings.Contains(string(ir), "internal/runtime/maps.checkMasksAndShiftsAlignment") || strings.Count(string(ir), "internal constant [256 x i8]") != 2 {
				t.Fatal("complete original functions/private DATA/mutable AES source lost", err)
			}
			raw, err := os.ReadFile(meta)
			var metadata struct{ Functions []functionInfo }
			if err != nil || json.Unmarshal(raw, &metadata) != nil || len(metadata.Functions) != 2 {
				t.Fatal("whole-file metadata differs", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			for _, optimization := range []string{"0", "2"} {
				object := filepath.Join(folder, "maps-O"+optimization+".o")
				stdout, stderr, err := gotoolprofile.RunBounded(ctx, folder, os.Environ(), sdkLLVM22LLC(t, ctx), "-O="+optimization, "-filetype=obj", "-o", object, output)
				if err != nil || len(stderr) != 0 {
					t.Fatalf("whole SDK LLVM22 O%s object: %v\n%s%s", optimization, err, stdout, stderr)
				}
				if info, err := os.Stat(object); err != nil || info.Size() == 0 {
					t.Fatal("whole SDK object absent", err)
				}
			}
			after, err := os.ReadFile(input)
			if err != nil || sha256.Sum256(after) != sha256.Sum256(original) {
				t.Fatal("original SDK source changed", err)
			}
			t.Logf("complete SDK source SHA256=%x; 2 TEXT/all DATA public CLI + LLVM22 O0/O2 only, not physical SDK entry/execution", sha256.Sum256(original))
		})
	}
}
