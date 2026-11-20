//go:build go1.27

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestCompileOneCurrentGoARM64PrivateP256Source(t *testing.T) {
	path := filepath.Join(runtime.GOROOT(), "src", "crypto", "internal", "fips140", "nistec", "p256_asm_arm64.s")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	whole := string(data)
	first := strings.Index(whole, "TEXT ")
	if first < 0 {
		t.Fatal("original Go source has no TEXT")
	}
	extract := func(header string) string {
		start := strings.Index(whole, header)
		if start < 0 {
			t.Fatalf("original Go source has no %q", header)
		}
		body := whole[start:]
		if end := strings.Index(body[1:], "\nTEXT "); end >= 0 {
			body = body[:end+1]
		}
		return body
	}
	source := whole[:first] + extract("TEXT ·p256Sqr(SB)") + "\n" + extract("TEXT p256SqrInternal<>(SB)")
	requireARM64PrivateCLIOriginalObject(t, source)
	pkg, input := arm64PrivateCLIPackage(t,
		"package p\nfunc p256Sqr(*[4]uint64,*[4]uint64,int)\n", source)
	for _, target := range []struct{ os, triple string }{
		{"darwin", "aarch64-apple-darwin"},
		{"linux", "aarch64-unknown-linux-gnu"},
		{"linux", "aarch64-unknown-linux-musl"},
		{"freebsd", "aarch64-unknown-freebsd"},
		{"windows", "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			config, err := resolveCompileConfig(true, "", true, 2)
			if err != nil {
				t.Fatal(err)
			}
			config.Context = arm64PrivateCLIContext(t)
			output := filepath.Join(t.TempDir(), "original-p256.ll")
			if err := compileOne(pkg, plan9asm.ArchARM64, target.os, "arm64", target.triple,
				asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
				t.Fatal(err)
			}
			ir, err := os.ReadFile(output)
			if err != nil || strings.Count(string(ir), "define ") != 1 {
				t.Fatalf("original source continuation did not stay with p256Sqr: %v", err)
			}
			object := strings.TrimSuffix(output, ".ll") + ".o"
			if info, err := os.Stat(object); err != nil || info.Size() == 0 {
				t.Fatalf("original p256Sqr did not produce a real LLVM22 object: %v", err)
			}
		})
	}
}
