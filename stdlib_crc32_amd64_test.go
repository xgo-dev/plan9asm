//go:build !llgo
// +build !llgo

package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStdlibHashCRC32_AMD64_Compile(t *testing.T) {
	clang := requireLLVM22Tool(t, "clang")

	goroot := runtime.GOROOT()
	src, err := os.ReadFile(filepath.Join(goroot, "src", "hash", "crc32", "crc32_amd64.s"))
	if err != nil {
		t.Fatal(err)
	}

	file, err := Parse(ArchAMD64, string(src))
	if err != nil {
		t.Fatal(err)
	}

	resolve := func(sym string) string {
		if strings.HasPrefix(sym, "·") {
			return "hash/crc32." + strings.TrimPrefix(sym, "·")
		}
		return strings.ReplaceAll(sym, "·", ".")
	}

	sliceTy := LLVMType("{ ptr, i64, i64 }")
	ret3 := LLVMType("{ i32, i32, i32 }")
	sigs := map[string]FuncSig{
		"hash/crc32.castagnoliSSE42": {
			Name: "hash/crc32.castagnoliSSE42",
			Args: []LLVMType{I32, sliceTy},
			Ret:  I32,
			Frame: FrameLayout{
				Params: []FrameSlot{
					{Offset: 0, Type: I32, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: 0},
					{Offset: 16, Type: I64, Index: 1, Field: 1},
					{Offset: 24, Type: I64, Index: 1, Field: 2},
				},
				Results: []FrameSlot{{Offset: 32, Type: I32, Index: 0, Field: -1}},
			},
		},
		"hash/crc32.castagnoliSSE42Triple": {
			Name: "hash/crc32.castagnoliSSE42Triple",
			Args: []LLVMType{I32, I32, I32, sliceTy, sliceTy, sliceTy, I32},
			Ret:  ret3,
			Frame: FrameLayout{
				Params: []FrameSlot{
					{Offset: 0, Type: I32, Index: 0, Field: -1},
					{Offset: 4, Type: I32, Index: 1, Field: -1},
					{Offset: 8, Type: I32, Index: 2, Field: -1},
					{Offset: 16, Type: Ptr, Index: 3, Field: 0},
					{Offset: 24, Type: I64, Index: 3, Field: 1},
					{Offset: 32, Type: I64, Index: 3, Field: 2},
					{Offset: 40, Type: Ptr, Index: 4, Field: 0},
					{Offset: 48, Type: I64, Index: 4, Field: 1},
					{Offset: 56, Type: I64, Index: 4, Field: 2},
					{Offset: 64, Type: Ptr, Index: 5, Field: 0},
					{Offset: 72, Type: I64, Index: 5, Field: 1},
					{Offset: 80, Type: I64, Index: 5, Field: 2},
					{Offset: 88, Type: I32, Index: 6, Field: -1},
				},
				Results: []FrameSlot{
					{Offset: 96, Type: I32, Index: 0, Field: -1},
					{Offset: 100, Type: I32, Index: 1, Field: -1},
					{Offset: 104, Type: I32, Index: 2, Field: -1},
				},
			},
		},
		"hash/crc32.ieeeCLMUL": {
			Name: "hash/crc32.ieeeCLMUL",
			Args: []LLVMType{I32, sliceTy},
			Ret:  I32,
			Frame: FrameLayout{
				Params: []FrameSlot{
					{Offset: 0, Type: I32, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: 0},
					{Offset: 16, Type: I64, Index: 1, Field: 1},
					{Offset: 24, Type: I64, Index: 1, Field: 2},
				},
				Results: []FrameSlot{{Offset: 32, Type: I32, Index: 0, Field: -1}},
			},
		},
	}

	ll, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym:   resolve,
		Sigs:         sigs,
		Goarch:       "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, `"target-features"="+crc32,+sse4.2"`) {
		t.Fatalf("missing crc32 target-features attr:\n%s", ll)
	}
	if !strings.Contains(ll, `"target-features"="+pclmul,+sse4.1"`) {
		t.Fatalf("missing pclmul target-features attr:\n%s", ll)
	}

	tmp := t.TempDir()
	llPath := filepath.Join(tmp, "crc32_amd64.ll")
	objPath := filepath.Join(tmp, "crc32_amd64.o")
	if err := os.WriteFile(llPath, []byte(ll), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(clang, "-target", "x86_64-unknown-linux-gnu", "-c", llPath, "-o", objPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("clang failed: %v\n%s", err, string(out))
	}
}
