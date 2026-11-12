package plan9asm

import (
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// This is a native measurement, not a speed-ratio acceptance gate. Run the
// exact same command before/after the change on the same ARM64 machine.
// It translates the complete original SDK file, without a KeepFunc filter or
// an llgo runtime build whose separate closure-entry boundary is not closed.
func TestARM64VectorMemoryStdlibIndexByteBenchmark(t *testing.T) {
	if runtime.GOARCH != "arm64" || runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("throughput requires native ARM64; instruction semantics have the required cross-runtime counterpart")
	}
	llc, triple, compiler, _ := arm64FPPairRuntimeTools(t)
	opt := findLLVM22Tool("opt")
	if opt == "" {
		t.Fatal("LLVM 22 opt not found")
	}
	pkg := arm64BytealgCountSDKPackage(t) // Complete actual bytealg declarations/selection, not copied signatures.
	filename := filepath.Join(runtime.GOROOT(), "src", "internal", "bytealg", "indexbyte_arm64.s")
	source, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	translated, err := TranslateGoModule(pkg, source, GoModuleOptions{
		GOARCH: "arm64", TargetTriple: triple, FileName: "indexbyte_arm64.s",
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	ir := translated.Module.String()
	translated.Module.Dispose()
	for _, name := range []string{"IndexByte", "IndexByteString"} {
		if _, present := translated.Signatures[name]; !present {
			t.Fatalf("complete original indexbyte file lost %s", name)
		}
	}
	// An explicit scalar LLVM shim avoids borrowing the host C compiler's
	// aggregate ABI to call the translator's typed Go slice parameter.
	ir += `
define i64 @vector_bench_index_byte(ptr %p, i64 %n, i8 %c) {
  %s0 = insertvalue { ptr, i64, i64 } poison, ptr %p, 0
  %s1 = insertvalue { ptr, i64, i64 } %s0, i64 %n, 1
  %s2 = insertvalue { ptr, i64, i64 } %s1, i64 %n, 2
  %r = call i64 @IndexByte({ ptr, i64, i64 } %s2, i8 %c)
  ret i64 %r
}
`
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"indexbyte.ll": ir, "main.c": arm64VectorMemoryIndexByteC,
		"go.mod": "module indexbytebenchmark\n\ngo 1.20\n", "main.go": arm64VectorMemoryIndexByteGo,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(name string, args ...string) {
		t.Helper()
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		command := exec.CommandContext(ctx, name, args...)
		command.Dir = dir
		command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOARCH=arm64", "GOOS="+runtime.GOOS)
		output, err := runtimeOracleCombinedOutput(ctx, command)
		if err != nil {
			t.Fatalf("indexbyte measurement command %s: %v\n%s", name, err, output)
		}
		if len(output) != 0 {
			t.Log(strings.TrimSpace(string(output)))
		}
	}
	t.Logf("temporary diagnostic IR/assembly/objects/executables: %s (automatically cleaned)", dir)
	optimizedIR := filepath.Join(dir, "indexbyte-optimized.ll")
	run(opt, "-passes=default<O2>", "-S", filepath.Join(dir, "indexbyte.ll"), "-o", optimizedIR)
	var llvmExecutables []string
	for _, pipeline := range []struct{ name, input string }{
		{"raw-llc-O2", filepath.Join(dir, "indexbyte.ll")},
		{"optimized-llvm-O2", optimizedIR},
	} {
		object := filepath.Join(dir, pipeline.name+".o")
		executable := filepath.Join(dir, pipeline.name)
		arguments := []string{"-mtriple=" + triple, "-relocation-model=pic", "-O=2"}
		run(llc, append(append([]string(nil), arguments...), "-filetype=obj", pipeline.input, "-o", object)...)
		run(llc, append(append([]string(nil), arguments...), "-filetype=asm", pipeline.input, "-o", filepath.Join(dir, pipeline.name+".s"))...)
		linkArgs := append(append([]string(nil), compiler[1:]...), "-O2", object, filepath.Join(dir, "main.c"),
			"-DVECTOR_BENCH_ENGINE=\""+pipeline.name+"\"", "-o", executable)
		run(compiler[0], linkArgs...)
		llvmExecutables = append(llvmExecutables, executable)
	}
	goExecutable := filepath.Join(dir, "indexbyte-go")
	run(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-p=2", "-o", goExecutable, "main.go")
	t.Logf("actual SDK=%s sourceSHA256=%x; raw=no IR prepass; optimized=opt default<O2>; both llc-O2/C-O2; sizes=1048576 iterations=1024 offsets=0,1,31", runtime.Version(), sha256.Sum256(source))
	run(goExecutable)
	for _, executable := range llvmExecutables {
		run(executable)
	}
	after, err := os.ReadFile(filename)
	if err != nil || sha256.Sum256(after) != sha256.Sum256(source) {
		t.Fatalf("original indexbyte source changed during observation: %v", err)
	}
}

const arm64VectorMemoryIndexByteGo = `package main

import (
	"bytes"
	"fmt"
	"time"
	"unsafe"
)

func main() {
	const size = 1 << 20
	const iterations = 1024
	storage := make([]byte, size+96)
	for i := range storage {
		storage[i] = 0x5a
	}
	aligned := int((32 - uintptr(unsafe.Pointer(&storage[0]))%32) % 32)
	for _, off := range []int{0, 1, 31} {
		data := storage[aligned+off : aligned+off+size]
		var checksum int64
		start := time.Now()
		for i := 0; i < iterations; i++ {
			checksum += int64(bytes.IndexByte(data, 0xfe))
		}
		elapsed := time.Since(start).Nanoseconds()
		if checksum != -iterations || elapsed <= 0 {
			panic("stock Go result/time mismatch")
		}
		fmt.Printf("engine=stock-Go size=%d iterations=%d offset=%d ns=%d checksum=%d GB/s=%.3f\n",
			size, iterations, off, elapsed, checksum, float64(size)*iterations/float64(elapsed))
	}
}
`

const arm64VectorMemoryIndexByteC = `
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef VECTOR_BENCH_ENGINE
#error benchmark engine label is required
#endif
extern int64_t vector_bench_index_byte(const unsigned char *, int64_t, unsigned char);

static int64_t nanos(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t)) exit(1);
  return (int64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

int main(void) {
  const unsigned size = 1 << 20, iterations = 1024;
  unsigned char *storage = malloc(size + 96);
  if (!storage) return 1;
  memset(storage, 0x5a, size + 96);
  unsigned char *aligned = (unsigned char *)(((uintptr_t)storage + 31) & ~(uintptr_t)31);
  const unsigned offsets[] = {0, 1, 31};
  for (unsigned i = 0; i < 3; i++) {
    unsigned off = offsets[i];
    unsigned char *data = aligned + off;
    for (unsigned length = 0; length <= 80; length++) {
      if (vector_bench_index_byte(data, length, 0xfe) != -1) return 1;
      for (unsigned hit = 0; hit < length; hit++) {
        data[hit] = 0xfe;
        if (vector_bench_index_byte(data, length, 0xfe) != (int64_t)hit) return 1;
        data[hit] = 0x5a;
      }
    }
    int64_t checksum = 0, start = nanos();
    for (unsigned n = 0; n < iterations; n++) {
      checksum += vector_bench_index_byte(data, size, 0xfe);
    }
    int64_t elapsed = nanos() - start;
    if (checksum != -(int64_t)iterations || elapsed <= 0) return 1;
    printf("engine=%s size=%u iterations=%u offset=%u ns=%lld checksum=%lld GB/s=%.3f\n",
           VECTOR_BENCH_ENGINE, size, iterations, off, (long long)elapsed, (long long)checksum,
           (double)size * iterations / elapsed);
  }
  free(storage);
  return 0;
}
`
