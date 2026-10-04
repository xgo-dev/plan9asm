//go:build !llgo

package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestARM64ConformanceNativeGo(t *testing.T) {
	crossLinux := runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && os.Getenv("PLAN9ASM_CROSS_EXEC") == "1"
	if runtime.GOARCH != "arm64" && !crossLinux {
		t.Skip("native Go assembler oracle requires an arm64 host")
	}
	args := []string{"test", "./testdata/conformance/arm64"}
	if crossLinux {
		if _, err := exec.LookPath("qemu-aarch64"); err != nil {
			t.Fatal("qemu-aarch64 not found")
		}
		args = []string{"test", "-exec=qemu-aarch64", "./testdata/conformance/arm64"}
	}
	cmd := exec.Command("go", args...)
	if crossLinux {
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native Go conformance failed: %v\n%s", err, out)
	}
}

func TestARM64ConformanceTranslate(t *testing.T) {
	translateARM64Conformance(t, "aarch64-unknown-linux-gnu")
}

func translateARM64Conformance(t *testing.T, triple string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("testdata", "conformance", "arm64", "conformance_arm64.s"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchARM64, string(src))
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"pairStores": {
				Name: "pairStores",
				Args: []LLVMType{Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
			"families": {
				Name: "families",
				Args: []LLVMType{Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ll
}

func TestARM64ConformanceLLVMRuntime(t *testing.T) {
	crossLinux := runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && os.Getenv("PLAN9ASM_CROSS_EXEC") == "1"
	if runtime.GOARCH != "arm64" && !crossLinux {
		t.Skip("runtime execution test only runs on an arm64 host")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("llc not found")
	}
	compiler := []string{}
	runPrefix := []string(nil)
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	if crossLinux {
		compiler = []string{"aarch64-linux-gnu-gcc"}
		runPrefix = []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"}
		triple = "aarch64-unknown-linux-gnu"
	} else {
		_, clang, ok := findLlcAndClang(t)
		if !ok {
			t.Skip("clang not found")
		}
		compiler = []string{clang}
	}

	ll := translateARM64Conformance(t, triple)
	mainC := `
#include <stdint.h>
extern void families(uint64_t *out, uint64_t *data);
extern void pairStores(uint64_t *out, uint64_t *data);
int main(void) {
    uint64_t data[8] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL, 0x1122334455667788ULL, 0x8877665544332211ULL};
    uint64_t want[76] = {
        0xfedcba9876cdef10ULL, 0x0000000076543ef0ULL, 0xfedcba9876589abcULL, 0x0000000076543abcULL,
        0xffffffffffcdef00ULL, 0x00000000ffffdef0ULL, 0xfffffffffff89abcULL, 0x00000000fffffabcULL,
        0x0000000000cdef00ULL, 0x000000000000def0ULL, 0x0000000000089abcULL, 0x0000000000000abcULL,
        5, 5, 10, 10, 0xfffffffffffffff6ULL, 0x00000000fffffff6ULL, 0xfffffffffffffff7ULL, 0x00000000fffffff7ULL,
        1, 1, 0xffffffffffffffffULL, 0x00000000ffffffffULL, 6, 6, 0xfffffffffffffffaULL, 0x00000000fffffffaULL,
        0xfffffffffffffffbULL, 0x00000000fffffffbULL, 0xefcdab8967452301ULL, 0x00000000efcdab89ULL,
        0x23016745ab89efcdULL, 0x00000000ab89efcdULL, 0x67452301efcdab89ULL, 0x000123456789abcdULL,
        0x00000000ff89abcdULL, 0x23456789abcdef00ULL, 0x00000000abcdef00ULL, 0x000123456789abcdULL,
        0x000000000089abcdULL, 0xef0123456789abcdULL, 0x00000000ef89abcdULL, 0x0000123456789abcULL,
        0x00000000fff89abcULL, 0x3456789abcdef000ULL, 0x00000000bcdef000ULL, 0x0000123456789abcULL,
        0x0000000000089abcULL, 0xdef0123456789abcULL, 0x00000000def89abcULL, 0x0123456789abcdd7ULL,
        0x0000000089abcdd7ULL, 0, 0, 0xffffffffffff89abULL, 0x00000000000089abULL, 0x0000000001234567ULL,
        0x0000000001234567ULL, 0xffffffffffffffefULL, 0x00000000000000efULL, 0x0123456789abcdefULL,
        0xfedcba9876543210ULL, 0x0123456789abcdefULL, 0xfedcba9876543210ULL, 0x1122334455667788ULL,
        0x8877665544332211ULL, 0xffffffff89abcdefULL, 1, 1, 1, 1,
        0x0000000089abcdefULL, 0x0123456789abcdefULL, 0x1234, 0
    };
    uint64_t got[76] = {0};
    families(got, data);
    for (int i = 0; i < 76; i++)
        if (got[i] != want[i])
            return i + 1;
    uint64_t pairs[20], expected[20];
    for (int i = 0; i < 20; i++)
        pairs[i] = expected[i] = 0xdeadbeef;
    expected[0] = 0;
    expected[1] = 32;
    expected[6] = (uint64_t)-32;
    for (int i = 0; i < 4; i++) {
        expected[2 + i] = expected[16 + i] = data[i];
        expected[8 + i] = data[(i + 2) % 4];
    }
    pairStores(pairs, data);
    for (int i = 0; i < 20; i++)
        if (pairs[i] != expected[i])
            return 100 + i;
    return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "arm64_conformance", triple, ll, mainC, runPrefix)
}
