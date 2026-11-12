//go:build go1.27

package plan9asm

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// Read the actual selected SDK declaration and assembly. No guessed ManualSig
// replaces its source-owned seven inputs and three register results.
func amd64RegisterTupleSDKSource(t *testing.T) (GoPackage, string, []byte) {
	t.Helper()
	const path = "internal/runtime/syscall/linux"
	root := runtime.GOROOT()
	directory := filepath.Join(root, "src", filepath.FromSlash(path))
	declaration, err := os.ReadFile(filepath.Join(directory, "syscall_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "syscall_linux.go", declaration, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var selected *ast.FuncDecl
	for _, item := range file.Decls {
		function, ok := item.(*ast.FuncDecl)
		if ok && function.Name.Name == "Syscall6" {
			if selected != nil || function.Recv != nil || function.Body != nil {
				t.Fatal("SDK register entry declaration is not unique/bodyless")
			}
			selected = function
		}
	}
	if selected == nil {
		t.Fatal("selected SDK register entry declaration is absent")
	}
	// This selected declaration uses only built-in uintptr types. Keeping the
	// original FuncType avoids importing or rechecking unrelated SDK bodies.
	view := &ast.File{Name: file.Name, Decls: []ast.Decl{selected}}
	config := types.Config{Sizes: types.SizesFor("gc", "amd64")}
	typed, err := config.Check(path, fset, []*ast.File{view}, nil)
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := os.ReadFile(filepath.Join(directory, "asm_linux_amd64.s"))
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := PreprocessAssemblySource(string(assembly), AssemblyPreprocessOptions{
		FileName: "asm_linux_amd64.s",
		ReadInclude: func(parent, name string) (string, []byte, error) {
			if name != "textflag.h" {
				return "", nil, fmt.Errorf("unexpected SDK include %q", name)
			}
			name = filepath.Join(root, "pkg", "include", name)
			data, err := os.ReadFile(name)
			return name, data, err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual SDK=%s declarationSHA256=%x assemblySHA256=%x", root, sha256.Sum256(declaration), sha256.Sum256(assembly))
	return GoPackage{Path: path, Types: typed, Syntax: []*ast.File{view}}, expanded, assembly
}

func TestAMD64RegisterTupleResultSDKOriginalGoObject(t *testing.T) {
	pkg, _, source := amd64RegisterTupleSDKSource(t)
	dir := t.TempDir()
	input, object := filepath.Join(dir, "source.s"), filepath.Join(dir, "source.o")
	if err := os.WriteFile(input, source, 0600); err != nil {
		t.Fatal(err)
	}
	root := runtime.GOROOT()
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(root, "bin", "go"), "tool", "asm",
		"-p", pkg.Path, "-I", filepath.Join(root, "pkg", "include"), "-o", object, input)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=amd64")
	data, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(input, object, data, err, ctx.Err(), true, "amd64"); failure != nil {
		t.Fatalf("actual original SDK assembly: %v\n%s", failure, data)
	}
}

func amd64RegisterTupleSDKIR(t *testing.T, api string) string {
	t.Helper()
	pkg, source, _ := amd64RegisterTupleSDKSource(t)
	ir, err := x86ScalarFPBitViewPackageAPI(t, source, pkg, "amd64", "x86_64-unknown-linux-gnu", api)
	if err != nil {
		t.Fatal(err)
	}
	// C sees a void function and an output pointer. The internal LLVM tuple is
	// extracted here; its three-word return is never mistaken for the C ABI.
	return ir + `
define void @observe_sdk_tuple(ptr %out, i64 %n, i64 %a1, i64 %a2, i64 %a3, i64 %a4, i64 %a5, i64 %a6) {
  %r = call { i64, i64, i64 } @Syscall6(i64 %n, i64 %a1, i64 %a2, i64 %a3, i64 %a4, i64 %a5, i64 %a6)
  %r0 = extractvalue { i64, i64, i64 } %r, 0
  %r1 = extractvalue { i64, i64, i64 } %r, 1
  %r2 = extractvalue { i64, i64, i64 } %r, 2
  %p1 = getelementptr i64, ptr %out, i64 1
  %p2 = getelementptr i64, ptr %out, i64 2
  store i64 %r0, ptr %out, align 8
  store i64 %r1, ptr %p1, align 8
  store i64 %r2, ptr %p2, align 8
  ret void
}
`
}

func TestAMD64RegisterTupleResultSDKThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir := amd64RegisterTupleSDKIR(t, api)
			for _, optimized := range []bool{false, true} {
				body := ir
				if optimized {
					body = x86MulDivRoundOptimize(t, body)
				}
				x86ResultInitializationObject(t, llc, "x86_64-unknown-linux-gnu", body, "sdk-register-tuple")
			}
			t.Logf("SDK_REGISTER_TUPLE_IR_BASE64=%s", base64.StdEncoding.EncodeToString([]byte(ir)))
		})
	}
}

const amd64RegisterTupleKernelOracle = `
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>

extern void observe_sdk_tuple(uint64_t *, uint64_t, uint64_t, uint64_t,
                              uint64_t, uint64_t, uint64_t, uint64_t);

static void reference(uint64_t result[3], uint64_t number, uint64_t a3) {
  uint64_t ax, dx;
  register uint64_t r10 __asm__("r10") = 0;
  register uint64_t r8 __asm__("r8") = 0;
  register uint64_t r9 __asm__("r9") = 0;
  __asm__ volatile("syscall"
      : "=a"(ax), "=d"(dx)
      : "0"(number), "D"(UINT64_C(0)), "S"(UINT64_C(0)), "1"(a3),
        "r"(r10), "r"(r8), "r"(r9)
      : "rcx", "r11", "cc", "memory");
  if (ax >= (uint64_t)-4095) {
    result[0] = UINT64_MAX;
    result[1] = 0;
    result[2] = -ax;
  } else {
    result[0] = ax;
    result[1] = dx;
    result[2] = 0;
  }
}

int main(void) {
  const uint64_t guard = UINT64_C(0x9acefedb01234567);
  const uint64_t numbers[] = {SYS_getpid, UINT64_MAX};
  unsigned cases = 0;
  for (unsigned iteration = 0; iteration < 32; ++iteration) {
    const uint64_t a3 = UINT64_C(0x7263548190abcdef) ^ iteration;
    for (unsigned which = 0; which < 2; ++which) {
      uint64_t expected[3];
      uint64_t output[] = {guard, 13, 29, 47, guard};
      errno = EDOM;
      reference(expected, numbers[which], a3);
      if (errno != EDOM) return 2;
      observe_sdk_tuple(output + 1, numbers[which], 0, 0, a3, 0, 0, 0);
      if (errno != EDOM || output[0] != guard || output[4] != guard) return 3;
      for (unsigned field = 0; field < 3; ++field) {
        if (output[field + 1] != expected[field]) {
          fprintf(stderr, "case=%u field=%u got=%llx want=%llx\n", which, field,
                  (unsigned long long)output[field + 1], (unsigned long long)expected[field]);
          return 4;
        }
      }
      if (which == 1 && expected[2] != ENOSYS) return 5;
      ++cases;
    }
  }
  printf("SDK_REGISTER_TUPLE_KERNEL_PASS cases=%u fields=%u\n", cases, 3 * cases);
  return cases == 64 ? 0 : 6;
}
`
