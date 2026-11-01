package main

import (
	"context"
	"fmt"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/nativeoracle"
	"golang.org/x/tools/go/packages"
)

func TestFallbackARM64FrameIncludesEveryAccessedWord(t *testing.T) {
	for _, test := range []struct {
		name    string
		body    string
		params  []int64
		results []int64
	}{
		{
			name:   "two adjacent load pairs",
			body:   "LDP res+0(FP), (R0, R1)\nLDP b+16(FP), (R2, R3)\n",
			params: []int64{0, 8, 16, 24},
		},
		{
			name:   "overlapping scalar and pair reads",
			body:   "MOVD first+0(FP), R0\nLDP first+0(FP), (R0, R1)\nMOVD second+8(FP), R2\n",
			params: []int64{0, 8},
		},
		{
			name:   "quad float load",
			body:   "FMOVQ src+0(FP), F0\n",
			params: []int64{0, 8},
		},
		{
			name:    "integer pair result",
			body:    "MOVD $1, R0\nMOVD $2, R1\nSTP (R0, R1), ret+0(FP)\n",
			results: []int64{0, 8},
		},
		{
			name:    "quad float result",
			body:    "VMOVQ $1, $2, V0\nFMOVQ F0, ret+0(FP)\n",
			results: []int64{0, 8},
		},
		{
			name:   "32-bit pair occupies one fallback word",
			body:   "LDPW src+0(FP), (R0, R1)\nLDPSW src+0(FP), (R2, R3)\nSTPW (R0, R1), ret+8(FP)\n",
			params: []int64{0}, results: []int64{8},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := "TEXT span(SB),4,$0-32\n" + test.body + "RET\n"
			requireFallbackARM64GoObject(t, source)
			file, err := plan9asm.Parse(plan9asm.ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			sig := fallbackSigForAsmFunc(file.Funcs[0], "span", "arm64")
			for _, field := range []struct {
				name  string
				slots []plan9asm.FrameSlot
				want  []int64
			}{
				{name: "params", slots: sig.Frame.Params, want: test.params},
				{name: "results", slots: sig.Frame.Results, want: test.results},
			} {
				var offsets []int64
				for _, slot := range field.slots {
					offsets = append(offsets, slot.Offset)
				}
				if !reflect.DeepEqual(offsets, field.want) {
					t.Fatalf("%s offsets=%v, want %v", field.name, offsets, field.want)
				}
			}
			for _, triple := range []string{
				"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
				"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
			} {
				if _, err := plan9asm.Translate(file, plan9asm.Options{
					Goarch: "arm64", TargetTriple: triple,
					Sigs: map[string]plan9asm.FuncSig{"span": sig},
				}); err != nil {
					t.Fatalf("%s: %v", triple, err)
				}
			}
		})
	}
}

func TestFallbackARM64PairCannotExpandADeclaredPaddingSlot(t *testing.T) {
	file, err := plan9asm.Parse(plan9asm.ArchARM64,
		"TEXT ·span(SB),4,$0-16\nLDP first+0(FP), (R0, R1)\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	typesPkg := types.NewPackage("example.com/fpspan", "fpspan")
	params := types.NewTuple(
		types.NewVar(token.NoPos, typesPkg, "first", types.Typ[types.Uint64]),
		types.NewVar(token.NoPos, typesPkg, "second", types.Typ[types.Uint32]),
	)
	typesPkg.Scope().Insert(types.NewFunc(token.NoPos, typesPkg, "span",
		types.NewSignatureType(nil, nil, nil, params, nil, false)))
	pkg := &packages.Package{
		PkgPath: typesPkg.Path(), Types: typesPkg,
		TypesSizes: types.SizesFor("gc", "arm64"),
	}
	resolve := resolveSymFunc(pkg.PkgPath)
	sigs, _, err := sigsForAsmFile(pkg, file, resolve, "arm64")
	if err != nil {
		t.Fatal(err)
	}
	_, err = plan9asm.Translate(file, plan9asm.Options{
		Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: sigs, ResolveSym: resolve,
	})
	if err == nil || !strings.Contains(err.Error(), "has no slot at +12(FP)") {
		t.Fatalf("declared padding must remain unaddressable: %v", err)
	}
}

func TestFallbackARM64WideFrameCompilesWithLLVM22(t *testing.T) {
	config, err := resolveCompileConfig(true, "", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	const source = "TEXT span(SB),4,$0-40\n" +
		"LDP first+0(FP), (R0, R1)\nLDP third+16(FP), (R2, R3)\n" +
		"ADD R0, R1, R0\nADD R2, R0, R0\nADD R3, R0, R0\n" +
		"MOVD R0, ret+32(FP)\nRET\n"
	requireFallbackARM64GoObject(t, source)
	dir := t.TempDir()
	asm := filepath.Join(dir, "span_arm64.s")
	if err := os.WriteFile(asm, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	pkg := &packages.Package{
		PkgPath:    "example.com/fpspan",
		Types:      types.NewPackage("example.com/fpspan", "fpspan"),
		TypesSizes: types.SizesFor("gc", "arm64"),
	}
	for _, goos := range []string{"darwin", "linux", "windows"} {
		t.Run(goos, func(t *testing.T) {
			err := compileOne(pkg, plan9asm.ArchARM64, goos, "arm64", targetTriple(goos, "arm64"),
				asmTask{PkgPath: pkg.PkgPath, AsmFile: asm, OutLL: filepath.Join(dir, goos+".ll")},
				false, config)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("native complete-argument oracle", func(t *testing.T) {
		mode, err := fallbackARM64OracleExecution(runtime.GOOS, runtime.GOARCH, os.Getenv("PLAN9ASM_CROSS_EXEC"))
		if err != nil {
			t.Fatal(err)
		}
		if mode == "" {
			t.Skip("host-inapplicable; the required Linux cross owner executes this same complete oracle")
		}
		const oracle = `#include <stdint.h>
#include <stdio.h>
extern uint64_t span(uint64_t, uint64_t, uint64_t, uint64_t);
int main(void) {
    for (uint64_t i = 0; i < 512; i++) {
        uint64_t a = UINT64_C(0xfedcba9876543210) ^ i;
        uint64_t b = UINT64_C(0x13579bdf2468ace0) + i * 17;
        uint64_t c = UINT64_C(0xa5a5a5a5a5a5a5a5) - i;
        uint64_t d = UINT64_C(0x8000000000000001) ^ (i << 12);
        uint64_t want = a + b + c + d;
        uint64_t got = span(a, b, c, d);
        if (got != want) {
            fprintf(stderr, "four-word frame result differs at %llu\n", (unsigned long long)i);
            return 1;
        }
    }
    return 0;
}
`
		main := filepath.Join(dir, "oracle.c")
		if err := os.WriteFile(main, []byte(oracle), 0o600); err != nil {
			t.Fatal(err)
		}
		binary := filepath.Join(dir, "oracle")
		linker, objectOS := "clang", runtime.GOOS
		var emulator string
		if mode == "cross" {
			linker, objectOS = "aarch64-linux-gnu-gcc", "linux"
			emulator, err = exec.LookPath("qemu-aarch64")
			if err != nil {
				t.Fatal("required pinned ARM64 emulator: ", err)
			}
			version, stderr, err := gotoolprofile.RunBounded(arm64PrivateCLIContext(t), dir, os.Environ(), emulator, "--version")
			if err != nil || !regexp.MustCompile(`(?m)^qemu-aarch64 version 10\.2\.3\b`).Match(version) {
				t.Fatalf("required QEMU 10.2.3: %v\n%s%s", err, version, stderr)
			}
		}
		linker, err = exec.LookPath(linker)
		if err != nil {
			t.Fatal("required oracle linker: ", err)
		}
		arguments := []string{"-O2", main, filepath.Join(dir, objectOS+".o"), "-o", binary}
		if mode == "native" {
			version, stderr, err := gotoolprofile.RunBounded(arm64PrivateCLIContext(t), dir, os.Environ(), linker, "--version")
			if err != nil || !regexp.MustCompile(`(?m)\bclang version 22\.`).Match(version) {
				t.Fatalf("required LLVM 22 clang: %v\n%s%s", err, version, stderr)
			}
		}
		if mode == "native" && runtime.GOOS == "darwin" {
			flags, err := nativeoracle.DarwinClangFlags(arm64PrivateCLIContext(t), os.Environ())
			if err != nil {
				t.Fatal(err)
			}
			arguments = append(flags, arguments...)
		}
		if stdout, stderr, err := gotoolprofile.RunBounded(arm64PrivateCLIContext(t), dir, os.Environ(), linker, arguments...); err != nil {
			t.Fatalf("link complete inferred-argument oracle: %v\n%s%s", err, stdout, stderr)
		}
		executable, runArguments := binary, []string(nil)
		if mode == "cross" {
			executable, runArguments = emulator, []string{"-L", "/usr/aarch64-linux-gnu", binary}
		}
		if stdout, stderr, err := gotoolprofile.RunBounded(arm64PrivateCLIContext(t), dir, os.Environ(), executable, runArguments...); err != nil {
			t.Fatalf("execute complete inferred-argument oracle: %v\n%s%s", err, stdout, stderr)
		}
	})
}

func fallbackARM64OracleExecution(goos, goarch, cross string) (string, error) {
	if cross != "" && cross != "0" && cross != "1" {
		return "", fmt.Errorf("invalid PLAN9ASM_CROSS_EXEC value %q", cross)
	}
	if cross == "1" && (goos != "linux" || goarch != "amd64" && goarch != "arm64") {
		return "", fmt.Errorf("required ARM64 cross execution needs Linux/amd64 or native Linux/arm64")
	}
	if goarch == "arm64" && (goos == "darwin" || goos == "linux") {
		return "native", nil
	}
	if cross == "1" {
		return "cross", nil
	}
	return "", nil
}

func requireFallbackARM64GoObject(t *testing.T, source string) {
	t.Helper()
	dir := t.TempDir()
	asm, object := filepath.Join(dir, "span.s"), filepath.Join(dir, "span.o")
	if err := os.WriteFile(asm, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	env := append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local")
	if stdout, stderr, err := gotoolprofile.RunBounded(ctx, dir, env, "go", "tool", "asm", "-o", object, asm); err != nil {
		t.Fatalf("independent Go assembler rejected source: %v\n%s%s", err, stdout, stderr)
	}
	if info, err := os.Stat(object); err != nil || info.Size() == 0 {
		t.Fatalf("independent Go assembler did not emit an object: %v", err)
	}
}
