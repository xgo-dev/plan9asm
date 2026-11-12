package plan9asm

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func x86ByteSwapExecuteOriginalAndLLVM(t *testing.T, arch string, execution x86FloatCompareExecution) {
	t.Helper()
	triple := "x86_64-unknown-linux-gnu"
	if arch == "386" {
		triple = "i386-unknown-linux-gnu"
	}
	if execution.triple != triple || len(execution.prefix) != 0 || execution.preserveArgv0 {
		t.Fatal("native BSWAP owner requires exact direct Linux execution")
	}
	source, declarations, rows := x86ByteSwapNativeRows(t, arch)
	var adapters strings.Builder
	for index, row := range rows {
		kernel := x86ByteSwapNativeKernel(row)
		code := x86OrderingHintGoBytes(t, arch, kernel)
		var raw strings.Builder
		raw.WriteString("TEXT kernel(SB),4,$0-0\n")
		for _, value := range code {
			fmt.Fprintf(&raw, "BYTE $%d\n", value)
		}
		if actual := x86OrderingHintGoBytes(t, arch, raw.String()); !bytes.Equal(actual, code) {
			t.Fatal("actual named/raw original-Go opcode kernel differs")
		}
		adapter, err := x86ByteSwapNativeAdapter(arch, row, index, code)
		if err != nil {
			t.Fatal(err)
		}
		adapters.WriteString(adapter)
	}
	driver := x86ByteSwapNativeDriver(t, arch, rows, adapters.String())
	want := fmt.Sprintf("BSWAP original-Go opcode bytes and complete LLVM fixture: %d checks, six FLAGS/DF and stack canaries\n", len(rows)*len(x86ByteSwapNativeValues)*128)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, execution.triple, api)
			if err != nil || ir == "" {
				t.Fatal("complete BSWAP numerical fixture failed", err)
			}
			for _, optimizeIR := range []bool{false, true} {
				input := ir
				if optimizeIR {
					input = x86MulDivRoundOptimize(t, input)
				}
				for _, level := range []string{"-O0", "-O2"} {
					t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimizeIR, level), func(t *testing.T) {
						executable := execution.compileLLVM(t, "bswap", input, driver, level)
						var output []byte
						if arch == "386" {
							sealed, err := x87IA32StaticExecutable(executable)
							if err != nil {
								t.Fatal(err)
							}
							output = x87IA32RunDirect(t, sealed, nil, os.Environ())
						} else {
							output = execution.run(t, executable)
						}
						if string(output) != want {
							t.Fatalf("native original opcode/LLVM/reference result/status/canary disagreement: %s", output)
						}
					})
				}
			}
		})
	}
}

// Compile the actual generated C/assembly driver for both target ISAs without
// executing either. Minimal freestanding declarations replace only its two
// libc includes; this is syntax/ABI-object evidence, not a native SDK or run.
func TestX86ByteSwapNativeAdapterBothISAsCompileWithLLVM22(t *testing.T) {
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("BSWAP native-driver objects require LLVM22 clang")
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			_, _, rows := x86ByteSwapNativeRows(t, arch)
			var adapters strings.Builder
			for index, row := range rows {
				code := x86OrderingHintGoBytes(t, arch, x86ByteSwapNativeKernel(row))
				adapter, err := x86ByteSwapNativeAdapter(arch, row, index, code)
				if err != nil {
					t.Fatal(err)
				}
				adapters.WriteString(adapter)
			}
			driver := x86ByteSwapNativeDriver(t, arch, rows, adapters.String())
			const includes = "#include <stdint.h>\n#include <stdio.h>\n"
			if !strings.HasPrefix(driver, includes) || strings.Count(driver, includes) != 1 {
				t.Fatal("complete native-driver include projection changed")
			}
			driver = `typedef __UINT8_TYPE__ uint8_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef __UINTPTR_TYPE__ uintptr_t;
#define UINT64_C(x) x##ULL
#define NULL ((void*)0)
struct FILE;
extern struct FILE *stderr;
extern int printf(const char*,...);
extern int fprintf(struct FILE*,const char*,...);
` + strings.TrimPrefix(driver, includes)
			dir := t.TempDir()
			input, output := filepath.Join(dir, "driver.c"), filepath.Join(dir, "driver.o")
			if err := os.WriteFile(input, []byte(driver), 0600); err != nil {
				t.Fatal(err)
			}
			triple := "x86_64-unknown-linux-gnu"
			if arch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			x86FloatCompareCaptureCommand(t, exec.Command(clang, "--no-default-config", "-target", triple,
				"-ffreestanding", "-nostdinc", "-fno-pie", "-O2", "-c", input, "-o", output))
			if info, err := os.Stat(output); err != nil || info.Size() == 0 {
				t.Fatal("complete native-driver target object missing", err)
			}
		})
	}
}
