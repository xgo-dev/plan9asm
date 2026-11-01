package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestARM64TextFrameAllocation(t *testing.T) {
	for _, test := range []struct {
		name             string
		frame, low, high int64
		body             string
	}{
		{"zero", 0, 0, 0, ""},
		{"no-frame", -8, 0, 0, ""},
		{"small", 16, 0, 16, ""},
		{"snappy-table", 32904, 0, 32904, "ADD $128,RSP,R17\nMOVD R0,(R17)\n"},
		{"negative-sp", 32904, -512, 32904, "SUB $512,RSP\nMOVD R0,(RSP)\nADD $512,RSP\n"},
		{"positive-sp", 32904, 0, 32904 + 512, "ADD $512,RSP\nMOVD R0,(RSP)\nSUB $512,RSP\n"},
		{"explicit-beyond-frame", 16, 0, 4160, "MOVD R0,4096(RSP)\n"},
		{"runtime-call2MiB", 1 << 21, 0, 1 << 21, ""},
		{"runtime-call1GiB", 1 << 30, 0, 1 << 30, ""},
		{"large-frame-sp-movement", 1 << 21, -512, 1<<21 + 512, "SUB $512,RSP\nMOVD R0,(RSP)\nADD $1024,RSP\nMOVD R0,(RSP)\nSUB $512,RSP\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := fmt.Sprintf("TEXT stack_bounds(SB),$%d-0\nMOVD RSP,R9\n%sRET\n", test.frame, test.body)
			requireARM64GoAssemblerResult(t, source, true)
			ir := arm64StackTestIR(t, source)
			match := regexp.MustCompile(`getelementptr inbounds \[(\d+) x i8\], ptr %local_stack, i32 0, i64 (\d+)`).FindStringSubmatch(ir)
			if len(match) != 3 {
				t.Fatal("missing local stack allocation")
			}
			size, _ := strconv.ParseInt(match[1], 10, 64)
			bias, _ := strconv.ParseInt(match[2], 10, 64)
			if bias+test.low < 0 || bias+test.high > size {
				t.Fatalf("allocation [%d,%d) does not contain declared frame/accesses [%d,%d)", -bias, size-bias, test.low, test.high)
			}
		})
	}
}

func TestARM64TextFrameRejectsInvalidSize(t *testing.T) {
	for _, frame := range []int64{-16, -1, 1<<31 + 8, 1<<63 - 1} {
		t.Run(strconv.FormatInt(frame, 10), func(t *testing.T) {
			file, err := Parse(ArchARM64, fmt.Sprintf("TEXT frame(SB),$%d-0\nMOVD RSP,R9\nRET\n", frame))
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{
				"frame": {Name: "frame", Ret: Void},
			}})
			if err == nil {
				t.Fatalf("invalid or oversized TEXT frame %d accepted", frame)
			}
		})
	}
}

func TestARM64LargeTextFrameLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, frame := range []int64{1 << 21, 1 << 28, 1 << 30} {
		for _, triple := range []string{
			"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
			"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
		} {
			t.Run(fmt.Sprintf("%d/%s", frame, triple), func(t *testing.T) {
				source := fmt.Sprintf("TEXT large_frame(SB),$%d-0\nADD $128,RSP,R3\nMOVD R3,R0\nRET\n", frame)
				requireARM64GoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
					Sigs: map[string]FuncSig{"large_frame": {Name: "large_frame", Ret: Ptr, Attrs: "uwtable"}},
				})
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(ir, `asm sideeffect "", "=r,0"`) || !strings.Contains(ir, "%local_stack = alloca i8, i64 %") {
					t.Fatal("large declared frame must retain its full size through a dynamic alloca")
				}
				compileLLVMToObject(t, llc, triple, "large-frame.ll", "large-frame.o", ir)
				compileARM64LargeFrameOptimized(t, llc, triple, ir)
			})
		}
	}
}

func compileARM64LargeFrameOptimized(t *testing.T, llc, triple, ir string) {
	t.Helper()
	opt := findLLVM22Tool("opt")
	readobj := findLLVM22Tool("llvm-readobj")
	if opt == "" || readobj == "" {
		t.Fatal("LLVM 22 opt and llvm-readobj are required")
	}
	dir := t.TempDir()
	input, optimized := filepath.Join(dir, "input.ll"), filepath.Join(dir, "optimized.ll")
	if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(opt, "-passes=default<O2>", "-S", input, "-o", optimized).CombinedOutput(); err != nil {
		t.Fatalf("optimize large frame: %v\n%s", err, out)
	}
	data, err := os.ReadFile(optimized)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "alloca i8, i64 %") || !strings.Contains(string(data), "uwtable") {
		t.Fatal("optimization lost the dynamic allocation or caller's unwind attribute")
	}
	for _, level := range []string{"-O0", "-O2"} {
		object := filepath.Join(dir, strings.TrimPrefix(level, "-")+".o")
		if out, err := exec.Command(llc, level, "-mtriple="+triple, "-filetype=obj", optimized, "-o", object).CombinedOutput(); err != nil {
			t.Fatalf("compile optimized large frame %s: %v\n%s", level, err, out)
		}
		if strings.Contains(triple, "windows") {
			out, err := exec.Command(readobj, "--unwind", object).CombinedOutput()
			if err != nil {
				t.Fatalf("inspect Windows unwind: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), "RuntimeFunction {") || !strings.Contains(string(out), "mov x29, sp") {
				t.Fatalf("dynamic frame lost its Windows unwind frame chain:\n%s", out)
			}
		}
	}
}

const arm64TextFrameSource = `TEXT frame_table(SB),$32904-16
MOVD value+0(FP),R0
MOVD R0,64(RSP)
ADD $128,RSP,R17
ADD $32768,R17,R6
MOVD R0,(R6)
MOVD $32768,R4
fill:
MOVD R0,(R17)
ADD $8,R17
SUB $8,R4
CBNZ R4,fill
ADD $128,RSP,R17
MOVD $32768,R4
BL frame_observe(SB)
MOVD $0,R5
check:
MOVD (R17),R1
EOR R0,R1
ORR R1,R5
ADD $8,R17
SUB $8,R4
CBNZ R4,check
MOVD 64(RSP),R1
EOR R0,R1
ORR R1,R5
MOVD (R6),R1
EOR R0,R1
ORR R1,R5
MOVD R5,ret+8(FP)
RET
`

// The original observer call escapes a pointer to the private Go frame. Its
// manual register signature provides no bounds or non-escape memory contract.
// Keep that full source as a Context regression rather than pretending that the
// C observer body is a contract available to the translator.
func TestARM64TextFrameObserverNeedsBoundedMemoryContract(t *testing.T) {
	for _, large := range []bool{false, true} {
		source := arm64TextFrameSource
		if large {
			source = strings.ReplaceAll(source, "32904", "2097288")
			source = strings.ReplaceAll(source, "32768", "2097152")
		}
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		for _, triple := range []string{
			"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
			"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
		} {
			t.Run(fmt.Sprintf("large=%v/%s", large, triple), func(t *testing.T) {
				_, err := Translate(file, Options{
					Goarch: "arm64", TargetTriple: triple,
					Sigs: arm64TextFrameSigs(),
				})
				if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "caller LR") {
					t.Fatalf("unbounded private-frame observer must retain Context: %v", err)
				}
			})
		}
	}
}

// This separate positive fixture has no escaping call. Both its Go and LLVM
// runtime oracles execute this exact source, not different versions of it.
func arm64TextFrameNoEscapeSource() string {
	return strings.ReplaceAll(arm64TextFrameSource, "BL frame_observe(SB)\n", "")
}

func arm64TextFrameNoEscapeRuntime(t *testing.T, triple string) (string, string) {
	return arm64TextFrameRuntimeForSource(t, triple, arm64TextFrameNoEscapeSource())
}

func arm64TextFrameSigs() map[string]FuncSig {
	return map[string]FuncSig{"frame_table": {
		Name: "frame_table", Args: []LLVMType{I64}, Ret: I64,
		Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
			Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
		},
	}, "frame_observe": {
		Name: "frame_observe", Args: []LLVMType{Ptr, I64, I64}, Ret: Void,
		ArgRegs: []Reg{"R17", "R4", "R0"},
	}}
}

func arm64TextFrameRuntimeForSource(t *testing.T, triple, source string) (string, string) {
	t.Helper()
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: arm64TextFrameSigs(),
	})
	if err != nil {
		t.Fatal(err)
	}
	const main = `
#include <stdint.h>
#include <stdio.h>
extern uint64_t frame_table(uint64_t);
int main(void) {
  volatile uint64_t canary[2] = {UINT64_C(0x123456789abcdef0), UINT64_C(0xfedcba9876543210)};
  uint64_t value = UINT64_C(0x89abcdef01234567);
  for (unsigned i = 0; i < 128; i++) {
    uint64_t got = frame_table(value);
    if (got != 0) {
      fprintf(stderr, "frame table mismatch: %llx\n", (unsigned long long)got);
      return 1;
    }
    if (canary[0] != UINT64_C(0x123456789abcdef0) || canary[1] != UINT64_C(0xfedcba9876543210)) return 2;
    value = value * UINT64_C(6364136223846793005) + 1;
  }
  return 0;
}
`
	return ir, main
}

func TestARM64LargeTextFrameNoEscapeRuntime(t *testing.T) {
	llc, clang := findLLVM22Tool("llc"), findLLVM22Tool("clang")
	if llc == "" || clang == "" {
		t.Fatal("LLVM 22 llc and clang are required")
	}
	source := strings.ReplaceAll(arm64TextFrameNoEscapeSource(), "32904", "2097288")
	source = strings.ReplaceAll(source, "32768", "2097152")
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, main := arm64TextFrameRuntimeForSource(t, triple, source)
			if !strings.Contains(ir, "%local_stack = alloca i8, i64 %") {
				t.Fatal("2 MiB runtime oracle did not exercise the large-frame allocation path")
			}
			compileLLVMToObject(t, llc, triple, "large-runtime.ll", "large-runtime.o", ir)
			native := runtime.GOARCH == "arm64" && ((runtime.GOOS == "darwin" && strings.Contains(triple, "apple")) ||
				(runtime.GOOS == "linux" && strings.Contains(triple, "linux")) ||
				(runtime.GOOS == "freebsd" && strings.Contains(triple, "freebsd")))
			if native {
				compileAndRunRuntimeTestForTarget(t, llc, clang, "large-runtime", triple, ir, main, nil)
			}
		})
	}
}

func TestARM64TextFrameNoEscapeLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
		"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, main := arm64TextFrameNoEscapeRuntime(t, triple)
			compileLLVMToObject(t, llc, triple, "frame.ll", "frame.o", ir)
			native := runtime.GOARCH == "arm64" && ((runtime.GOOS == "darwin" && strings.Contains(triple, "apple")) ||
				(runtime.GOOS == "linux" && strings.Contains(triple, "linux")) ||
				(runtime.GOOS == "freebsd" && strings.Contains(triple, "freebsd")))
			if native {
				clang := findLLVM22Tool("clang")
				if clang == "" {
					t.Fatal("LLVM 22 clang not found")
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "frame", triple, ir, main, nil)
			}
		})
	}
}

func TestARM64TextFrameNoEscapeNativeGo(t *testing.T) {
	cross := runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && os.Getenv("PLAN9ASM_CROSS_EXEC") == "1"
	if runtime.GOARCH != "arm64" && !cross {
		t.Skip("native Go oracle runs on arm64 or required Linux/QEMU")
	}
	const main = `package main
func frame_table(value uint64) uint64
func main() {
  value := uint64(0x89abcdef01234567)
  for i := 0; i < 128; i++ {
    if got := frame_table(value); got != 0 { panic("declared frame table mismatch") }
    value = value * 6364136223846793005 + 1
  }
}
`
	for _, large := range []bool{false, true} {
		t.Run(fmt.Sprintf("large=%v", large), func(t *testing.T) {
			source := arm64TextFrameNoEscapeSource()
			if large {
				source = strings.ReplaceAll(source, "32904", "2097288")
				source = strings.ReplaceAll(source, "32768", "2097152")
			}
			dir := t.TempDir()
			for name, data := range map[string]string{
				"go.mod":        "module frameoracle\n\ngo 1.20\n",
				"main.go":       main,
				"frame_arm64.s": strings.Replace(source, "TEXT frame_table", "TEXT ·frame_table", 1),
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"run", "."}
			if cross {
				if _, err := exec.LookPath("qemu-aarch64"); err != nil {
					t.Fatal(err)
				}
				args = []string{"run", "-exec=qemu-aarch64", "."}
			}
			cmd := exec.Command("go", args...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOWORK=off", "GOARCH=arm64", "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("Go TEXT frame oracle: %v\n%s", err, out)
			}
		})
	}
}
