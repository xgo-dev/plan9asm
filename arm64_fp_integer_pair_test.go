package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/nativeoracle"
)

func arm64FPPairRuntimeTools(t *testing.T) (llc, triple string, compiler, runner []string) {
	t.Helper()
	cross := runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && os.Getenv("PLAN9ASM_CROSS_EXEC") == "1"
	native := runtime.GOARCH == "arm64" && (runtime.GOOS == "darwin" || runtime.GOOS == "linux")
	if !native && !cross {
		t.Skip("ARM64 native execution or the required Linux cross-runtime matrix")
	}
	llc = findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	triple = testTargetTriple(runtime.GOOS, runtime.GOARCH)
	compiler = []string{findLLVM22Tool("clang")}
	if cross {
		triple = "aarch64-unknown-linux-gnu"
		compiler = []string{"aarch64-linux-gnu-gcc"}
		runner = []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"}
		for _, tool := range []string{compiler[0], runner[0]} {
			if _, err := exec.LookPath(tool); err != nil {
				t.Fatalf("required cross-runtime tool %s: %v", tool, err)
			}
		}
	} else if compiler[0] == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	if native && runtime.GOOS == "darwin" {
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		flags, err := nativeoracle.DarwinClangFlags(ctx, os.Environ())
		if err != nil {
			t.Fatal(err)
		}
		compiler = append(compiler, flags...)
	}
	return llc, triple, compiler, runner
}

func TestCrossLinuxRuntimeMatrixARM64FPPairSecondSlot(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	const source = `TEXT fpPairSecond(SB),$0-24
	LDP a+0(FP), (R3, R4)
	MOVD R4, ret+16(FP)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"fpPairSecond": {
			Name: "fpPairSecond", Args: []LLVMType{I64, I64}, Ret: I64,
			Frame: FrameLayout{
				Params: []FrameSlot{
					{Offset: 0, Type: I64, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
				},
				Results: []FrameSlot{{Offset: 16, Type: I64, Index: 0, Field: -1}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const main = `#include <stdint.h>
#include <stdio.h>
extern uint64_t fpPairSecond(uint64_t, uint64_t);
int main(void) {
	const uint64_t expected = UINT64_C(0xfedcba9876543210);
	uint64_t got = fpPairSecond(UINT64_C(0x0123456789abcdef), expected);
	if (got != expected) {
		fprintf(stderr, "second FP slot got=%llx want=%llx\n", (unsigned long long)got, (unsigned long long)expected);
		return 1;
	}
	return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "fp_pair_second", triple, ir, main, runner)
}

func TestARM64FPIntegerPairCompleteGoForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, op := range []string{"LDP", "LDPW", "LDPSW", "STP", "STPW"} {
		for _, offset := range []int64{0, 1, 2, 4, 512, 16384} {
			t.Run(fmt.Sprintf("%s/%d", op, offset), func(t *testing.T) {
				instruction := fmt.Sprintf("%s frame+%d(FP), (R3, R4)", op, offset)
				if strings.HasPrefix(op, "ST") {
					instruction = fmt.Sprintf("%s (R3, R4), frame+%d(FP)", op, offset)
				}
				source := "TEXT fpPairForms(SB),$0-20000\n\t" + instruction + "\n\tRET\n"
				requireARM64GoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				sig := FuncSig{Name: "fpPairForms", Args: []LLVMType{I64, I64, I64}, Ret: Void}
				start := offset &^ 7
				for i := 0; i < 3; i++ {
					sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: start + int64(i)*8, Type: I64, Index: i, Field: -1})
				}
				for _, triple := range []string{
					"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
					"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
				} {
					ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: map[string]FuncSig{sig.Name: sig}})
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, triple, "fp-pair.ll", "fp-pair.o", ir)
				}
			})
		}
	}
}

func TestARM64FPIntegerPairRejectsGoInvalidForms(t *testing.T) {
	for _, op := range []string{"LDP", "LDPW", "LDPSW", "STP", "STPW"} {
		for _, suffix := range []string{".W", ".P"} {
			instruction := op + suffix + " frame+0(FP), (R3, R4)"
			if strings.HasPrefix(op, "ST") {
				instruction = op + suffix + " (R3, R4), frame+0(FP)"
			}
			t.Run(op+suffix, func(t *testing.T) {
				source := "TEXT badFP(SB),$0-16\n\t" + instruction + "\n\tRET\n"
				requireARM64GoAssemblerResult(t, source, false)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					return
				}
				_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{"badFP": {Name: "badFP", Ret: Void}}})
				if err == nil {
					t.Errorf("translator accepted Go-rejected %s", instruction)
				}
			})
		}
	}
	for _, op := range []string{"LDP", "LDPW", "LDPSW"} {
		instruction := op + " frame+0(FP), (R3, R3)"
		t.Run(op+"/duplicate", func(t *testing.T) {
			source := "TEXT badFP(SB),$0-16\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{"badFP": {
				Name: "badFP", Args: []LLVMType{I64, I64}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: I64, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
				}},
			}}})
			if err == nil {
				t.Errorf("translator accepted Go-rejected %s", instruction)
			}
		})
	}
}

func TestARM64FPIntegerPairRejectsMissingFrameBytes(t *testing.T) {
	for _, op := range []string{"LDP", "LDPW", "LDPSW", "STP", "STPW"} {
		for _, slots := range [][]FrameSlot{
			{{Offset: 0, Type: I32, Index: 0, Field: -1}},
			{{Offset: 0, Type: I16, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}},
		} {
			instruction := op + " frame+0(FP), (R3, R4)"
			if strings.HasPrefix(op, "ST") {
				instruction = op + " (R3, R4), frame+0(FP)"
			}
			source := "TEXT missingFP(SB),$0-16\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			args := make([]LLVMType, len(slots))
			for i, slot := range slots {
				args[i] = slot.Type
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{"missingFP": {
				Name: "missingFP", Args: args, Ret: Void, Frame: FrameLayout{Params: slots},
			}}})
			if err == nil || !strings.Contains(err.Error(), "frame range") {
				t.Errorf("%s must reject absent/padding bytes, got %v", op, err)
			}
		}
	}
}

func TestARM64FPFrameRangeValidation(t *testing.T) {
	for _, test := range []struct {
		name   string
		off    int64
		size   int64
		slots  []FrameSlot
		result bool
	}{
		{name: "empty", size: 0},
		{name: "negative size", size: -1},
		{name: "oversized", size: 17},
		{name: "overflow", off: 1<<63 - 8, size: 16},
		{name: "aggregate", size: 8, slots: []FrameSlot{{Offset: 0, Type: "[2 x i64]"}}},
		{name: "overlap at start", size: 8, slots: []FrameSlot{{Offset: 0, Type: I64}, {Offset: 0, Type: I32}}},
		{name: "overlap inside", size: 8, slots: []FrameSlot{{Offset: 0, Type: I64}, {Offset: 4, Type: I32}}},
		{name: "negative request", off: -8, size: 8, slots: []FrameSlot{{Offset: -8, Type: I64}}},
		{name: "negative slot", size: 4, slots: []FrameSlot{{Offset: -1, Type: I64}}},
		{name: "minimum slot subtraction overflow", off: 1<<63 - 17, size: 8, slots: []FrameSlot{{Offset: -1 << 63, Type: I64}}},
		{name: "negative maximum slot subtraction overflow", off: 1<<63 - 17, size: 8, slots: []FrameSlot{{Offset: -(1<<63 - 1), Type: I64}}},
		{name: "slot end overflow", off: 1<<63 - 4, size: 1, slots: []FrameSlot{{Offset: 1<<63 - 4, Type: I64}}},
		{name: "negative result slot", size: 4, slots: []FrameSlot{{Offset: -1, Type: I64}}, result: true},
		{name: "result slot end overflow", off: 1<<63 - 4, size: 1, slots: []FrameSlot{{Offset: 1<<63 - 4, Type: I64}}, result: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := arm64Ctx{sig: FuncSig{Frame: FrameLayout{Params: test.slots}}}
			if test.result {
				c.sig.Frame.Params = nil
				c.fpResults = test.slots
			}
			if _, err := c.fpFrameParts(test.off, test.size); err == nil {
				t.Fatal("invalid FP frame range accepted")
			}
		})
	}
}
