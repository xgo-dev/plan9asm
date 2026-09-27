package plan9asm

import (
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestARM64StackAllocationIncludesAdjustments(t *testing.T) {
	for _, raw := range []bool{false, true} {
		for _, test := range []struct {
			name, source string
			machine      []string
			low, high    int64
		}{
			{"subtract", "SUB $192,RSP\nMOVD R0,(RSP)\nADD $192,RSP\n",
				[]string{"sub sp,sp,#192", "str x0,[sp]", "add sp,sp,#192"}, -192, 0},
			{"add", "ADD $512,RSP\nMOVD R0,8(RSP)\nSUB $512,RSP\n",
				[]string{"add sp,sp,#512", "str x0,[sp,#8]", "sub sp,sp,#512"}, 0, 528},
			{"nested", "SUB $512,RSP\nSTP.W (R0,R1),-32(RSP)\nLDP.P 32(RSP),(R0,R1)\nADD $512,RSP\n",
				[]string{"sub sp,sp,#512", "stp x0,x1,[sp,#-32]!", "ldp x0,x1,[sp],#32", "add sp,sp,#512"}, -544, 0},
			{"restore", "MOVD RSP,R3\nSUB $192,RSP\nMOVD R3,RSP\nSUB $512,RSP\nMOVD R0,(RSP)\nADD $512,RSP\n",
				[]string{"mov x3,sp", "sub sp,sp,#192", "mov sp,x3", "sub sp,sp,#512", "str x0,[sp]", "add sp,sp,#512"}, -512, 0},
		} {
			t.Run(fmt.Sprintf("%s/raw=%v", test.name, raw), func(t *testing.T) {
				source := "TEXT stack_bounds(SB),$0-0\n" + test.source + "RET\n"
				if raw {
					var body strings.Builder
					for _, word := range assembleARM64LLVMWords(t, test.machine, "") {
						fmt.Fprintf(&body, "WORD $%#08x\n", word)
					}
					source = "TEXT stack_bounds(SB),$0-0\n" + body.String() + "RET\n"
				}
				requireARM64GoAssemblerResult(t, source, true)
				ir := arm64StackTestIR(t, source)
				match := regexp.MustCompile(`getelementptr inbounds \[(\d+) x i8\], ptr %local_stack, i32 0, i64 (\d+)`).FindStringSubmatch(ir)
				if len(match) != 3 {
					t.Fatal("missing local stack allocation")
				}
				size, _ := strconv.ParseInt(match[1], 10, 64)
				bias, _ := strconv.ParseInt(match[2], 10, 64)
				if bias+test.low < 0 || bias+test.high > size {
					t.Fatalf("stack [%d,%d) relative to initial SP cannot contain [%d,%d)", -bias, size-bias, test.low, test.high)
				}
			})
		}
	}
}

func arm64StackBoundsRuntime(t *testing.T, triple string) (string, string) {
	t.Helper()
	var machine []string
	for i, size := range []int{192, 512, 4096} {
		machine = append(machine, fmt.Sprintf("sub sp,sp,#%d", size),
			"stp x0,x1,[sp,#16]", "mov x0,xzr", "mov x1,xzr",
			"movi v0.16b,#0x5a", "stp q0,q0,[sp,#-32]!",
			"str q0,[sp,#64]", "ldp q1,q2,[sp],#32",
			"ldp x0,x1,[sp,#16]", fmt.Sprintf("add sp,sp,#%d", size),
			fmt.Sprintf("str x1,[x0,#%d]", i*8))
	}
	var source strings.Builder
	source.WriteString(`TEXT stack_runtime(SB),$32-16
MOVD out+0(FP),R0
MOVD value+8(FP),R1
MOVD R1,n-8(SP)
MOVD R0,p-16(SP)
MOVD $0,R1
MOVD n-8(SP),R1
MOVD p-16(SP),R0
`)
	for _, word := range assembleARM64LLVMWords(t, machine, "") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"stack_runtime": {
			Name: "stack_runtime", Args: []LLVMType{Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const main = `
#include <stdint.h>
extern void stack_runtime(uint64_t*, uint64_t);
int main(void) {
  uint64_t value = 1;
  for (unsigned i = 0; i < 128; i++) {
    uint64_t got[5] = {0x12345678, 0, 0, 0, 0x87654321};
    stack_runtime(got + 1, value);
    if (got[0] != 0x12345678 || got[4] != 0x87654321) return 1;
    for (unsigned j = 1; j <= 3; j++) if (got[j] != value) return 2;
    value = value * UINT64_C(6364136223846793005) + 1;
  }
  return 0;
}
`
	return ir, main
}

func TestARM64StackBoundsLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, main := arm64StackBoundsRuntime(t, triple)
			compileLLVMToObject(t, llc, triple, "stack.ll", "stack.o", ir)
			if runtime.GOARCH == "arm64" && runtime.GOOS == "darwin" && triple == "aarch64-apple-darwin" {
				clang := findLLVM22Tool("clang")
				if clang == "" {
					t.Fatal("LLVM 22 clang not found")
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "stack", triple, ir, main, nil)
			}
		})
	}
}

func arm64StackTestIR(t *testing.T, source string) string {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"stack_bounds": {Name: "stack_bounds", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ir
}

func TestARM64StackMovementControlFlow(t *testing.T) {
	for _, test := range []struct {
		name, body string
		low, high  int64
		failure    bool
	}{
		{"balanced-loop", "loop:\nSUB $192,RSP\nMOVD R0,(RSP)\nADD $192,RSP\nCBNZ R0,loop\nRET\n", -192, 0, false},
		{"alias-walk-without-sp-restore", "MOVD RSP,R3\nloop:\nADD $1,R3\nCBNZ R0,loop\nRET\n", 0, 0, false},
		{"unbalanced-loop", "loop:\nSUB $192,RSP\nCBNZ R0,loop\nRET\n", 0, 0, true},
		{"diamond", "CBZ R0,small\nSUB $512,RSP\nB done\nsmall:\nSUB $192,RSP\ndone:\nMOVD R0,(RSP)\nRET\n", -512, 0, false},
		{"raw-return", "SUB $192,RSP\nCBZ R0,tail\nend:\nADD $192,RSP\nWORD $0xd65f03c0\ntail:\nB end\nRET\n", -192, 0, false},
		{"runtime-sized-backing", "SUB R0,RSP\nMOVD R1,(RSP)\nRET\n", 0, 64, false},
		{"saved-sp", "MOVD RSP,R3\nSUB $192,RSP\nMOVD R3,RSP\nSUB $512,RSP\nRET\n", -512, 0, false},
		{"derived-sp", "SUB $512,RSP,R3\nMOVD R3,RSP\nRET\n", -512, 0, false},
		{"aligned-sp-bic", "SUB $16,RSP,R3\nBIC $15,R3\nMOVD R3,RSP\nRET\n", -31, 0, false},
		{"aligned-sp-and", "AND $-16,RSP,R3\nMOVD R3,RSP\nRET\n", -15, 0, false},
		{"saved-sp-join", "MOVD RSP,R3\nCBZ R0,small\nSUB $512,R3\nB done\nsmall:\nSUB $192,R3\ndone:\nMOVD R3,RSP\nRET\n", -512, 0, false},
		{"dynamic-alias", "MOVD RSP,R3\nSUB R0,R3\nMOVD R3,RSP\nMOVD R1,(RSP)\nRET\n", 0, 0, true},
		{"external-sp", "MOVD (R0),RSP\nSUB R1,RSP\nRET\n", 0, 0, false},
		{"unused-stack-restore", "SUB $16,RSP\nMOVD 8(RSP),R2\nMOVD R2,RSP\nRET\n", -16, 56, false},
		{"unproved-stack-reload", "MOVD RSP,R3\nMOVD R3,(RSP)\nMOVD (RSP),RSP\nMOVD R0,(RSP)\nRET\n", 0, 0, true},
		{"alias-clobber", "MOVD RSP,R3\nMUL R0,R3\nMOVD R3,RSP\nMOVD R1,(RSP)\nRET\n", 0, 0, true},
		{"excessive", "SUB $2097152,RSP\nMOVD R1,(RSP)\nRET\n", 0, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := "TEXT stack_bounds(SB),$0-0\n" + test.body
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ctx := &arm64Ctx{blocks: arm64SplitBlocks(file.Funcs[0])}
			low, high, err := ctx.stackMovementRange()
			if test.failure {
				if err == nil {
					t.Fatal("unbounded stack movement accepted")
				}
				return
			}
			if err != nil || low != test.low || high != test.high {
				t.Fatalf("range=[%d,%d] err=%v, want [%d,%d]", low, high, err, test.low, test.high)
			}
		})
	}
}

func TestARM64StackOperandBoundsRejectOverflow(t *testing.T) {
	for _, offset := range []int64{1 << 21, -1 << 21, 1<<63 - 1, -1 << 63} {
		source := fmt.Sprintf("TEXT stack_bounds(SB),$0-0\nMOVD R0,%d(RSP)\nRET\n", offset)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		ctx := &arm64Ctx{blocks: arm64SplitBlocks(file.Funcs[0])}
		if _, _, err := ctx.stackOffsetRange(); err == nil {
			t.Fatalf("accepted oversized stack offset %d", offset)
		}
	}
}

func TestARM64StackScalableAdjustments(t *testing.T) {
	for _, op := range []string{"ADDVL", "ADDPL"} {
		for _, immediate := range []int{-32, -1, 31} {
			for _, raw := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/raw=%v", op, immediate, raw), func(t *testing.T) {
					body := fmt.Sprintf("%s $%d,RSP,RSP\n", op, immediate)
					if raw {
						machine := fmt.Sprintf("%s sp,sp,#%d", strings.ToLower(op), immediate)
						word := assembleARM64LLVMWords(t, []string{machine}, "+sve")[0]
						body = fmt.Sprintf("WORD $%#08x\n", word)
					}
					file, err := Parse(ArchARM64, "TEXT scalable_stack(SB),$0-0\n"+body+"RET\n")
					if err != nil {
						t.Fatal(err)
					}
					ctx := &arm64Ctx{blocks: arm64SplitBlocks(file.Funcs[0])}
					low, high, err := ctx.stackMovementRange()
					maximumScale := int64(256)
					if op == "ADDPL" {
						maximumScale = 32
					}
					wantLow, wantHigh := int64(0), int64(0)
					if immediate < 0 {
						wantLow = int64(immediate) * maximumScale
					} else {
						wantHigh = int64(immediate) * maximumScale
					}
					if err != nil || low != wantLow || high != wantHigh {
						t.Fatalf("range=[%d,%d] err=%v, want [%d,%d]", low, high, err, wantLow, wantHigh)
					}
				})
			}
		}
	}
}
