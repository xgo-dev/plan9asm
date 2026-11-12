package plan9asm

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/nativeoracle"
)

const amd64VirtualBoolDeclarations = `package virtualargs
type Flag bool
type Pair struct { First, Second bool }
func Identity(a bool) bool
func Invert(a bool) bool
func Widen(a bool) uint64
func Second(a, b bool) bool
func Named(a Flag) Flag
func PairSecond(a Pair) bool
`

const amd64VirtualBoolSource = `
TEXT ·Identity<ABIInternal>(SB),4,$0
	RET
TEXT ·Invert<ABIInternal>(SB),4,$0
	XORB $1, AX
	RET
TEXT ·Widen<ABIInternal>(SB),4,$0
	MOVBQZX AL, AX
	RET
TEXT ·Second<ABIInternal>(SB),4,$0
	MOVB BL, AL
	RET
TEXT ·Named<ABIInternal>(SB),4,$0
	RET
TEXT ·PairSecond<ABIInternal>(SB),4,$0
	MOVB BL, AL
	RET
`

// These wrappers call the unchanged grouped LLVM declarations. Their i1
// inputs represent Go bool values, not arbitrary native bytes or a stock-Go
// register ABI. Returning i64 avoids depending on the host C bool ABI.
func amd64VirtualBoolWrappers() string {
	var wrappers strings.Builder
	for _, name := range []string{"Identity", "Invert", "Widen", "Second", "Named", "PairSecond"} {
		fmt.Fprintf(&wrappers, "\ndefine i64 @bool_%s(i32 %%a, i32 %%b) {\n", name)
		wrappers.WriteString("  %x = icmp ne i32 %a, 0\n  %y = icmp ne i32 %b, 0\n")
		arguments, result := "i1 %x", "i1"
		switch name {
		case "Second":
			arguments = "i1 %x, i1 %y"
		case "PairSecond":
			wrappers.WriteString("  %first = insertvalue { i1, i1 } poison, i1 %x, 0\n")
			wrappers.WriteString("  %pair = insertvalue { i1, i1 } %first, i1 %y, 1\n")
			arguments = "{ i1, i1 } %pair"
		case "Widen":
			result = "i64"
		}
		fmt.Fprintf(&wrappers, "  %%value = call %s @%q(%s)\n", result, amd64VirtualArgumentsPackage+"."+name, arguments)
		if result == "i1" {
			wrappers.WriteString("  %wide = zext i1 %value to i64\n  ret i64 %wide\n}\n")
		} else {
			wrappers.WriteString("  ret i64 %value\n}\n")
		}
	}
	return wrappers.String()
}

func amd64VirtualBoolIR(t *testing.T, triple, api string) string {
	t.Helper()
	pkg := mustGoPackage(t, amd64VirtualArgumentsPackage, amd64VirtualBoolDeclarations)
	ir, err := amd64VirtualArgumentsRequest(t, pkg, []byte(amd64VirtualBoolSource), triple, api, false, nil)
	if err != nil || strings.Count(ir, "define ") != 6 {
		t.Fatal("complete typed boolean input family was not translated", err, ir)
	}
	return ir + amd64VirtualBoolWrappers()
}

func TestGoModuleAMD64VirtualBoolObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("typed boolean objects require LLVM22 llc")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		for _, api := range []string{"public", "owned-context"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				x86PackedStringCompileObject(t, llc, triple, amd64VirtualBoolIR(t, triple, api), "-O2")
			})
		}
	}
}

func TestGoModuleAMD64VirtualBoolPortableValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("typed boolean execution requires LLVM22 llc/clang")
	}
	const driver = `#include <stdint.h>
extern uint64_t bool_Identity(uint32_t,uint32_t), bool_Invert(uint32_t,uint32_t);
extern uint64_t bool_Widen(uint32_t,uint32_t), bool_Second(uint32_t,uint32_t);
extern uint64_t bool_Named(uint32_t,uint32_t), bool_PairSecond(uint32_t,uint32_t);
int main(void) {
    for (uint32_t a = 0; a != 2; ++a) {
        for (uint32_t b = 0; b != 2; ++b) {
            if (bool_Identity(a,b) != a || bool_Invert(a,b) != 1-a ||
                bool_Widen(a,b) != a || bool_Second(a,b) != b ||
                bool_Named(a,b) != a || bool_PairSecond(a,b) != b) return 1;
        }
    }
    return 0;
}
`
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	compiler := []string{clang}
	if runtime.GOOS == "darwin" {
		ctx, cancel := runtimeOracleStageContext(t)
		flags, err := nativeoracle.DarwinClangFlags(ctx, os.Environ())
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		compiler = append(compiler, flags...)
	}
	for _, api := range []string{"public", "owned-context"} {
		ir := amd64VirtualBoolIR(t, triple, api)
		for _, optimized := range []bool{false, true} {
			input := ir
			if optimized {
				input = x86UndefinedTrapOptimizedIR(t, input)
			}
			for _, level := range []int{0, 2} {
				t.Run(fmt.Sprintf("%s/IR_O2=%t/backendO%d", api, optimized, level), func(t *testing.T) {
					compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "virtual-bool", triple, input, driver, nil, level)
				})
			}
		}
	}
}

func TestGoModuleAMD64VirtualBoolKeepsOtherStateUnknown(t *testing.T) {
	for _, row := range []struct{ name, declaration, body string }{
		{"upper-input", "func Entry(a bool) uint64", "MOVQ AX,AX"},
		{"upper-named-input", "type Flag bool\nfunc Entry(a Flag) uint64", "MOVQ AX,AX"},
		{"upper-second-input", "func Entry(a,b bool) uint64", "MOVQ BX,AX"},
		{"aggregate-result", "func Entry(a bool) (bool,bool)", "MOVB $1,AX\nMOVB $1,BX"},
		{"noncanonical-result", "func Entry(a bool) bool", "MOVB $2,AX"},
		{"unknown-register", "func Entry(a bool) bool", "MOVB DL,AL"},
	} {
		for _, api := range []string{"public", "owned-context"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				pkg := mustGoPackage(t, amd64VirtualArgumentsPackage, "package virtualargs\n"+row.declaration+"\n")
				source := []byte("TEXT ·Entry<ABIInternal>(SB),4,$0\n" + row.body + "\nRET\n")
				ir, err := amd64VirtualArgumentsRequest(t, pkg, source, "x86_64-unknown-linux-gnu", api, false, nil)
				amd64VirtualArgumentsRequireContext(t, ir, err)
			})
		}
	}
}
