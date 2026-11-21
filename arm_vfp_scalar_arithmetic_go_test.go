package plan9asm

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestARMScalarFloatArithmeticOfficialGoWords(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/asm/testdata/armv6.s"))
	if err != nil {
		t.Fatal(err)
	}
	// Include both plan9 register arities, predication and every classic
	// and fused accumulator direction from Go's original encoding tests.
	pattern := regexp.MustCompile(`(?m)^\s*((?:ADD|SUB|MUL|NMUL|DIV|F?N?MUL[AS])[FD](?:\.[A-Z]+)?[ \t]+[^/\n]+?)\s*//\s*([0-9a-f]{8})\s*$`)
	rows := pattern.FindAllStringSubmatch(string(data), -1)
	if len(rows) != 36 {
		t.Fatalf("Go scalar VFP arithmetic corpus has %d rows, want 36", len(rows))
	}
	const prefix = "TEXT arithmetic(SB),4,$0-0\n"
	var named, raw strings.Builder
	named.WriteString(prefix)
	raw.WriteString(prefix)
	for _, row := range rows {
		encoded, err := hex.DecodeString(row[2])
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&named, "CMP R0,R1\n%s\n", row[1])
		fmt.Fprintf(&raw, "CMP R0,R1\nWORD $%#08x\n", binary.LittleEndian.Uint32(encoded))
	}
	named.WriteString("RET\n")
	raw.WriteString("RET\n")
	sigs := map[string]FuncSig{"arithmetic": {Name: "arithmetic", Ret: Void}}
	for _, row := range []struct{ name, source string }{{"named", named.String()}, {"word", raw.String()}} {
		t.Run(row.name, func(t *testing.T) {
			requireARMGoAssemblerResult(t, row.source, true)
			ir := translateARMCompleteForms(t, row.source, sigs)
			for _, call := range []string{"call float @llvm.fma.f32", "call double @llvm.fma.f64"} {
				if count := strings.Count(ir, call); count != 4 {
					t.Errorf("got %d calls to %q, want four", count, call)
				}
			}
		})
	}
}
func TestCrossLinuxRuntimeMatrixARMVFPAccumulateRounding(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	// Words from the official Go armv6.s VFP corpus. The products below
	// round to one on their own but leave a nonzero fused residual.
	rows := []struct {
		name string
		word uint32
	}{
		{"FMULAF", 0xeea67a05}, {"FMULAD", 0xeea67b05},
		{"FMULSF", 0xeea67a45}, {"FMULSD", 0xeea67b45},
		{"FNMULAF", 0xee967a45}, {"FNMULAD", 0xee967b45},
		{"FNMULSF", 0xee967a05}, {"FNMULSD", 0xee967b05},
		{"NMULAF", 0xee167a45}, {"NMULAD", 0xee167b45},
	}
	var assembly strings.Builder
	assembly.WriteString("TEXT oracle(SB),4,$0-4\nMOVW out+0(FP), R4\n")
	var expected []string
	for _, row := range rows {
		move, exponent := "MOVF", 13
		if strings.HasSuffix(row.name, "D") {
			move, exponent = "MOVD", 28
		}
		accumulator := -1.0
		if strings.Contains(row.name, "MULS") {
			accumulator = 1
		}
		delta := math.Ldexp(1, -exponent)
		var residual float64
		if strings.HasPrefix(row.name, "F") {
			residual = delta * delta
			if strings.HasPrefix(row.name, "FMULA") || strings.HasPrefix(row.name, "FNMULS") {
				residual = -residual
			}
		}
		want := math.Float64bits(residual)
		if move == "MOVF" {
			want = uint64(math.Float32bits(float32(residual)))
		}
		for _, instruction := range []string{row.name + " F5, F6, F7", fmt.Sprintf("WORD $%#08x", row.word)} {
			fmt.Fprintf(&assembly, "%s $%.18f,F5\n%s $%.18f,F6\n%s $%.1f,F7\n",
				move, 1+delta, move, 1-delta, move, accumulator)
			fmt.Fprintf(&assembly, "%s\n%s F7,%d(R4)\n", instruction, move, len(expected)*8)
			expected = append(expected, fmt.Sprintf("0x%016x", want))
		}
	}
	assembly.WriteString("RET\n")
	want := strings.Join(expected, ", ")
	runARMGoSourceOracle(t, assembly.String(), fmt.Sprintf(`package main
import "fmt"
func oracle(out *[%d]uint64)
func main() {
	var got [%d]uint64
	oracle(&got)
	want := [...]uint64{%s}
	if got != want { panic(fmt.Sprintf("VFP accumulator bits got %%#x, want %%#x", got, want)) }
	fmt.Println("original Go VFP accumulation matches")
}
`, len(expected), len(expected), want))
	sigs := map[string]FuncSig{"oracle": {
		Name: "oracle", Args: []LLVMType{Ptr}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Index: 0, Type: Ptr, Field: -1}}},
	}}
	ir := translateARMCompleteForms(t, assembly.String(), sigs)
	mainC := fmt.Sprintf(`
#include <stdint.h>
#include <stdio.h>
extern void oracle(uint64_t*);
int main(void) {
	uint64_t got[%d] = {0}, want[] = {%s};
	oracle(got);
	for (unsigned i = 0; i < sizeof(want)/sizeof(want[0]); i++) {
		if (got[i] == want[i]) continue;
		fprintf(stderr, "VFP case %%u got %%llx, want %%llx\n", i,
		        (unsigned long long)got[i], (unsigned long long)want[i]);
		return 1;
	}
	return 0;
}
`, len(expected), want)
	for _, optimization := range []int{0, 2} {
		t.Run(fmt.Sprintf("O%d", optimization), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"},
				"vfp_accumulate_rounding", "armv7-unknown-linux-gnueabihf", ir, mainC,
				[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"}, optimization)
		})
	}
}
