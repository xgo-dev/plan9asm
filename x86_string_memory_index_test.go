package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func x86StringMemoryIndexFixture(quoted, crlf bool) (string, []string) {
	var ir strings.Builder
	ir.WriteString("; complete generated function-index fixture\n")
	names := make([]string, 212)
	for index := range names {
		name := fmt.Sprintf("segment%d", index)
		names[index] = name
		symbol := name
		if quoted {
			symbol = strconv.Quote(symbol)
		}
		fmt.Fprintf(&ir, "define i64 @%s(ptr %%source) {\nentry:\n", symbol)
		ir.WriteString(strings.Repeat("; retained complete-body payload, not another function definition\n", 32))
		fmt.Fprintf(&ir, "  %%loaded = load volatile i64, ptr %%source, align 1\n  %%mix = add i64 %%loaded, %d\n  ret i64 %%mix\n}\n", index)
	}
	source := ir.String()
	if crlf {
		source = strings.ReplaceAll(source, "\n", "\r\n")
	}
	return source, names
}

func TestX86StringMemoryFunctionIndexRetainsAllCompleteBodies(t *testing.T) {
	for _, quoted := range []bool{false, true} {
		for _, crlf := range []bool{false, true} {
			t.Run(fmt.Sprintf("quoted%t/CRLF%t", quoted, crlf), func(t *testing.T) {
				ir, names := x86StringMemoryIndexFixture(quoted, crlf)
				bodies := x86StringMemoryFunctions(t, ir, names)
				if len(bodies) != len(names) {
					t.Fatal("complete module index lost a function", len(bodies), len(names))
				}
				for index, name := range names {
					body := bodies[name]
					if !strings.Contains(body, fmt.Sprintf("add i64 %%loaded, %d\n", index)) &&
						!strings.Contains(body, fmt.Sprintf("add i64 %%loaded, %d\r\n", index)) ||
						strings.Count(body, "load volatile i64") != 1 ||
						!strings.Contains(body, "ret i64 %mix") {
						t.Fatal("index selected, cropped or mixed a different function", name)
					}
				}
			})
		}
	}
}

func TestX86StringMemoryFunctionIndexAvoidsPerFunctionMatcherAllocations(t *testing.T) {
	ir, names := x86StringMemoryIndexFixture(false, false)
	var bodies map[string]string
	allocations := testing.AllocsPerRun(1, func() {
		bodies = x86StringMemoryFunctions(t, ir, names)
	})
	// Leave room for SDK-specific string/interface overhead, not compilation
	// of a fresh whole-module matcher for each requested function.
	budget := float64(16*len(names) + 256)
	if len(bodies) != len(names) || allocations > budget {
		t.Fatalf("whole-module index allocations=%g, budget=%g, functions=%d", allocations, budget, len(bodies))
	}
}

func BenchmarkX86StringMemoryWholeModuleIndex(b *testing.B) {
	ir, names := x86StringMemoryIndexFixture(false, false)
	b.Logf("functions=%d bytes=%d fixture-sha256=%x", len(names), len(ir), sha256.Sum256([]byte(ir)))
	b.SetBytes(int64(len(ir)))
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if got := x86StringMemoryFunctions(b, ir, names); len(got) != len(names) {
			b.Fatal("benchmark omitted complete functions")
		}
	}
}
