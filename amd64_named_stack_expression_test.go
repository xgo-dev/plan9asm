package plan9asm

import (
	"strings"
	"testing"
)

func TestAMD64NamedStackConstantExpressions(t *testing.T) {
	const source = `TEXT namedStackExpressions(SB),$64-0
	MOVL AX, tmpdig-(0*4)(SP)
	MOVL BX, tmpdig-(1*4)(SP)
	ADDL tmpdig-(0*4)(SP), AX
	ADDL tmpdig-(1*4)(SP), BX
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	if got := file.Funcs[0].Instrs[1].Args[1]; got.Kind != OpMem || got.Mem.Off != 0 {
		t.Fatalf("first named stack slot parsed as %+v, want offset 0 memory", got)
	}
	if got := file.Funcs[0].Instrs[2].Args[1]; got.Kind != OpMem || got.Mem.Off != -4 {
		t.Fatalf("second named stack slot parsed as %+v, want offset -4 memory", got)
	}
	ll, err := Translate(file, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"namedStackExpressions": {Name: "namedStackExpressions", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, "add i32") {
		t.Fatalf("named stack loads omitted from IR:\n%s", ll)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "named-stack-expressions.ll", "named-stack-expressions.o", ll)
}

func TestNamedStackConstantOffsetRejectsUnresolvedExpressions(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		want   int64
		ok     bool
	}{
		{prefix: "tmpdig-(7*4)", want: -28, ok: true},
		{prefix: "tmpdig+(2<<3)", want: 16, ok: true},
		{prefix: "tmpdig-(unknown*4)"},
		{prefix: "tmpdig-(4/0)"},
		{prefix: "tmp-dig-(1*4)"},
	} {
		got, ok := parseNamedStackConstantOffset(tc.prefix)
		if ok != tc.ok || ok && got != tc.want {
			t.Errorf("parseNamedStackConstantOffset(%q) = %d, %v; want %d, %v", tc.prefix, got, ok, tc.want, tc.ok)
		}
	}
}
