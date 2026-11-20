package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestAMD64UntrackedVectorLoadsProduceLLVMValues(t *testing.T) {
	c := &amd64Ctx{
		b:        &strings.Builder{},
		xRegSlot: map[int]string{},
		yRegSlot: map[int]string{},
		zRegSlot: map[int]string{},
	}

	for _, test := range []struct {
		name string
		load func(Reg) (string, error)
	}{
		{name: "X0", load: c.loadX},
		{name: "Y0", load: c.loadY},
		{name: "Z0", load: c.loadZ},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := test.load(Reg(test.name))
			if err != nil {
				t.Fatal(err)
			}
			if value != "zeroinitializer" {
				t.Fatalf("untracked register value = %q; want an untyped LLVM value", value)
			}
		})
	}

	for _, width := range []int{16, 32, 64} {
		value := c.bitcastVectorBytesToIntegerLanes(width, width/4, 32, "zeroinitializer")
		if value == "" {
			t.Fatal("bitcast produced no value")
		}
		want := fmt.Sprintf("bitcast <%d x i8> zeroinitializer to <%d x i32>", width, width/4)
		if !strings.Contains(c.b.String(), want) {
			t.Fatalf("missing valid LLVM bitcast %q in:\n%s", want, c.b.String())
		}
	}

	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	const triple = "x86_64-unknown-linux-gnu"
	ir := "target triple = \"" + triple + "\"\n" +
		"define void @untracked_vector_loads() {\nentry:\n" +
		c.b.String() + "  ret void\n}\n"
	compileLLVMToObject(t, llc, triple,
		"amd64-untracked-vector-loads.ll", "amd64-untracked-vector-loads.o", ir)
}
