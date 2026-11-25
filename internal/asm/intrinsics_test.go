package asm

import (
	"strings"
	"testing"
)

func TestCollectMissingLLVMIntrinsicDecls(t *testing.T) {
	prelude := "declare <2 x i64> @llvm.x86.pclmulqdq(<2 x i64>, <2 x i64>, i8)\n"
	body := `
define void @f() {
entry:
  %a = call i32 @llvm.cttz.i32(i32 4, i1 false)
  %b = call i32 @llvm.cttz.i32(i32 %a, i1 true)
  %c = call <16 x i8> @llvm.sadd.sat.v16i8(<16 x i8> zeroinitializer, <16 x i8> zeroinitializer)
  %d = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> zeroinitializer, <2 x i64> zeroinitializer, i8 1)
  %e = call { i64, i32 } @llvm.x86.rdrand.64()
  %g = call double @llvm.fma.f64(double 1.0, double 2.0, double 3.0)
  %h = call [2 x i32] @llvm.fake.arr([2 x i32] zeroinitializer, ptr null)
  %k = call { { i32, i32 }, i1 } @llvm.fake.nested({ { i32, i32 }, i1 } zeroinitializer)
  call void @llvm.aarch64.hint(i32 7)
  ret void
}
`
	declsText := strings.TrimSpace(CollectMissingLLVMIntrinsicDecls(prelude, body))
	decls := strings.Split(declsText, "\n")
	want := []string{
		"declare void @llvm.aarch64.hint(i32)",
		"declare i32 @llvm.cttz.i32(i32, i1)",
		"declare [2 x i32] @llvm.fake.arr([2 x i32], ptr)",
		"declare { { i32, i32 }, i1 } @llvm.fake.nested({ { i32, i32 }, i1 })",
		"declare double @llvm.fma.f64(double, double, double)",
		"declare <16 x i8> @llvm.sadd.sat.v16i8(<16 x i8>, <16 x i8>)",
		"declare { i64, i32 } @llvm.x86.rdrand.64()",
	}
	if len(decls) != len(want) {
		t.Fatalf("got %d decls:\n%s\nwant %d:\n%s", len(decls), declsText, len(want), strings.Join(want, "\n"))
	}
	for i := range want {
		if decls[i] != want[i] {
			t.Errorf("decl[%d] = %q, want %q", i, decls[i], want[i])
		}
	}
	if strings.Contains(declsText, "pclmulqdq") {
		t.Errorf("unexpected duplicate decl for prelude intrinsic: %s", declsText)
	}
	if got := CollectMissingLLVMIntrinsicDecls("", "define void @empty() { ret void }"); got != "" {
		t.Errorf("expected empty decls, got %q", got)
	}
}
