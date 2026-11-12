package plan9asm

import "strings"

func emitARMPrelude(b *strings.Builder) {
	b.WriteString("declare i64 @syscall(i64, i64, i64, i64, i64, i64, i64)\n")
	b.WriteString("declare i32 @llvm.fshr.i32(i32, i32, i32)\n")
	b.WriteString("declare i32 @llvm.ctlz.i32(i32, i1)\n")
	b.WriteString("declare i32 @llvm.bitreverse.i32(i32)\n")
	b.WriteString("declare i32 @llvm.bswap.i32(i32)\n")
	b.WriteString("declare i16 @llvm.bswap.i16(i16)\n")
	for _, name := range []string{"ssat", "usat", "ssat16", "usat16"} {
		b.WriteString("declare i32 @llvm.arm." + name + "(i32, i32)\n")
	}
	b.WriteString("declare float @llvm.fabs.f32(float)\n")
	b.WriteString("declare double @llvm.fabs.f64(double)\n")
	b.WriteString("declare float @llvm.sqrt.f32(float)\n")
	b.WriteString("declare double @llvm.sqrt.f64(double)\n")
	b.WriteString("declare void @llvm.prefetch.p0(ptr, i32, i32, i32)\n")
	b.WriteString("\n")
}

func armLLVMBlockName(src string) string {
	return arm64LLVMBlockName(src)
}
