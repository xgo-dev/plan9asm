package arm

import (
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

func EmitPrelude(b *strings.Builder) {
	b.WriteString("declare i32 @llvm.fshr.i32(i32, i32, i32)\n")
	b.WriteString("declare i32 @llvm.ctlz.i32(i32, i1)\n")
	b.WriteString("\n")
}

func armLLVMBlockName(src string) string {
	return asm.LLVMBlockName(src)
}
