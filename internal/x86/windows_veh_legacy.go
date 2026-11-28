package x86

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// Go 1.20 switches to g0 in assembly before calling the selected handler.
// These offsets are part of this exact 386 runtime layout. Match the expanded
// input; a different runtime layout must supply its own bridge.
var legacyVEHBody = vehBody(`MOVL ptrs+0(FP),CX
SUBL $40,SP
MOVL BX,28(SP)
MOVL BP,16(SP)
MOVL SI,20(SP)
MOVL DI,24(SP)
MOVL AX,SI
MOVL TLS,DX
CMPL DX,$0
JNE 3(PC)
MOVL $0,AX
JMP done
MOVL 0(DX)(TLS*1),DX
CMPL DX,$0
JNE 2(PC)
CALL runtime·badsignal2(SB)
MOVL DX,32(SP)
MOVL SP,36(SP)
MOVL 24(DX),BX
MOVL 0(BX),BX
CMPL DX,BX
JEQ g0
MOVL TLS,BP
MOVL BX,0(BP)(TLS*1)
MOVL 28(BX),DI
SUBL $40,DI
MOVL SP,36(DI)
MOVL DI,SP
g0:
MOVL 0(CX),BX
MOVL 4(CX),CX
MOVL BX,0(SP)
MOVL CX,4(SP)
MOVL DX,8(SP)
CALL SI
MOVL 12(SP),AX
MOVL 36(SP),SP
MOVL 32(SP),DX
MOVL TLS,BP
MOVL DX,0(BP)(TLS*1)
done:
MOVL 24(SP),DI
MOVL 20(SP),SI
MOVL 16(SP),BP
MOVL 28(SP),BX
ADDL $40,SP
BYTE $0xc2
WORD $4
RET`)

// Call the lowered cdecl handler with the three arguments at the native SP.
// Its i32 return is already in EAX. The exception path and the interrupted
// goroutine can have different stacks and TLS values.
func emitLegacyVEH(b *strings.Builder, sig asm.FuncSig, opt asm.Options) error {
	// A fallback 386 signature can expose the single foreign stack slot as i32.
	if sig.Ret != asm.Void || (len(sig.Args) != 0 && (len(sig.Args) != 1 || sig.Args[0] != asm.I32)) {
		return fmt.Errorf("%w: unexpected legacy VEH entry signature", asm.ErrProbeNeedsContext)
	}
	name := opt.ResolveSym("runtime·badsignal2")
	callee, ok := opt.Sigs[name]
	if !ok || len(callee.Args) != 0 || callee.Ret != asm.Void {
		return fmt.Errorf("%w: legacy VEH requires badsignal2() -> void", asm.ErrProbeNeedsContext)
	}
	code := strings.Join([]string{
		"movl 4(%esp), %ecx", "subl $$40, %esp",
		"movl %ebx, 28(%esp)", "movl %ebp, 16(%esp)", "movl %esi, 20(%esp)", "movl %edi, 24(%esp)", "movl %eax, %esi",
		"movl %fs:0x14, %edx", "testl %edx, %edx", "jnz 1f", "xorl %eax, %eax", "jmp 3f",
		"1: movl (%edx), %edx", "testl %edx, %edx", "jnz 2f", "movl %esp, %edi", "andl $$-16, %esp", "calll ${0:c}", "movl %edi, %esp",
		"2: movl %edx, 32(%esp)", "movl %esp, 36(%esp)", "movl 24(%edx), %ebx", "movl (%ebx), %ebx", "cmpl %ebx, %edx", "je 4f",
		"movl %fs:0x14, %ebp", "movl %ebx, (%ebp)", "movl 28(%ebx), %edi",
		"subl $$40, %edi", "movl %esp, 36(%edi)", "movl %edi, %esp",
		"4: movl (%ecx), %ebx", "movl 4(%ecx), %ecx", "movl %esp, %edi", "andl $$-16, %esp", "subl $$4, %esp",
		"pushl %edx", "pushl %ecx", "pushl %ebx", "calll *%esi", "movl %edi, %esp",
		"movl 36(%esp), %esp", "movl 32(%esp), %edx", "movl %fs:0x14, %ebp", "movl %edx, (%ebp)",
		"3: movl 24(%esp), %edi", "movl 20(%esp), %esi", "movl 16(%esp), %ebp", "movl 28(%esp), %ebx",
		"addl $$40, %esp", "retl $$4",
	}, "; ")
	params := make([]string, len(sig.Args))
	for i, ty := range sig.Args {
		params[i] = string(ty)
	}
	fmt.Fprintf(b, "define %s %s(%s) %s naked noinline {\n  call void asm sideeffect %q, \"i,~{memory}\"(ptr %s)\n  unreachable\n}\n", sig.Ret, asm.LLVMGlobal(sig.Name), strings.Join(params, ", "), sig.Attrs, code, asm.LLVMGlobal(asm.FuncSigSymbol(name, callee)))
	return nil
}
