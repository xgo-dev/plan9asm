//go:build !llgo

package plan9asm

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// Exercise the A32 entry ABI across a dynamic shift and across the four-word
// AAPCS register boundary. The native caller sets carry immediately before BX.
func TestCrossLinuxRuntimeMatrixARMEntryTransfers(t *testing.T) {
	const triple = "armv7-unknown-linux-gnueabihf"
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	for _, op := range []string{"SLL", "SRL", "SRA"} {
		for _, layout := range []struct{ words, extra int }{{2, 0}, {4, 13 + 9}, {6, 13 + 9 + 23 + 41}} {
			count := layout.words
			name := fmt.Sprintf("shift%s%d", op, count)
			fmt.Fprintf(&source, "TEXT %s(SB),NOSPLIT,$0-%d\n", name, count*4+4)
			sig := FuncSig{Name: name, Ret: I32}
			for i := 0; i < count; i++ {
				sig.Args = append(sig.Args, I32)
				sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Index: i, Type: I32, Offset: int64(i * 4), Field: -1})
			}
			sig.Frame.Results = []FrameSlot{{Type: I32, Offset: int64(count * 4), Field: -1}}
			sigs[name] = sig
			fmt.Fprintf(&source, `MOVW x+0(FP),R0
MOVW n+4(FP),R1
%s R1,R0,R0
MOVW CPSR,R2
SRL $29,R2
AND $1,R2
EOR R2,R0
`, op)
			for i := 2; i < count; i++ {
				fmt.Fprintf(&source, "MOVW p%d+%d(FP),R2\nADD R2,R0\n", i, i*4)
			}
			fmt.Fprintf(&source, "MOVW R0,ret+%d(FP)\nRET\n", count*4)
			fmt.Fprintf(&declarations, "extern unsigned %s();\n", name)
			fmt.Fprintf(&checks, "    if (callWithC(%s, x, n, c) != ((ref%s(x,n) ^ c) + %d)) return %d;\n", name, op, layout.extra, count)
		}
	}
	source.WriteString("TEXT cpsrTail(SB),NOSPLIT,$0\nMOVW CPSR,R4\nMOVW $99,R5\nB callee6(SB)\n")
	sigs["cpsrTail"] = FuncSig{Args: []LLVMType{I32, I32, I32, I32}, Ret: I32}
	sigs["callee6"] = FuncSig{Args: []LLVMType{I32, I32, I32, I32, I32, I32}, Ret: I32}
	source.WriteString("TEXT cas<>(SB),NOSPLIT,$0\nMOVW $0xffff0fc0,R15\n")
	sigs["cas<>"] = FuncSig{Ret: Void}
	for _, op := range []string{"BL", "B", "RET"} {
		name := "cas" + op
		fmt.Fprintf(&source, `TEXT %s(SB),NOSPLIT,$0-16
MOVW old+0(FP),R0
MOVW next+4(FP),R1
MOVW p+8(FP),R2
%s cas<>(SB)
`, name, op)
		if op == "BL" {
			// Return 0 on success and nonzero on failure, using the helper carry.
			source.WriteString("MOVW $0,R3\nMOVW.CC $1,R3\nMOVW R3,ret+12(FP)\nRET\n")
		}
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{I32, I32, Ptr}, Ret: I32, Frame: FrameLayout{
			Params: []FrameSlot{{Type: I32, Field: -1}, {Type: I32, Index: 1, Offset: 4, Field: -1}, {Type: Ptr, Index: 2, Offset: 8, Field: -1}},
		}}
		if op == "BL" {
			sig := sigs[name]
			sig.Frame.Results = []FrameSlot{{Type: I32, Offset: 12, Field: -1}}
			sigs[name] = sig
		}
		fmt.Fprintf(&declarations, "extern int %s(int,int,int *);\n", name)
	}
	f, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(f, Options{Goarch: "arm", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	ir = runOptO2(t, ir)
	verifyLLVMWithTargetLLC(t, ir, triple)
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		return
	}
	main := declarations.String() + `
extern unsigned callWithC(unsigned (*)(), unsigned, unsigned, unsigned);
__asm__(".text\n.arm\n.global callWithC\n.type callWithC,%function\n"
 "callWithC:\n push {r4,lr}\n mov ip,r0\n mov r0,r1\n mov r1,r2\n cmp r3,#1\n"
 "mov r2,#13\n mov r3,#9\n sub sp,sp,#8\n mov r4,#23\n str r4,[sp]\n mov r4,#41\n str r4,[sp,#4]\n"
 "blx ip\n add sp,sp,#8\n pop {r4,pc}\n");
#define SHIFT_REF(name,op) static unsigned name(unsigned x, unsigned n) { unsigned out; __asm__(op " %0,%1,%2" : "=r"(out) : "r"(x),"r"(n)); return out; }
SHIFT_REF(refSLL,"lsl")
SHIFT_REF(refSRL,"lsr")
SHIFT_REF(refSRA,"asr")
extern unsigned cpsrTail(unsigned,unsigned,unsigned,unsigned);
unsigned callee6(unsigned a,unsigned b,unsigned c,unsigned d,unsigned cpsr,unsigned x) { return x; }
int main(void) {
 if (cpsrTail(0,0,0,0)!=99) return 45;
 const unsigned amounts[] = {0,1,31,32,33,255,256};
 for (unsigned i=0;i<sizeof(amounts)/sizeof(amounts[0]);i++) {
  unsigned x=0x87654321u, n=amounts[i];
  for (unsigned c=0;c<2;c++) {
` + checks.String() + `
  }
 }
 int (*cas[])(int,int,int *) = {casB, casBL, casRET};
 for (unsigned i=0; i<3; ++i) {
  int x=17;
  if (cas[i](13,42,&x)==0 || x!=17) return 20+i;
  if (cas[i](17,42,&x)!=0 || x!=42) return 30+i;
 }
 return 0;
}
`
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-marm"}, "arm_entry", triple, ir, main, []string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
}
