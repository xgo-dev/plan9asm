package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// This is a required Linux/amd64 runtime axis selected by the cross-runtime
// TestCrossLinuxRuntimeMatrix prefix. Missing AVX/AVX2 is a failure, not a skip.
// Darwin/Rosetta object/software results cannot satisfy this original-Go axis.
func TestCrossLinuxRuntimeMatrixX86PackedWordMultiplyOriginalVEX(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	execution.requireAVX(t)
	var declarations, assembly, tests strings.Builder
	declarations.WriteString("package oracle\nfunc ReadCSR() uint32\nfunc SetCSR(value uint32)\n")
	assembly.WriteString("TEXT ·ReadCSR(SB),4,$0-4\nSTMXCSR ret0+0(FP)\nRET\nTEXT ·SetCSR(SB),4,$0-4\nLDMXCSR value+0(FP)\nRET\n")
	tests.WriteString(x86WordMultiplyOriginalGoTestHeader)
	count := 0
	for _, name := range x86WordMultiplyNames[4:] {
		for _, width := range []int{16, 32} {
			bank := map[int]string{16: "X", 32: "Y"}[width]
			for _, memory := range []bool{false, true} {
				for destination := 0; destination < 3; destination++ {
					fn := fmt.Sprintf("V%d", count)
					count++
					source := bank + "0"
					if memory {
						source = "(DI)"
					}
					fmt.Fprintf(&declarations, "func %s(out,a,b *[64]byte,flags *uint64,csr *uint32,seed uint64,profile uint32)\n", fn)
					fmt.Fprintf(&assembly, `TEXT ·%s(SB),4,$0-56
MOVQ out+0(FP),DX
MOVQ a+8(FP),DI
MOVQ b+16(FP),SI
MOVQ flags+24(FP),CX
MOVQ csr+32(FP),BX
VMOVDQU (DI),Y0
VMOVDQU (SI),Y1
VMOVDQU (SI),Y2
LDMXCSR profile+48(FP)
PUSHQ seed+40(FP)
POPFQ
%s %s,%s1,%s%d
VMOVDQU Y%d,(DX)
PUSHFQ
POPQ AX
MOVQ AX,(CX)
STMXCSR (BX)
VZEROUPPER
RET
`, fn, name, source, bank, bank, destination, destination)
					fmt.Fprintf(&tests, `{
 for i:=range out {out[i]=0xc3}
 flags:=struct{before,value,after uint64}{0x1122334455667788,0,0x8877665544332211}
 csr:=struct{before,value,after uint32}{0x11223344,0,0x44332211}
 %s(op,ap,bp,&flags.value,&csr.value,seed,profile)
 if flags.value&0x8d5!=seed||flags.before!=0x1122334455667788||flags.after!=0x8877665544332211||csr.value!=profile||csr.before!=0x11223344||csr.after!=0x44332211||ReadCSR()!=profile||a!=originalA||b!=originalB {t.Fatalf("%s state/canary sample%%d",sample)}
 for i,value:=range out {
  want:=byte(0xc3)
  if i>=offset&&i<offset+32 {
   index:=i-offset;want=0
   if index<%d {
    ai:=index&^1
    x,y:=uint16(ap[ai])|uint16(ap[ai+1])<<8,uint16(bp[ai])|uint16(bp[ai+1])<<8
    want=byte(product(x,y,%d)>>uint((index&1)*8))
   }
  }
  if value!=want {t.Fatalf("%s full-byte/upper-zero/canary sample%%d byte%%d got%%x want%%x",sample,i,value,want)}
 }
}
`, fn, fn, width, x86WordMultiplyReferenceMode(name), fn)
				}
			}
		}
	}
	tests.WriteString("}}\n}\n")
	x86WordMultiplyRunOriginalGo(t, execution, declarations.String(), assembly.String(), tests.String())
	t.Logf("%d actual original VEX X/Y kernels ×257 samples ×2 six-flag seeds; register/memory and all destination aliases, full Y upper-zero/MXCSR/input/canaries. No original EVEX execution claim.", count)
}
