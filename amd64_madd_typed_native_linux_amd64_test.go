package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// The filename is the Linux/amd64 build role and the cross-runtime prefix is
// selected by required CI. Native AVX must be available: no Skip, Rosetta
// fallback or object-only substitution satisfies this original-Go axis.
func TestCrossLinuxRuntimeMatrixX86MADDTypedOriginalVEX(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	execution.requireAVX(t)
	var declarations, assembly, table strings.Builder
	declarations.WriteString("package oracle\n")
	count := 0
	for _, row := range x86MADDOracleRows() {
		if row.legacy || row.masking != 0 || row.width > 32 {
			continue
		}
		name := fmt.Sprintf("V%d", count)
		count++
		fmt.Fprintf(&declarations, "func %s(out *[48]byte,a,b *[64]byte,flags uint64,csr uint32)\n", name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$8-36\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),CX\nMOVQ b+16(FP),DX\nSTMXCSR saved-4(SP)\nLDMXCSR csr+32(FP)\nVMOVDQU (CX),Y0\nVMOVDQU (DX),Y1\nVMOVDQU (DX),Y2\nPUSHQ flags+24(FP)\nPOPFQ\n", name)
		instruction, destination := row.instruction()
		fmt.Fprintf(&assembly, "%s\nVMOVDQU Y%s,(AX)\nPUSHFQ\nPOPQ R10\nMOVQ R10,32(AX)\nSTMXCSR 40(AX)\nVZEROUPPER\nLDMXCSR saved-4(SP)\nRET\n", instruction, destination[1:])
		fmt.Fprintf(&table, "{%s,%d,%d},\n", name, row.width, row.inputBytes)
	}
	tests := `package oracle
import (
 "testing"
 "encoding/binary"
 "runtime"
 "unsafe"
)

var cases = []struct {
 run func(*[48]byte, *[64]byte, *[64]byte, uint64, uint32)
 width, bytes int
}{
` + table.String() + `}

func TestOriginal(t *testing.T) {
 runtime.LockOSThread()
 defer runtime.UnlockOSThread()
 edges := [...]int32{0, 1, -1, 127, -128, 255, 256, -257, 32767, -32768, 16384, -16384}
 profiles := []uint32{0x1f80, 0x3fc1, 0x5f82, 0x9fe5}
 observations := 0
 for row, entry := range cases {
  for sample := 0; sample < 32; sample++ {
   for _, csr := range profiles {
    for seed := 0; seed < 2; seed++ {
     var a, b [64]byte
     var out, want [50]byte
     for i := 0; i < 64; i += entry.bytes {
      x, y := edges[(sample+i*3)%len(edges)], edges[(sample+7+i*3)%len(edges)]
      a[i], b[i] = byte(x), byte(y)
      if entry.bytes == 2 {
       a[i+1], b[i+1] = byte(uint32(x)>>8), byte(uint32(y)>>8)
      }
     }
     if entry.bytes == 2 && sample == 0 {
      for i := 0; i < 64; i += 2 {
       a[i] = 0
       b[i] = 0
       a[i+1] = 0x80
       b[i+1] = 0x80
      }
     }
     if entry.bytes == 1 && sample < 2 {
      for i := range a {
       a[i] = 0x7f
       if sample == 1 {
        a[i] = 0x80
       }
       b[i] = 0xff
      }
     }
     beforeA, beforeB := a, b
     for i := range out {
      out[i] = 0xc3
      want[i] = 0xc3
     }

     flags := uint64(2)
     if seed != 0 {
      flags |= 0x8d5
     }
     entry.run((*[48]byte)(unsafe.Pointer(&out[1])), &a, &b, flags, csr)
     for i := 0; i < 32; i++ {
      want[i+1] = 0
     }
     for i := 0; i < entry.width; i += entry.bytes * 2 {
      var sum int64
      if entry.bytes == 2 {
       sum = int64(int16(binary.LittleEndian.Uint16(a[i:]))) * int64(int16(binary.LittleEndian.Uint16(b[i:]))) +
             int64(int16(binary.LittleEndian.Uint16(a[i+2:]))) * int64(int16(binary.LittleEndian.Uint16(b[i+2:])))
      } else {
       sum = int64(int8(a[i]))*int64(b[i]) + int64(int8(a[i+1]))*int64(b[i+1])
       if sum < -32768 {
        sum = -32768
       }
       if sum > 32767 {
        sum = 32767
       }
      }
      for j := 0; j < entry.bytes * 2; j++ {
       want[i+j+1] = byte(uint32(sum) >> uint(j*8))
      }
     }

     actualFlags := binary.LittleEndian.Uint64(out[33:41])
     actualCSR := binary.LittleEndian.Uint32(out[41:45])
     copy(want[33:45], out[33:45])
     observations++
     if out != want || a != beforeA || b != beforeB || actualFlags&0x8d5 != flags&0x8d5 || actualCSR != csr {
      t.Fatalf("original VEX MADD row%d sample%d flags%x CSR%x got%x want%x",
               row, sample, actualFlags, actualCSR, out, want)
     }
    }
   }
  }
 }
 if observations != len(cases)*32*4*2 {
  t.Fatal("incomplete original VEX matrix", observations)
 }
}
`
	x86WordMultiplyRunOriginalGo(t, execution, declarations.String(), assembly.String(), tests)
	t.Logf("%d original VEX X/Y kernels, register/memory/all destination aliases ×32 samples ×4 CSR profiles ×2 six-flag seeds; full Y upper-zero/input/canaries. No original EVEX execution claim.", count)
}
