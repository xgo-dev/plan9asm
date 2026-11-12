package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func x86ImmediateCompareReference(a, b uint64, bits int, unsigned bool, predicate int) bool {
	if !unsigned {
		// A sign-bit bias compares arbitrary lane widths without relying on
		// the host integer's signed width or reproducing an LLVM predicate.
		a ^= uint64(1) << uint(bits-1)
		b ^= uint64(1) << uint(bits-1)
	}
	switch predicate & 7 {
	case 0:
		return a == b
	case 1:
		return a < b
	case 2:
		return a <= b
	case 3:
		return false
	case 4:
		return a != b
	case 5:
		return a >= b
	case 6:
		return a > b
	default:
		return true
	}
}

func TestX86ImmediatePackedComparePredicatesMasksAndOrder(t *testing.T) {
	for _, op := range x86ImmediateCompareResultMembers {
		bits := map[byte]int{'B': 8, 'W': 16, 'D': 32, 'Q': 64}[op[len(op)-1]]
		for _, width := range []int{16, 32, 64} {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			for _, predicate := range []int{0, 1, 2, 3, 4, 5, 6, 7, 255} {
				t.Run(fmt.Sprintf("%s/%s/%d", op, bank, predicate), func(t *testing.T) {
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-32\nMOVQ a+0(FP),AX\nMOVQ b+8(FP),BX\nMOVQ mask+16(FP),CX\n"+
						"MOVQ AX,X0\nMOVQ BX,X1\nVPBROADCASTQ X0,Z0\nVPBROADCASTQ X1,Z1\nKMOVQ CX,K2\n"+
						"%s $%d,%s1,%s0,K2,K2\nKMOVQ K2,AX\nMOVQ AX,ret+24(FP)\nRET\n", op, predicate, bank, bank)
					ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(a,b,mask uint64) uint64", "amd64", "x86_64-unknown-linux-gnu", "text")
					if err != nil {
						t.Fatal("complete predicate/mask source", err)
					}
					var calls, tupleType strings.Builder
					var want []uint64
					for _, values := range [][2]uint64{{0, 0}, {1, 2}, {^uint64(0), 0}, {0x8080808080808080, 0x7f7f7f7f7f7f7f7f}} {
						for _, mask := range []uint64{0, 1, 0x55aa55aa55aa55aa, ^uint64(0)} {
							index := len(want)
							fmt.Fprintf(&calls, " %%r%d = call i64 @Value(i64 %d,i64 %d,i64 %d)\n", index, values[0], values[1], mask)
							var expected uint64
							for lane := 0; lane < width*8/bits; lane++ {
								shift := uint(lane % (64 / bits) * bits)
								laneMask := ^uint64(0) >> uint(64-bits)
								a, b := values[0]>>shift&laneMask, values[1]>>shift&laneMask
								if mask&(uint64(1)<<uint(lane)) != 0 && x86ImmediateCompareReference(a, b, bits, strings.HasPrefix(op, "VPCMPU"), predicate) {
									expected |= uint64(1) << uint(lane)
								}
							}
							want = append(want, expected)
						}
					}
					// Keep a nonzero observer canary so an all-false result is
					// a ConstantStruct, not an uninspectable aggregate zero.
					want = append(want, 0x13579bdf)
					for range want {
						if tupleType.Len() != 0 {
							tupleType.WriteString(", ")
						}
						tupleType.WriteString("i64")
					}
					typ := "{ " + tupleType.String() + " }"
					previous := "poison"
					for index := range want {
						value := fmt.Sprintf("%%r%d", index)
						if index == len(want)-1 {
							value = "324508639"
						}
						fmt.Fprintf(&calls, " %%tuple%d = insertvalue %s %s, i64 %s, %d\n", index, typ, previous, value, index)
						previous = fmt.Sprintf("%%tuple%d", index)
					}
					probe := fmt.Sprintf("\ndefine %s @Probe() {\n%s ret %s %s\n}\n", typ, calls.String(), typ, previous)
					x86ScalarFPNamedConstantResult(t, ir+probe, "Probe", want)
				})
			}
		}
	}
}
