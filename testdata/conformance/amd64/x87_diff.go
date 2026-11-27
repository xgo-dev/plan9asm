//go:build amd64

package amd64conformance

// Native amd64 Plan 9 x87 differential kernels compiled by BOTH Go's native
// amd64 assembler and plan9asm.TranslateGoModule -> LLVM 22 opt -O2 -> llc.

func diffX87FmovdStackDepths(out *[16]uint64)
func diffX87Constants(outF64 *[7]uint64, outRaw80 *[70]byte)
func diffX87BCD(inBCD *[10]byte, outBCD *[10]byte, outF64 *uint64)
func diffX87Arith80(a, b float64, out *[10]uint64)
func diffX87FUCOMI(a, b float64, out *[6]uint64)
func diffX87TopStatus(out *[12]uint64)
func diffX87Binary80Precision(outInt *[6]int64, outRaw80 *[60]byte)
func diffX87Exceptions(out *[10]uint64)
func diffX87ConstRoundingModes(outRaw80 *[280]byte)
func diffX87BCDOne(cw uint64, inRaw80 *[10]byte, outBCD *[10]byte, outSW *uint64)
func diffX87ConvInt(cw uint64, inRaw80 *[10]byte, outVals *[3]uint64, outSW *[3]uint64)
func diffX87ConvFloat(cw uint64, inRaw80 *[10]byte, outF32 *uint32, outF64 *uint64, outRnd80 *[10]byte, outSW *[3]uint64)
func diffX87ArithPC(cw uint64, aRaw80 *[10]byte, bRaw80 *[10]byte, outRaw80 *[50]byte, outSW *[5]uint64)
func diffX87Cmp(aRaw80 *[10]byte, bRaw80 *[10]byte, outCC *[5]uint64, outExc *[5]uint64)
func diffX87DynamicStackBranch(x uint64, out *[4]uint64)
func diffX87MMXAliasAndTop(x uint64, out *[8]uint64)
func diffX87ResetHelper()
func diffX87CallAndMergeAlias(x uint64, out *[6]uint64)
