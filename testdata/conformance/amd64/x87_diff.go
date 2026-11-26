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
