//go:build amd64

package amd64conformance

func diffCPUID(leaf, subleaf uint32, out *[4]uint32)

func diffArith64(a, b uint64, out *[20]uint64)

func diffArithWidths(a, b uint64, out *[24]uint64)

func diffMulDiv(a, b uint64, out *[16]uint64)

func diffShiftsRotates(val, cnt uint64, out *[24]uint64)

func diffDoubleShift16(dst, src, cnt uint64, out *[16]uint64)

func diffDoubleShift3264(dst, src, cnt uint64, out *[16]uint64)

func diffFlagsSaveRestore(a, b uint64, out *[16]uint64)

func diffPushfqRawIF() uint64

func diffBitCond(a, b uint64, out *[16]uint64)

func diffAtomicAndString(buf *[64]byte, val uint64, out *[16]uint64)

func diffZeroArgCallee() int64

func diffZeroArgCaller() int64

func diffADX(a, b uint64, out *[8]uint64)

func diffPCMPESTRI0C(needle, hay *[16]byte, nLen, hLen uint64, out *[8]uint64)

func diffSHA256Block(state *[8]uint32, block *[64]byte)

func diffSHA1Block(state *[5]uint32, block *[64]byte)
