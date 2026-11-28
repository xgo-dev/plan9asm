//go:build arm64

package plan9asm

func nativeARM64Extr35(rm, rn uint64) uint64
func nativeARM64Extr0(rm, rn uint64) uint64
func nativeARM64Extr1(rm, rn uint64) uint64
func nativeARM64Extr63(rm, rn uint64) uint64
func nativeARM64ExtrW17(rm, rn uint32) uint32
func nativeARM64ExtrW0(rm, rn uint32) uint32

func nativeARM64ExtrReference(rm, rn uint64) (r35, r0, r1, r63 uint64, w17, w0 uint32, hasNative bool) {
	return nativeARM64Extr35(rm, rn),
		nativeARM64Extr0(rm, rn),
		nativeARM64Extr1(rm, rn),
		nativeARM64Extr63(rm, rn),
		nativeARM64ExtrW17(uint32(rm), uint32(rn)),
		nativeARM64ExtrW0(uint32(rm), uint32(rn)),
		true
}
