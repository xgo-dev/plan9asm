//go:build !arm64

package plan9asm

func nativeARM64ExtrReference(rm, rn uint64) (r35, r0, r1, r63 uint64, w17, w0 uint32, hasNative bool) {
	return 0, 0, 0, 0, 0, 0, false
}
