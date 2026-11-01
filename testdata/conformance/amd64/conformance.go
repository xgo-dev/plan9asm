//go:build amd64

package amd64conformance

func byteMemory(p *[4]byte, value byte)

func byteFlags(p *[4]byte, flags *[8]byte)

func unpackLowQWords(dst, src *[2]uint64)

func unpackDuplicateLowQWord(dst *[2]uint64)

func shiftLegacyThreeOperand(src, dst, amount uint32) uint32

func clearTopBit(value uint64) uint64

func doubleShift32(out *[8]uint32, src, dst, amount uint32)

func doubleShift64(out *[8]uint64, src, dst, amount uint64)

func scalarShiftRotateSemantics(out *[14]uint64, value, count uint64)

func incDecSemantics(out *[12]uint64, value uint64)

func scalarAddSubSemantics(out *[16]uint64, value, source uint64)

func compareExchangeScalarSemantics(out *[24]uint64, memory *[8]uint64, expected, desired uint64)

func compareExchangePairSemantics(out *[9]uint64, memory *uint64, expectedLow, expectedHigh, desiredLow, desiredHigh uint64)

func parallelBitSemantics(out *[8]uint64, mask, source uint64)

func bitTestRegisterSemantics(out *[24]uint64, value, index uint64)

func bitTestMemorySemantics(out *[12]byte, data *[9]uint64)

func packedWordMultiplyAddSemantics(out *[18]int32, a, b *[16]int16)

func packedUnsignedSignedByteMultiplyAddSemantics(out *[32]int16, signed *[32]int8, unsigned *[32]uint8)

// packedDotProductSemantics is executed by the translated LLVM runtime
// oracle; the native suite assembles the AVX-512 source without requiring the
// host CPU to execute it.
func packedDotProductSemantics(out *[64]int32, signedBytes *[64]int8, unsignedBytes *[64]uint8, wordsA, wordsB *[32]int16, accumulator *[16]int32)

func packedIntegerMinMaxSemantics(out *[1024]byte, a, b *[64]byte)

func packedWordMultiplySemantics(out *[64]uint16, a, b *[8]int16)

func packedFloatShuffleSemantics(out *[96]byte, a, b *[32]byte)

func inLaneFloatingPermuteSemantics(out *[144]byte, data, control *[32]byte)

func immediatePackedBlendSemantics(out *[240]byte, a, b *[32]byte)

func packedUnpackSemantics(out *[384]byte, a, b *[32]byte)

func qwordPermuteSemantics(out *[8]uint64, data *[4]uint64)

func qwordVariablePermuteSemantics(out *[8]uint64, data, control *[4]uint64)

func packedFloatMoveVEXSemantics(out *[128]byte, src *[32]byte)

func packedFloatMoveMaskSemantics(out *[688]byte, src, old *[64]byte)

func packedSignExtendMoveVEXSemantics(out *[288]byte, src *[32]byte)

func packedSignExtendMoveMaskSemantics(out *[768]byte, src, old *[64]byte)

func goHexVectorOps(out *[160]byte, a, b *[16]byte)

func goHexWordOps(value, count uint64) uint64

func packedArithmeticShift32(out *[8]int32, src *[4]int32)

func packedSubtractSemantics(out *[80]byte, a, b *[16]byte)

func expandedEcosystemVectors(out *[816]byte, a, b *[16]byte)

func parityBranches(value byte) uint64

func unorderedBranch(value float64) uint64

func packedFloatToDwordModes(out *[20]int32, src *[4]float32)

// sameWidthPackedConversionSemantics is exercised by the translated LLVM
// runtime oracle. The native Go suite still assembles it, but deliberately
// does not execute AVX-512 on hosts which may lack that ISA.
func sameWidthPackedConversionSemantics(out *[576]byte, ints *[16]int32, floats, squares32 *[16]float32, squares64 *[8]float64)

func packedSingleToDouble(out *[4]float64, src *[4]float32)

func conditionalMoveCodes(out, src *[16]uint64)

func fma3Semantics(out *[288]byte, a64, b64, c64 *[2]float64, a32, b32, c32 *[4]float32)

func binaryFloatingSemantics(out *[384]byte, a64, b64 *[2]float64, a32, b32 *[4]float32)

func horizontalFloatingSemantics(out *[192]byte, a32, b32 *[8]float32, a64, b64 *[4]float64)
