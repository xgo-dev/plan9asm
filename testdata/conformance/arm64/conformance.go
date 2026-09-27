//go:build arm64

package arm64conformance

func families(out *[76]uint64, data *[8]uint64)

func scalarFloatSquareRoots(out *[16]byte)

func fusedMultiplyAddSemantics(out *[48]byte)

func pairedAtomicSemantics(out *[23]uint64, data *[9]uint64)

func vectorPermuteSemantics(out *[96]byte, n *[16]byte, m *[16]byte)

func vectorWideningShiftSemantics(out *[128]byte, source *[16]byte)

func scalarExtendSemantics(out *[10]uint64, value uint64)

func vectorCountBitsSemantics(out *[32]byte, source *[16]byte)

func unsignedWideningAddSemantics(out *[96]byte, narrow *[16]byte, addend *[16]byte)
