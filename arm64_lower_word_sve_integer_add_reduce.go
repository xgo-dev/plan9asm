package plan9asm

import "fmt"

type arm64RawSVEIntegerAddReduction struct {
	spec        arm64SVEAddReductionSpec
	form        arm64SVEAddReductionForm
	destination Reg
}

// SADDV and UADDV share the predicated integer-add reduction encoding.
// Signed D is reserved; unsigned D is valid. The remaining variable fields
// are the scalar destination, predicate, and scalable source registers.
func decodeARM64RawSVEIntegerAddReduction(word uint32) (arm64RawSVEIntegerAddReduction, bool) {
	if word&0xff3ee000 != 0x04002000 {
		return arm64RawSVEIntegerAddReduction{}, false
	}

	size := int(word>>22) & 3
	unsigned := word&(1<<16) != 0
	if size == 3 && !unsigned {
		return arm64RawSVEIntegerAddReduction{}, false
	}

	kind := arm64SVESignedAddReduce
	if unsigned {
		kind = arm64SVEUnsignedAddReduce
	}
	destination := int(word) & 31
	return arm64RawSVEIntegerAddReduction{
		spec: arm64SVEAddReductionSpec{kind: kind},
		form: arm64SVEAddReductionForm{
			elementBits: 8 << size,
			source:      int(word>>5) & 31,
			predicate:   int(word>>10) & 7,
			destination: destination,
		},
		destination: Reg(fmt.Sprintf("V%d", destination)),
	}, true
}
