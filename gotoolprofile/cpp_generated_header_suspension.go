package gotoolprofile

import "fmt"

// Only the actual active include callback can construct this requirement.
// Candidate resources, malformed controls and unknown includes do not suspend
// planning, and no successful execution or header permission is implied.
type cppGeneratedHeaderRequirement struct {
	assembly string
	operand  string
}

func (e *cppGeneratedHeaderRequirement) Error() string {
	return fmt.Sprintf("active CPP operand has no independently registered original: %s", e.operand)
}

func (e *cppGeneratedHeaderRequirement) CPPGeneratedHeaderRequirement() (assembly, operand string) {
	return e.assembly, e.operand
}

// CPPOriginalNeedsGeneratedHeader accepts only a single wrapped callback
// requirement for this exact assembly. A joined or unrelated error must never
// be swallowed while the producer obtains its actual compiler header.
func CPPOriginalNeedsGeneratedHeader(err error, assembly string) bool {
	for depth := 0; err != nil && depth < 32; depth++ {
		if requirement, ok := err.(*cppGeneratedHeaderRequirement); ok {
			return requirement.assembly == assembly && requirement.operand == "go_asm.h"
		}
		wrapped, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = wrapped.Unwrap()
	}
	return false
}
