package plan9asm

import "fmt"

type arm64StreamingState uint8

const (
	arm64StreamingStateBoth arm64StreamingState = iota
	arm64StreamingStateSM
	arm64StreamingStateZA
)

type arm64RawStreamingModeControl struct {
	enable bool
	state  arm64StreamingState
}

var arm64RawStreamingModeControlForms = map[uint32]arm64RawStreamingModeControl{
	0xd503477f: {enable: true, state: arm64StreamingStateBoth},
	0xd503437f: {enable: true, state: arm64StreamingStateSM},
	0xd503457f: {enable: true, state: arm64StreamingStateZA},
	0xd503467f: {state: arm64StreamingStateBoth},
	0xd503427f: {state: arm64StreamingStateSM},
	0xd503447f: {state: arm64StreamingStateZA},
}

func decodeARM64RawStreamingModeControl(word uint32) (arm64RawStreamingModeControl, bool) {
	form, ok := arm64RawStreamingModeControlForms[word]
	return form, ok
}

func (c *arm64Ctx) lowerRawStreamingModeControl(form arm64RawStreamingModeControl) error {
	mnemonic := "smstop"
	if form.enable {
		mnemonic = "smstart"
	}
	switch form.state {
	case arm64StreamingStateBoth:
	case arm64StreamingStateSM:
		mnemonic += " sm"
	case arm64StreamingStateZA:
		mnemonic += " za"
	default:
		return fmt.Errorf("arm64 unsupported streaming state %d", form.state)
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", mnemonic, "~{memory}")
	return nil
}
