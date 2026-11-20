package plan9asm

import "fmt"

// Native source authorities describe different complete source/object joins.
// Choosing one dispatch branch cannot silently discard the other authority.
func mixedNativeAuthorityContext() error {
	return fmt.Errorf("%w: numerical-read and ARM64 byte-carrier authorities cannot be combined", ErrProbeNeedsContext)
}

func (source *GoX86NumericalReadSource) revokeNumericalSource() {
	if source == nil {
		return
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.identity == source {
		source.ready = false
	}
}

func rejectMixedNativeAuthorities(binding *GoX86NumericalReadBinding, carrier *GoARM64ByteCarrierSource) error {
	if binding == nil || carrier == nil {
		return nil
	}
	// Do not hold either source lock while entering the other source. A copied
	// token is not allowed to revoke the original token's unrelated live owner.
	if binding.originalBinding == binding && binding.source == binding.originalSource {
		binding.source.revokeNumericalSource()
	}
	carrier.revokeCarrier()
	return mixedNativeAuthorityContext()
}
