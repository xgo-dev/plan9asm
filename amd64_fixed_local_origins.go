package plan9asm

// An initialized machine address, separate from NUM and relocated private SP.
// Roles describe its possible sources, not a proof of its runtime pointee
// extent. Preserve one exact literal only while all literal alternatives agree.
// Forgetting that detail never forgets the address or introduces permission.
type x86FixedLocalOrigins struct {
	address x86StaticSBAddress
	roles   uint8
}

const (
	fixedLocalNativeAddress uint8 = 1 << iota
	fixedLocalGlobalAddress
	fixedLocalLiteralAddress
	fixedLocalAddressRoles = fixedLocalNativeAddress | fixedLocalGlobalAddress | fixedLocalLiteralAddress
)

// Retain the conservative per-entry charge used before address compaction.
// Joins now update a fixed-size value and allocate no alternative-set tails.
const fixedLocalOriginPayloadBytes int64 = 64

func fixedLocalOriginStorage(state x86FixedLocalState) int64 {
	bytes := fixedLocalOriginMapStorage(state.opaque) + fixedLocalOriginMapStorage(state.opaqueCells)
	if state.savedBP != nil {
		bytes += 2 * fixedLocalOriginPayloadBytes // Includes the immutable saved register facts.
	}
	return bytes
}

func fixedLocalOriginMapStorage[K comparable](values map[K]x86FixedLocalOrigins) int64 {
	return int64(len(values)) * fixedLocalOriginPayloadBytes
}

func fixedLocalOrigin(origin x86FixedLocalOrigin) x86FixedLocalOrigins {
	switch {
	case origin.literal.symbol != "":
		return x86FixedLocalOrigins{address: origin.literal, roles: fixedLocalLiteralAddress}
	case origin.global != "":
		return x86FixedLocalOrigins{roles: fixedLocalGlobalAddress}
	default:
		return x86FixedLocalOrigins{roles: fixedLocalNativeAddress}
	}
}

func (origins x86FixedLocalOrigins) valid() bool {
	return origins.roles != 0 && origins.roles&^fixedLocalAddressRoles == 0 &&
		(origins.hasLiteral() || origins.address == (x86StaticSBAddress{}))
}

func (origins x86FixedLocalOrigins) equal(other x86FixedLocalOrigins) bool {
	return origins == other
}

func (origins x86FixedLocalOrigins) union(other x86FixedLocalOrigins) (x86FixedLocalOrigins, bool) {
	if !origins.valid() || !other.valid() {
		return x86FixedLocalOrigins{}, false
	}
	address := origins.address
	if !origins.hasLiteral() {
		address = other.address
	} else if other.hasLiteral() && address != other.address {
		address = x86StaticSBAddress{}
	}
	return x86FixedLocalOrigins{address: address, roles: origins.roles | other.roles}, true
}

func (origins x86FixedLocalOrigins) hasLiteral() bool {
	return origins.roles&fixedLocalLiteralAddress != 0
}

func (origins x86FixedLocalOrigins) readonly() bool {
	return origins.roles&(fixedLocalGlobalAddress|fixedLocalLiteralAddress) != 0
}

func (origins x86FixedLocalOrigins) literal() (x86StaticSBAddress, bool) {
	return origins.address, origins.roles == fixedLocalLiteralAddress && origins.address.symbol != ""
}

func fixedLocalOriginOwners(origins x86FixedLocalOrigins, proof *x86FixedLocalProof) bool {
	if !origins.valid() {
		return false
	}
	if !origins.hasLiteral() {
		return true
	}
	if proof == nil || proof.binding == nil || len(proof.binding.literalData) == 0 {
		return false
	}
	if origins.address.symbol == "" {
		return true // Each original literal was checked before joining identities.
	}
	_, found := proof.binding.literalData[origins.address.symbol]
	return found
}

func cloneFixedLocalOrigins[K comparable](input map[K]x86FixedLocalOrigins) map[K]x86FixedLocalOrigins {
	result := make(map[K]x86FixedLocalOrigins, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func mergeFixedLocalOrigins[K comparable](previous, current map[K]x86FixedLocalOrigins) (bool, error) {
	changed := false
	for key, old := range previous {
		incoming, found := current[key]
		if !found {
			delete(previous, key) // Unknown on either path is still unknown.
			changed = true
			continue
		}
		merged, valid := old.union(incoming)
		if !valid {
			return false, goAMD64FrameContext("fixed local CFG has an invalid opaque address")
		}
		if merged != old {
			previous[key] = merged
			changed = true
		}
	}
	return changed, nil
}

// Only the captured compared register is refined. Native addresses may equal
// the literal. Excluding one unknown literal never excludes every readonly
// alternative or turns an address into numerical bytes.
func fixedLocalLiteralEdge(state x86FixedLocalState, op Op, taken bool) (x86FixedLocalState, bool) {
	comparison := state.comparison
	origins, found := state.opaque[comparison.register]
	condition := x86BranchCondition(op)
	if !found || !origins.valid() || condition != "EQ" && condition != "NE" {
		return state, true
	}
	next := fixedLocalOrigin(x86FixedLocalOrigin{literal: comparison.literal})
	if taken != (condition == "EQ") {
		if origins.address != comparison.literal {
			return state, true
		}
		next = x86FixedLocalOrigins{roles: origins.roles &^ fixedLocalLiteralAddress}
	}
	if next.roles == 0 {
		return state, false
	}
	if next != origins {
		state.opaque = cloneFixedLocalOrigins(state.opaque)
		state.opaque[comparison.register] = next
	}
	return state, true
}
