package plan9asm

// Values are immutable typed sets. This ordered identity includes the raw
// comparison value, which may differ from a missing-input or alias-read value.
// It never uses a hash, map identity, or a permission/source certificate.
type arm64ControlMergeOperands struct {
	old, left, right arm64ControlValue
}

type arm64ControlMergeResult struct {
	value   arm64ControlValue
	changed bool
}

// The table belongs to one merge invocation. It is not retained by the state
// or by an analysis. Shared roots remain immutable after the table is released.
type arm64ControlMergeOperations map[arm64ControlMergeOperands]arm64ControlMergeResult

func (operations *arm64ControlMergeOperations) union(old, left, right arm64ControlValue) arm64ControlMergeResult {
	// Preserve the existing allocation-free stable-state case. Identity is
	// insufficient for false entries or multiple affine frame witnesses.
	if old == left && left == right && arm64ControlCanonical(left) {
		return arm64ControlMergeResult{value: left}
	}
	key := arm64ControlMergeOperands{old, left, right}
	if result, present := (*operations)[key]; present {
		return result
	}
	value := arm64ControlUnion(left, right)
	result := arm64ControlMergeResult{
		value: value, changed: !arm64ControlEqual(old, value),
	}
	if *operations == nil {
		*operations = make(arm64ControlMergeOperations)
	}
	(*operations)[key] = result
	return result
}
