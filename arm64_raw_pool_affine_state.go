package plan9asm

// Transfer helpers still receive the complete value state. Only this proof's
// queue and visited table use an exact, query-local constraint-set identity.
type arm64PoolAffineStateKey struct {
	at         int
	expression arm64PoolAffine
	bound      arm64PoolInterval
	set        int
	count      int
}

// A bucket is not a constraint identity. Omitting coefficients makes the lookup
// smaller, but all candidates still require complete array equality below.
// Inactive slots, ordering and historical flag positions remain significant.
type arm64PoolConstraintBucket [8]struct {
	constant    uint64
	relocations int64
	interval    arm64PoolInterval
	mask        uint64
	after       int
}

func arm64PoolConstraintBucketFor(constraints *[8]arm64PoolConstraint) arm64PoolConstraintBucket {
	var bucket arm64PoolConstraintBucket
	for n := range constraints {
		constraint := &constraints[n]
		bucket[n].constant = constraint.expression.constant
		bucket[n].relocations = constraint.expression.relocations
		bucket[n].interval = constraint.interval
		bucket[n].mask = constraint.mask
		bucket[n].after = constraint.after
	}
	return bucket
}

type arm64PoolAffineStateSets struct {
	sets    [][8]arm64PoolConstraint
	buckets map[arm64PoolConstraintBucket][]int
}

func (sets *arm64PoolAffineStateSets) identity(constraints *[8]arm64PoolConstraint) int {
	// Zero is the exact all-zero array, not merely an empty active prefix.
	if *constraints == [8]arm64PoolConstraint{} {
		return 0
	}
	bucket := arm64PoolConstraintBucketFor(constraints)
	for _, identity := range sets.buckets[bucket] {
		if sets.sets[identity-1] == *constraints {
			return identity
		}
	}
	if sets.buckets == nil {
		sets.buckets = make(map[arm64PoolConstraintBucket][]int)
	}
	// Copy the entire array. A later transfer cannot mutate a stored set or any
	// previously queued/visited state, and expansion returns another value copy.
	sets.sets = append(sets.sets, *constraints)
	identity := len(sets.sets)
	sets.buckets[bucket] = append(sets.buckets[bucket], identity)
	return identity
}

func (sets *arm64PoolAffineStateSets) compact(state *arm64PoolAffineState) arm64PoolAffineStateKey {
	return arm64PoolAffineStateKey{
		at: state.at, expression: state.expression, bound: state.bound,
		set: sets.identity(&state.constraints), count: state.count,
	}
}

func (sets *arm64PoolAffineStateSets) expand(key arm64PoolAffineStateKey) arm64PoolAffineState {
	state := arm64PoolAffineState{
		at: key.at, expression: key.expression, bound: key.bound, count: key.count,
	}
	if key.set != 0 {
		state.constraints = sets.sets[key.set-1]
	}
	return state
}
