package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"testing"
	"unsafe"
)

func TestARM64PoolAffineQueueAndVisitedAvoidFullConstraintCopies(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "arm64_raw_pool_affine.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var proof *ast.FuncDecl
	for _, decl := range file.Decls {
		if function, ok := decl.(*ast.FuncDecl); ok && function.Name.Name == "affineIntervalProof" {
			proof = function
		}
	}
	if proof == nil {
		t.Fatal("original affine proof consumer missing")
	}
	ast.Inspect(proof.Body, func(node ast.Node) bool {
		var element ast.Expr
		switch typed := node.(type) {
		case *ast.ArrayType:
			element = typed.Elt
		case *ast.MapType:
			element = typed.Key
		}
		if ident, ok := element.(*ast.Ident); ok && ident.Name == "arm64PoolAffineState" {
			t.Error("queue/visited still copy the complete eight-constraint transfer state")
		}
		return true
	})
}

func TestARM64PoolAffineStateExactRoundtrip(t *testing.T) {
	var sets arm64PoolAffineStateSets
	random := rand.New(rand.NewSource(17))
	for n := 0; n < 128; n++ {
		state := arm64PoolAffineState{
			at: n - 1, expression: arm64PoolRegisterExpression(n % 31),
			bound: arm64PoolInterval{uint64(n), uint64(n + 32)}, count: n % 9,
		}
		for slot := range state.constraints {
			constraint := &state.constraints[slot]
			for register := range constraint.expression.coefficient {
				constraint.expression.coefficient[register] = random.Int63() - random.Int63()
			}
			constraint.expression.constant = random.Uint64()
			constraint.expression.relocations = random.Int63()
			constraint.interval = arm64PoolInterval{random.Uint64(), random.Uint64()}
			constraint.mask, constraint.after = random.Uint64(), n-slot
		}
		key := sets.compact(&state)
		if actual := sets.expand(key); actual != state {
			t.Fatalf("full state changed in roundtrip %d", n)
		}
		if repeated := sets.compact(&state); repeated != key {
			t.Fatalf("equal state acquired another key in roundtrip %d", n)
		}
	}
	if compact, full := unsafe.Sizeof(arm64PoolAffineStateKey{}), unsafe.Sizeof(arm64PoolAffineState{}); compact >= full/2 {
		t.Fatalf("queue key still carries full constraint storage: compact=%d full=%d", compact, full)
	}
}

func TestARM64PoolAffineStateCompleteArrayIdentity(t *testing.T) {
	for count := 0; count <= 8; count++ {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			var sets arm64PoolAffineStateSets
			original := arm64PoolAffineState{count: count}
			originalKey := sets.compact(&original)
			for slot := 0; slot < 8; slot++ {
				for field := 0; field < 37; field++ {
					changed := original
					constraint := &changed.constraints[slot]
					switch {
					case field < 31:
						constraint.expression.coefficient[field] = -1
					case field == 31:
						constraint.expression.constant = 1 << 63
					case field == 32:
						constraint.expression.relocations = 1
					case field == 33:
						constraint.interval.low = 3
					case field == 34:
						constraint.interval.high = 7
					case field == 35:
						constraint.mask = 15
					case field == 36:
						constraint.after = -4
					}
					key := sets.compact(&changed)
					if key == originalKey || sets.expand(key) != changed {
						t.Fatalf("active/inactive field lost: count=%d slot=%d field=%d", count, slot, field)
					}
				}
			}
		})
	}
}

func TestARM64PoolAffineStateForcedBucketCollisionAndOwnership(t *testing.T) {
	var sets arm64PoolAffineStateSets
	first := arm64PoolAffineState{count: 1}
	first.constraints[0].expression.coefficient[0] = 1
	second := first
	second.constraints[0].expression.coefficient[30] = -1
	if arm64PoolConstraintBucketFor(&first.constraints) != arm64PoolConstraintBucketFor(&second.constraints) {
		t.Fatal("fixture did not force the same lookup key/hash")
	}
	firstKey, secondKey := sets.compact(&first), sets.compact(&second)
	if firstKey == secondKey || len(sets.buckets) != 1 || len(sets.sets) != 2 {
		t.Fatal("colliding unequal complete arrays merged")
	}
	if sets.expand(firstKey) != first || sets.expand(secondKey) != second {
		t.Fatal("collision replaced an earlier complete array")
	}
	copy := sets.expand(firstKey)
	copy.constraints[0].after = 17
	if sets.expand(firstKey) != first || sets.compact(&first) != firstKey {
		t.Fatal("expanded value aliases private stored constraints")
	}
	first.constraints[0].mask = 31
	if sets.expand(firstKey).constraints[0].mask != 0 {
		t.Fatal("input value aliases private stored constraints")
	}
	var other arm64PoolAffineStateSets
	otherKey := other.compact(&second)
	if otherKey.set != 1 || other.expand(otherKey) != second || sets.expand(firstKey) == second {
		t.Fatal("query-local identities leaked across proof invocations")
	}
}

func TestARM64PoolAffineStateVisitedEqualityMatchesFullState(t *testing.T) {
	var sets arm64PoolAffineStateSets
	full := make(map[arm64PoolAffineState]bool)
	compact := make(map[arm64PoolAffineStateKey]bool)
	for n := 0; n < 768; n++ {
		state := arm64PoolAffineState{at: n % 7, count: n % 9,
			expression: arm64PoolAffine{constant: uint64(n % 13)},
			bound:      arm64PoolInterval{0, uint64(n % 11)}}
		// Different order, inactive tail, historical flags and coefficients
		// distinguish states even if their bucket projections collide.
		state.constraints[n%8] = arm64PoolConstraint{
			expression: arm64PoolRegisterExpression(n % 31), after: n % 3,
		}
		for repeat := 0; repeat < 2; repeat++ {
			key := sets.compact(&state)
			if compact[key] != full[state] || sets.expand(key) != state {
				t.Fatalf("old complete-state equality changed at %d/%d", n, repeat)
			}
			full[state], compact[key] = true, true
		}
	}
	if len(full) != len(compact) {
		t.Fatal("visited state denominator changed")
	}
}
