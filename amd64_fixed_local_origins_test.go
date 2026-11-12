package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"unsafe"
)

var fixedLocalOriginBenchmarkState x86FixedLocalState

func BenchmarkFixedLocalOriginState(b *testing.B) {
	for _, entries := range []int{1, 8, 32} {
		state := x86FixedLocalState{
			pointers: make(map[Reg]int64), addresses: make(map[int64]int64),
			opaqueCells: make(map[int64]x86FixedLocalOrigins),
		}
		for index := 0; index < entries; index++ {
			state.opaqueCells[int64(index)*8] = fixedLocalOrigin(x86FixedLocalOrigin{parameter: int64(index) * 8})
		}
		b.Run(fmt.Sprintf("clone/%d", entries), func(b *testing.B) {
			b.ReportAllocs()
			for index := 0; index < b.N; index++ {
				fixedLocalOriginBenchmarkState = cloneFixedLocalState(state)
			}
		})
		b.Run(fmt.Sprintf("join/%d", entries), func(b *testing.B) {
			previous := cloneFixedLocalState(state)
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if changed, err := mergeFixedLocalState(&previous, state); err != nil || changed {
					b.Fatal("identical singleton states must be unchanged", changed, err)
				}
			}
			fixedLocalOriginBenchmarkState = previous
		})
	}
}

func TestGoAMD64FixedLocalOriginJoinStorageBudget(t *testing.T) {
	previous := map[Reg]x86FixedLocalOrigins{AX: fixedLocalOrigin(x86FixedLocalOrigin{})}
	current := map[Reg]x86FixedLocalOrigins{AX: fixedLocalOrigin(x86FixedLocalOrigin{
		literal: x86StaticSBAddress{symbol: "choice<>"},
	})}
	before := fixedLocalOriginMapStorage(previous)
	if changed, err := mergeFixedLocalOrigins(previous, current); err != nil || !changed {
		t.Fatal("actual address join failed", changed, err)
	}
	if bytes := fixedLocalOriginMapStorage(previous); bytes != before || bytes != 64 {
		t.Fatal("fixed-size address join changed the conservative per-entry charge", bytes)
	}
	for _, capacity := range []int64{63, 64} {
		budget := x86FixedLocalBudget{bytes: capacity}
		err := budget.consumeOrigins(before)
		if errors.Is(err, ErrProbeNeedsContext) != (capacity < before) {
			t.Fatal("cloning addresses bypassed its unchanged work bound", capacity, err)
		}
		if capacity < before && budget.bytes != capacity {
			t.Fatal("failed work accounting partially consumed its budget")
		}
	}
	allocations := testing.AllocsPerRun(10, func() {
		previous[AX] = fixedLocalOrigin(x86FixedLocalOrigin{})
		if _, err := mergeFixedLocalOrigins(previous, current); err != nil {
			panic(err)
		}
	})
	if allocations != 0 {
		t.Fatal("address join allocated alternative-set storage", allocations)
	}
}

func TestGoAMD64FixedLocalOriginValueStorage(t *testing.T) {
	if size := unsafe.Sizeof(x86FixedLocalOrigins{}); size > uintptr(fixedLocalOriginPayloadBytes) || size > 128 {
		t.Fatalf("address value is %d bytes, exceeding its charge or inline map threshold", size)
	}
}

func TestGoAMD64FixedLocalOriginSetValueSemantics(t *testing.T) {
	set := func(offsets ...int64) x86FixedLocalOrigins {
		value := fixedLocalOrigin(x86FixedLocalOrigin{literal: x86StaticSBAddress{symbol: "choice<>", offset: offsets[0]}})
		for _, offset := range offsets[1:] {
			var valid bool
			value, valid = value.union(fixedLocalOrigin(x86FixedLocalOrigin{literal: x86StaticSBAddress{symbol: "choice<>", offset: offset}}))
			if !valid {
				t.Fatal("complete native address join rejected")
			}
		}
		return value
	}
	t.Run("invalid equal values remain unknown", func(t *testing.T) {
		for _, value := range []x86FixedLocalOrigins{{}, {roles: 0x80}, {
			roles: fixedLocalNativeAddress, address: x86StaticSBAddress{symbol: "foreign<>"},
		}} {
			previous := map[Reg]x86FixedLocalOrigins{AX: value}
			if _, err := mergeFixedLocalOrigins(previous, map[Reg]x86FixedLocalOrigins{AX: value}); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("equal fast path granted an invalid address", err)
			}
		}
	})
	t.Run("independent order and duplicate joins", func(t *testing.T) {
		for _, offsets := range [][]int64{{0, 8, 16}, {16, 0, 8}, {8, 16, 8, 0, 16}} {
			first, second := set(0, 8, 16), set(offsets...)
			previous := map[Reg]x86FixedLocalOrigins{AX: first}
			if changed, err := mergeFixedLocalOrigins(previous, map[Reg]x86FixedLocalOrigins{AX: second}); err != nil || changed {
				t.Fatal("address join did not converge independently of order", changed, err)
			}
			if first != second || previous[AX] != first || !first.readonly() {
				t.Fatal("joining addresses lost readonly storage or changed a canonical value")
			}
		}
	})
	t.Run("union does not change either input", func(t *testing.T) {
		first, second := set(0), fixedLocalOrigin(x86FixedLocalOrigin{})
		merged, valid := first.union(second)
		if !valid || !merged.hasLiteral() || merged.roles&fixedLocalNativeAddress == 0 ||
			first != set(0) || second.hasLiteral() {
			t.Fatal("union mutated an input or lost an address role")
		}
	})
	t.Run("affine write does not change prior state", func(t *testing.T) {
		fn, sig, _ := fixedLocalPointerChoiceFixture(t, "MOVQ (SI),AX")
		proof := &x86FixedLocalProof{frame: fn.FrameSize, binding: sig.x86FixedLocal}
		original := set(8)
		state := x86FixedLocalState{
			opaque: map[Reg]x86FixedLocalOrigins{AX: original},
			known:  make(map[Reg]uint8), booleans: make(map[Reg]uint8),
		}
		ins := Instr{Op: "ADDQ", Args: []Operand{{Kind: OpImm, Imm: 8}, {Kind: OpReg, Reg: AX}}}
		if handled, err := fixedLocalInputAddressStep(&ins, &state, sig, proof, 0); err != nil || !handled {
			t.Fatal("exact affine write rejected", handled, err)
		}
		if !reflect.DeepEqual(original, set(8)) || !reflect.DeepEqual(state.opaque[AX], set(16)) {
			t.Fatal("affine write changed the prior address value")
		}
	})
}
