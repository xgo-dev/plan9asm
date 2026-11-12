package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

// Keep the oracle byte-addressed. The production representation may change,
// but a partially overwritten byte and an adjacent byte remain independent.
func fixedLocalByteStateFixture(size int) (x86FixedLocalState, []bool, []bool) {
	state := fixedLocalExchangeState()
	state.bytes = newFixedLocalByteSet(int64(size))
	state.booleanBytes = newFixedLocalByteSet(int64(size))
	known, booleans := make([]bool, size), make([]bool, size)
	for index := range known {
		known[index] = index%5 != 0
		booleans[index] = known[index] && index%3 == 0
		fixedLocalByteStateSet(&state, index, known[index], booleans[index])
	}
	return state, known, booleans
}

func fixedLocalByteStateSet(state *x86FixedLocalState, index int, known, boolean bool) {
	state.bytes.set(int64(index), known)
	state.booleanBytes.set(int64(index), boolean)
}

func checkFixedLocalByteState(t *testing.T, state x86FixedLocalState, known, booleans []bool) {
	t.Helper()
	missing := make([]int, len(known)+1)
	for index := range known {
		missing[index+1] = missing[index]
		if !known[index] {
			missing[index+1]++
		}
		if state.bytes.has(int64(index)) != known[index] || state.booleanBytes.has(int64(index)) != booleans[index] {
			t.Fatalf("byte %d: numerical=%v boolean=%v, want %v/%v", index,
				state.bytes.has(int64(index)), state.booleanBytes.has(int64(index)), known[index], booleans[index])
		}
	}
	for _, offset := range []int{0, 1, 7, 31, 63, 64, 65, len(known)} {
		for _, width := range []int{0, 1, 2, 8, 16, 63, 64, 65, len(known) - offset} {
			if offset > len(known) || width < 0 || width > len(known)-offset {
				continue
			}
			want := missing[offset+width] == missing[offset]
			if got := state.bytes.all(int64(offset), int64(width)); got != want {
				t.Fatalf("numerical read [%d,%d): got %v, want %v", offset, offset+width, got, want)
			}
		}
	}
	for index := len(known); index < len(state.bytes)*64; index++ {
		if state.bytes.has(int64(index)) || state.booleanBytes.has(int64(index)) {
			t.Fatalf("padding byte %d acquired facts outside the original frame", index)
		}
	}
	for offset := 0; offset < len(known); offset++ {
		width := len(known) - offset
		if width > 8 {
			width = 8
		}
		var expected uint8
		for index := 0; index < width; index++ {
			if booleans[offset+index] {
				expected |= 1 << uint(index)
			}
		}
		if got := fixedLocalMemoryBooleans(&state, int64(offset), int64(width)); got != expected {
			t.Fatalf("boolean read [%d,%d): got %#x, want %#x", offset, offset+width, got, expected)
		}
	}
}

func TestGoAMD64FixedLocalByteStatePartialWrites(t *testing.T) {
	for _, size := range []int{1, 7, 8, 63, 64, 65, 127, 128, 129, 1408} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			state, known, booleans := fixedLocalByteStateFixture(size)
			for _, offset := range []int{0, 1, 7, 8, 31, 60, 63, 64, 65, 127, size - 1} {
				for _, width := range []int{1, 2, 4, 8, 16, 32, 64} {
					if offset < 0 || width > size-offset {
						continue
					}
					for _, complete := range []bool{false, true} {
						fixedLocalNumericalStore(&state, int64(offset), int64(width), complete)
						for index := offset; index < offset+width; index++ {
							known[index] = known[index] || complete
							booleans[index] = false
						}
						checkFixedLocalByteState(t, state, known, booleans)
					}
				}
			}
		})
	}
}

func TestGoAMD64FixedLocalByteStateScalarTransport(t *testing.T) {
	const size = 129
	state, known, booleans := fixedLocalByteStateFixture(size)
	proof := &x86FixedLocalProof{frame: size}
	for _, offset := range []int{0, 7, 60, 63, 64, 65, 120} {
		for _, form := range []struct {
			op    string
			width int64
		}{{"MOVB", 1}, {"MOVW", 2}, {"MOVL", 4}, {"MOVQ", 8}} {
			width := form.width
			ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s $1,%d(SP)", form.op, offset))
			value := fixedLocalScalarValue{booleans: 0xa5}
			if err := fixedLocalWriteValue(&ins, 1, 0, value, &state, FuncSig{}, proof, 0, width); err != nil {
				t.Fatal(err)
			}
			for index := int64(0); index < width; index++ {
				known[offset+int(index)] = true
				booleans[offset+int(index)] = 0xa5&(1<<uint(index)) != 0
			}
			checkFixedLocalByteState(t, state, known, booleans)
		}
	}
}

func TestGoAMD64FixedLocalByteStateMeetAndClone(t *testing.T) {
	for _, size := range []int{0, 1, 63, 64, 65, 128, 129, 1408, 65536} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			state, known, booleans := fixedLocalByteStateFixture(size)
			other := cloneFixedLocalState(state)
			expectedKnown := append([]bool(nil), known...)
			expectedBooleans := append([]bool(nil), booleans...)
			wantChanged := false
			for index := range known {
				lastKnown, lastBoolean := index%7 != 0, index%11 == 0
				fixedLocalByteStateSet(&other, index, lastKnown, lastBoolean)
				expectedKnown[index] = known[index] && lastKnown
				expectedBooleans[index] = booleans[index] && lastBoolean
				wantChanged = wantChanged || expectedKnown[index] != known[index] || expectedBooleans[index] != booleans[index]
			}
			checkFixedLocalByteState(t, state, known, booleans)
			changed, err := mergeFixedLocalState(&state, other)
			if err != nil || changed != wantChanged {
				t.Fatalf("first meet: changed=%v want=%v error=%v", changed, wantChanged, err)
			}
			checkFixedLocalByteState(t, state, expectedKnown, expectedBooleans)
			if changed, err := mergeFixedLocalState(&state, other); err != nil || changed {
				t.Fatalf("stable meet changed state: %v, %v", changed, err)
			}
			for index := range known {
				fixedLocalByteStateSet(&other, index, true, true)
			}
			checkFixedLocalByteState(t, state, expectedKnown, expectedBooleans)
		})
	}
}

func TestGoAMD64FixedLocalByteStateFrameTail(t *testing.T) {
	for _, size := range []int{8, 24, 72} {
		for _, start := range []int{size - 8, size - 7, size - 1} {
			for _, write := range []bool{false, true} {
				for _, offset := range []int{size - 1, size} {
					name := fmt.Sprintf("frame%d/spill%d/write%v/byte%d", size, start, write, offset)
					t.Run(name, func(t *testing.T) {
						state, _, _ := fixedLocalByteStateFixture(size)
						for index := 0; index < size; index++ {
							fixedLocalByteStateSet(&state, index, write, false)
						}
						state.known[AX] = 255
						// A malformed observed spill must not borrow the bitmap's
						// padding as storage, even when the RMW byte is initialized.
						state.opaqueCells[int64(start)] = fixedLocalOrigin(x86FixedLocalOrigin{})
						row := fmt.Sprintf("SUBB %d(SP),AX", offset)
						if write {
							row = fmt.Sprintf("SUBB $1,%d(SP)", offset)
						}
						ins := x86ScalarLaneInstruction(t, row)
						effect, found, err := fixedLocalGPByteEffect(ins)
						if err != nil || !found {
							t.Fatal("scalar grammar fixture is invalid", found, err)
						}
						proof := &x86FixedLocalProof{frame: int64(size)}
						err = fixedLocalTypedByteStep(&ins, &state, FuncSig{}, proof, 0, effect)
						want := start == size-8 && offset < size
						if (err == nil) != want || !want && !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("private tail acceptance=%v, want %v: %v", err == nil, want, err)
						}
					})
				}
			}
		}
	}
}

func BenchmarkFixedLocalFrameState(b *testing.B) {
	for _, size := range []int{64, 1408, 65536} {
		state, _, _ := fixedLocalByteStateFixture(size)
		b.Run(fmt.Sprintf("clone/%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for index := 0; index < b.N; index++ {
				fixedLocalOriginBenchmarkState = cloneFixedLocalState(state)
			}
		})
		b.Run(fmt.Sprintf("meet/%d", size), func(b *testing.B) {
			other := cloneFixedLocalState(state)
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if changed, err := mergeFixedLocalState(&other, state); err != nil || changed {
					b.Fatal("identical byte states must be unchanged", changed, err)
				}
			}
			fixedLocalOriginBenchmarkState = other
		})
	}
}
