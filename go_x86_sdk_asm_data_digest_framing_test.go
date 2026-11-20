package plan9asm

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestGoX86SDKASMDataDigestLargeStringTemporaryBytes(t *testing.T) {
	state, source := sdkASMDataDigestFixture(t)
	payload := strings.Repeat("MOVQ", 1<<19) // An existing 2 MiB mapped-source role.
	state.Observation.Positions[0].Mapped = payload
	state.publish(source)
	runtime.GC()
	want, err := source.digest()
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var sums [3][32]byte
	for i := range sums {
		sums[i], err = source.digest()
		if err != nil {
			break
		}
	}
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, sum := range sums {
		if sum != want {
			t.Fatal("unchanged mapped source has a nondeterministic digest")
		}
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 3<<20 {
		t.Errorf("three complete digests allocate %d temporary bytes for a string; want <= %d",
			allocated, uint64(3<<20))
	}
	changed := []byte(payload)
	for _, index := range []int{0, len(payload) / 2, len(payload) - 1} {
		changed[index] ^= 0x20
		state.Observation.Positions[0].Mapped = string(changed)
		state.publish(source)
		got, digestErr := source.digest()
		if digestErr != nil || got == want {
			t.Fatal("current mapped-source mutation escaped the digest", index, digestErr)
		}
		changed[index] ^= 0x20
	}
}

func TestGoX86SDKASMDataDigestFramingAndMapOrder(t *testing.T) {
	type fields struct {
		First, Second string
		Bytes         []byte
	}
	for _, test := range []struct {
		name          string
		first, second any
	}{
		{"string-partitions", fields{First: "a", Second: "bc"}, fields{First: "ab", Second: "c"}},
		{"binary-delimiters", fields{First: "a\x00", Bytes: []byte("b")}, fields{First: "a", Bytes: []byte{0, 'b'}}},
		{"nil-and-empty-bytes", fields{}, fields{Bytes: []byte{}}},
		{"nil-and-empty-maps", map[string]string(nil), map[string]string{}},
		{"nil-and-empty-slices", []string(nil), []string{}},
		{"map-key-value-partitions", map[string]string{"a": "bc"}, map[string]string{"ab": "c"}},
		{"scalar-kinds", uint64(1), int64(1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			first, err := digestSDKASMDataState(test.first)
			if err != nil {
				t.Fatal(err)
			}
			second, err := digestSDKASMDataState(test.second)
			if err != nil || first == second {
				t.Fatal("different complete state has an ambiguous digest encoding", err)
			}
		})
	}
	t.Run("map-order", func(t *testing.T) {
		first := map[string][]byte{"a": {0, 1}, "b": {2, 3}}
		second := make(map[string][]byte)
		second["b"], second["a"] = []byte{2, 3}, []byte{0, 1}
		want, err := digestSDKASMDataState(first)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 8; i++ {
			got, err := digestSDKASMDataState(second)
			if err != nil || got != want {
				t.Fatal("map iteration or insertion order changed the complete state digest", err)
			}
		}
	})
	t.Run("invalid-state", func(t *testing.T) {
		type node struct{ Next *node }
		cycle := &node{}
		cycle.Next = cycle
		for _, value := range []any{
			json.RawMessage("{"), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
			map[int]string{1: "value"}, func() {}, cycle,
		} {
			if _, err := digestSDKASMDataState(value); err == nil {
				t.Fatal("invalid or unsupported state was silently omitted")
			}
		}
	})
}
