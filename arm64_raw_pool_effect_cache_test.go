package plan9asm

import "testing"

func TestARM64RawPoolGPEffectsReuseHasNoDecodeAllocations(t *testing.T) {
	// This actual register-indexed LDRB appears in the large SVE pool fixture.
	// Repeated range/CFG queries must not rebuild unrelated SVE operands.
	const word uint32 = 0x38616922
	flow := &arm64RawPoolValues{}
	want, known := arm64RawPoolGPWrites(word)
	if !known {
		t.Fatal("fixture lacks actual known GP effects")
	}
	flow.gpWrites(word)
	allocations := testing.AllocsPerRun(100, func() {
		got, valid := flow.gpWrites(word)
		if got != want || valid != known {
			t.Fatal("cached query changed its architectural effects")
		}
	})
	if allocations != 0 {
		t.Fatalf("warmed raw-word effect queries still allocate %.0f objects", allocations)
	}
}

func TestARM64RawPoolGPEffectsPreserveKnownAndUnknownWords(t *testing.T) {
	words := []uint32{
		0x38616922, // LDRB with a register-indexed address.
		0xd503201f, // NOP.
		0xd65f03c0, // Preserve the return-form classification too.
		0xffffffff,
		0x00000000,
	}
	first, second := &arm64RawPoolValues{}, &arm64RawPoolValues{}
	for _, word := range words {
		want, known := arm64RawPoolGPWrites(word)
		for repeat := 0; repeat < 3; repeat++ {
			for _, flow := range []*arm64RawPoolValues{first, second} {
				got, valid := flow.gpWrites(word)
				if got != want || valid != known {
					t.Fatalf("word %#08x: effects %#x/%v, want %#x/%v", word, got, valid, want, known)
				}
			}
		}
	}
}

func TestARM64RawPoolGPEffectsKeyCompleteEncodingAndSurviveFactReset(t *testing.T) {
	flow := &arm64RawPoolValues{}
	for _, base := range []uint32{0x38616920, 0xf9400020, 0x04a02020, 0x65068000, 0xffffffE0} {
		for register := uint32(0); register < 32; register++ {
			word := base | register
			want, known := arm64RawPoolGPWrites(word)
			got, valid := flow.gpWrites(word)
			if got != want || valid != known {
				t.Fatalf("full encoding %#08x lost its exact effects", word)
			}
		}
	}
	if len(flow.gpWriteCache) != 160 {
		t.Fatalf("cache does not retain exactly the queried machine words: %d", len(flow.gpWriteCache))
	}
	flow.clearValueCaches()
	allocations := testing.AllocsPerRun(100, func() {
		flow.gpWrites(0x38616922)
	})
	if allocations != 0 {
		t.Fatal("resetting context-dependent facts rebuilt context-free effects")
	}
}

func BenchmarkARM64RawPoolRepeatedGPEffects(b *testing.B) {
	const word uint32 = 0x38616922
	flow := &arm64RawPoolValues{}
	flow.gpWrites(word)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		flow.gpWrites(word)
	}
}
