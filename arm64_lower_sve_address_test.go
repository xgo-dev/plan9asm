package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARM64RawSVEAddress(op Op, immediate, source, destination int) uint32 {
	base := uint32(0x04205000)
	switch op {
	case "ADDPL":
		base = 0x04605000
	case "RDVL":
		base = 0x04bf5000
		source = 31
	}
	return base | uint32(immediate&63)<<5 | uint32(source)<<16 | uint32(destination)
}

func TestTranslateARM64SVEAddressCompleteGo127Forms(t *testing.T) {
	const named = `
TEXT sveaddressnamed(SB),$0-0
	ADDVL $-32, R0, R1
	ADDVL $31, RSP, RSP
	ADDPL $-32, R2, R3
	ADDPL $31, RSP, R4
	RDVL $-32, R5
	RDVL $31, R6
	RET
`
	var raw strings.Builder
	raw.WriteString("TEXT sveaddressraw(SB),$0-0\n")
	for _, op := range []Op{"ADDVL", "ADDPL", "RDVL"} {
		for immediate := -32; immediate <= 31; immediate++ {
			fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEAddress(op, immediate, 2, 3))
		}
	}
	raw.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, raw.String(), true)

	for name, source := range map[string]string{"named": named, "raw": raw.String()} {
		t.Run(name, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			function := "sveaddress" + name
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ll, err := Translate(file, Options{
						TargetTriple: triple,
						Goarch:       "arm64",
						Sigs:         map[string]FuncSig{function: {Name: function, Ret: Void}},
					})
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(ll, `"target-features"="+sve"`) || !strings.Contains(ll, "call i64 @llvm.vscale.i64()") {
						t.Fatalf("ARM64 SVE address lowering for %s/%s lacks SVE feature or runtime vector length:\n%s", name, triple, ll)
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-address.ll", "arm64-sve-address.o", ll)
				})
			}
		})
	}
}

func TestARM64RawSVEAddressDecoderCoversSignedImmediateDomain(t *testing.T) {
	for _, op := range []Op{"ADDVL", "ADDPL", "RDVL"} {
		for immediate := -32; immediate <= 31; immediate++ {
			word := encodeARM64RawSVEAddress(op, immediate, 29, 30)
			got, ok := decodeARM64RawSVEAddress(word)
			if !ok {
				t.Fatalf("decoder rejected %s immediate %d word %#08x", op, immediate, word)
			}
			if got.op != op || got.immediate != immediate || got.destination != 30 || (op != "RDVL" && got.source != 29) {
				t.Fatalf("decoded word %#08x as %+v, want op=%s immediate=%d source=29 destination=30", word, got, op, immediate)
			}
		}
	}
}

func TestARM64SVEAddressUsesRuntimeVectorAndPredicateLengths(t *testing.T) {
	const source = `
TEXT sveaddressscale(SB),$0-0
	ADDVL $-3, R1, R2
	ADDPL $5, R3, R4
	RDVL $7, R5
	RET
`
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs:         map[string]FuncSig{"sveaddressscale": {Name: "sveaddressscale", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, scale := range []string{"mul i64", "-48", "10", "112"} { // vscale * (imm * 16/2).
		if !strings.Contains(ll, scale) {
			t.Fatalf("SVE runtime length scaling omitted %q:\n%s", scale, ll)
		}
	}
}

func TestARM64RawSVEAddressDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		encodeARM64RawSVEAddress("RDVL", 1, 0, 31), // RDVL cannot target SP/ZR.
		0x04204000, // neighboring SVE class.
	} {
		if _, ok := decodeARM64RawSVEAddress(word); ok {
			t.Fatalf("SVE address decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}
