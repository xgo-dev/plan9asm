package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

func TestWasmListedFunctionBody(t *testing.T) {
	listing := "\t0x0000 00000 (probe.s:2)\tMemoryInit\t$0, $0\n" +
		"\t0x0000 01 01 7f 23 00 21 01 fc 08 41 25 1a 41 00 0f 00  ...#.!...A%.A...\n" +
		"\t0x0010 0b                                               .\n"
	want := []byte{1, 1, 0x7f, 0x23, 0, 0x21, 1, 0xfc, 8, 0x41, 0x25, 0x1a, 0x41, 0, 0x0f, 0, 0x0b}
	got, err := wasmListedFunctionBody(listing)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("listed bytes = %x, error = %v", got, err)
	}
	for _, changed := range []string{
		strings.Replace(listing, "0x0010", "0x0011", 1),
		strings.Replace(listing, "fc 08", "fc xx", 1),
	} {
		if _, err := wasmListedFunctionBody(changed); err == nil {
			t.Fatal("invalid listing retained emission evidence")
		}
	}
}

func TestWasmDirectEncoderKeepsOutcomesSeparate(t *testing.T) {
	goroot, err := gotoolchain.Root()
	if err != nil {
		t.Fatal(err)
	}
	observations, err := observeWasmDirectEncoder(goroot, "js")
	if err != nil {
		t.Fatal(err)
	}
	panicCount, omittedCount := 0, 0
	for _, observation := range observations {
		if len(observation.Samples) != 2 {
			t.Fatalf("%s lacks paired operands", observation.Opcode)
		}
		zero, one := observation.Samples[0], observation.Samples[1]
		if zero.Source == one.Source {
			t.Fatalf("%s repeated its first source", observation.Opcode)
		}
		switch observation.Outcome {
		case "assembler_panic":
			panicCount++
			if observation.Opcode != "BRTABLE" || zero.ExitCode != 2 || one.ExitCode != 2 ||
				zero.BodyHex != "" || one.BodyHex != "" || zero.ObjectSHA256 != "" || one.ObjectSHA256 != "" {
				t.Fatalf("panic acquired emitted-object evidence: %+v", observation)
			}
		case "indexes_omitted":
			omittedCount++
			if zero.ExitCode != 0 || one.ExitCode != 0 || zero.BodyHex == "" || zero.BodyHex != one.BodyHex ||
				zero.ObjectSHA256 == "" || one.ObjectSHA256 == "" {
				t.Fatalf("omission lacks matching object evidence: %+v", observation)
			}
		default:
			t.Fatalf("unknown direct encoder outcome: %+v", observation)
		}
	}
	if panicCount != 1 || omittedCount != 13 {
		t.Fatalf("got %d panics and %d omitted-index observations", panicCount, omittedCount)
	}
}
