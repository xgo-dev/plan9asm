package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestX86NumericalBroadcastCompleteOriginalFamily(t *testing.T) {
	// The same independent directory is checked against every original Go
	// opcode attribute and ytab row by TestX86BroadcastCompleteIndependentGoRows.
	// Boundary observation must consume the complete existing broadcast grammar,
	// even when a particular typed storage consumer supports only VEX forms.
	for _, arch := range []string{"amd64", "386"} {
		mode := 64
		if arch == "386" {
			mode = 32
		}
		var sources []string
		for _, spec := range x86BroadcastTestDirectory {
			inputs := []string{"65(AX)", "table+16(SB)"}
			for _, kind := range spec.source {
				inputs = append(inputs, map[rune]string{'X': "X3", 'G': "AX", 'K': "K0"}[kind])
			}
			if spec.source == "K" {
				inputs = inputs[2:]
			}
			destinations := []int{7}
			if arch == "amd64" && !strings.HasSuffix(spec.name, "128") {
				destinations = append(destinations, 23) // Force unmasked narrow EVEX too.
				if strings.Contains(spec.source, "X") {
					inputs = append(inputs, "X19")
				}
			}
			for _, bank := range spec.destinations {
				for _, input := range inputs {
					for masking := 0; masking < 3; masking++ {
						if masking != 0 && (spec.source == "K" || strings.HasSuffix(spec.name, "128")) {
							continue
						}
						op, mask := spec.name, ""
						if masking != 0 {
							mask = "K1,"
						}
						if masking == 2 {
							op += ".Z"
						}
						for _, destination := range destinations {
							sources = append(sources, fmt.Sprintf("%s %s,%s%c%d", op, input, mask, bank, destination))
						}
					}
				}
			}
		}
		code, pcs := x86NumericalBoundaryGoBytes(t, arch, strings.Join(sources, "\n")+"\nRET")
		if len(pcs) != len(sources)+1 {
			t.Fatal("complete original broadcast inventory changed", len(pcs), len(sources))
		}
		original := bytes.Clone(code)
		for index, source := range sources {
			t.Run(arch+"/"+source, func(t *testing.T) {
				instruction := code[pcs[index]:pcs[index+1]]
				length, err := x86NumericalVectorBoundary(instruction, mode)
				if err != nil || length != len(instruction) {
					t.Fatalf("actual Go %s (%x): boundary=%d/%d: %v", source, instruction, length, len(instruction), err)
				}
				decoded, size, known, err := decodedX86NumericalBroadcastBoundary(instruction, mode, x86RawMemoryDecoder{})
				if mode == 64 && strings.Contains(source, "(SB)") {
					if !known || err == nil {
						t.Fatal("physical boundary granted a raw RIP address", known, err)
					}
				} else if !known || err != nil || size != len(instruction) || string(decoded.Op) != strings.Fields(source)[0] {
					t.Fatal("shared family lost the existing source decoder identity", decoded, size, known, err)
				}
				for end := 0; end < len(instruction); end++ {
					if _, err := x86NumericalVectorBoundary(instruction[:end], mode); err == nil {
						t.Fatalf("accepted truncated broadcast at %d/%d", end, len(instruction))
					}
				}
			})
		}
		boundaries, scalar, err := x86NumericalNativeBoundaries(code, mode)
		_, terminal := scalar[pcs[len(pcs)-1]]
		if err != nil || len(boundaries) != len(pcs) || !bytes.Equal(code, original) || len(scalar) != 1 || !terminal {
			t.Error("complete broadcast source changed or lacks exact native boundaries", err, len(boundaries), len(pcs))
			continue
		}
		for index, boundary := range boundaries {
			end := int64(len(code))
			if index+1 < len(pcs) {
				end = pcs[index+1]
			}
			if boundary.PC != pcs[index] || int64(boundary.Length) != end-pcs[index] {
				t.Fatal("broadcast boundary lost original Go PC", index, boundary, pcs[index])
			}
		}
	}
}
