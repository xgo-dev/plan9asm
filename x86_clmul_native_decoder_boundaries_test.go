package plan9asm

import "testing"

func TestX86CLMULNativePhysicalPrefixRegisterAndTruncationBoundaries(t *testing.T) {
	for _, row := range x86CLMULNativeOriginCases() {
		for _, mode := range []int{32, 64} {
			t.Run(row.name()+"/"+map[int]string{32: "386", 64: "amd64"}[mode], func(t *testing.T) {
				original := row.code()
				if _, length, known, err := decodedX86RawCLMULInstruction(original, mode); !known || err != nil || length != len(original) {
					t.Fatal("complete original physical control failed before its boundary checks", known, length, err)
				}
				for extent := 0; extent < len(original); extent++ {
					if _, _, known, err := decodedX86RawCLMULInstruction(original[:extent], mode); known && err == nil {
						t.Fatal("truncated original prefix/ModRM/immediate acquired a complete source", extent)
					}
				}
				if row.memory {
					// This is a separate source/address contract, not an ISA
					// invalidity claim about otherwise valid address-size bytes.
					changed := append([]byte{0x67}, original...)
					if _, _, known, err := decodedX86RawCLMULInstruction(changed, mode); !known || err == nil {
						t.Fatal("unbound native address-size form borrowed the default source contract", known, err)
					}
				}
				if row.encoding == "evex" {
					for _, control := range []struct {
						name       string
						index      int
						set, clear byte
					}{
						{"mask", 3, 1, 0},
						{"zero", 3, 0x80, 0},
						{"broadcast", 3, 0x10, 0},
						{"reserved length", 3, 0x60, 0},
						{"fixed bit", 2, 0, 4},
					} {
						changed := append([]byte(nil), original...)
						changed[control.index] = changed[control.index]&^control.clear | control.set
						if _, _, known, err := decodedX86RawCLMULInstruction(changed, mode); !known || err == nil {
							t.Fatal("reserved CLMUL field acquired a physical source", control.name, known, err)
						}
					}
				}
				if mode != 32 {
					return // The complete existing mode64 root owns valid high-bank encodings.
				}
				if row.encoding == "legacy" {
					for _, prefix := range []byte{0x41, 0x44, 0x48} {
						changed := append([]byte{0x66, prefix}, original[1:]...)
						if _, _, known, err := decodedX86RawCLMULInstruction(changed, mode); !known || err == nil {
							t.Fatal("mode32 producer byte was reinterpreted as a legacy REX prefix", prefix, known, err)
						}
					}
					return
				}
				// A physical raw binding cannot grant Go's mode32 source a
				// high register bank. X is exercised only where it actually
				// selects a register or SIB index, not an ignored VEX reg bit.
				for _, control := range []struct {
					name  string
					index int
					clear byte
				}{
					{"R", 1, 0x80},
					{"B", 1, 0x20},
					{"vvvv", 2, 0x40},
					{"X", 1, 0x40},
					{"R prime", 1, 0x10},
					{"V prime", 3, 0x08},
				} {
					if row.encoding != "evex" && (control.name == "R prime" || control.name == "V prime" || control.name == "X" && !row.memory) {
						continue
					}
					changed := append([]byte(nil), original...)
					if control.name == "X" && row.memory {
						modRM := len(changed) - 2
						changed[modRM] = changed[modRM]&0x38 | 4
						// SIB: numerical CX index, pointer BX base, scale one.
						changed = append(changed[:modRM+1], 0x0b, changed[modRM+1])
						if _, length, known, err := decodedX86RawCLMULInstruction(changed, mode); !known || err != nil || length != len(changed) {
							t.Fatal("complete low-bank SIB control failed before its extension check", known, length, err)
						}
					}
					changed[control.index] &^= control.clear
					if _, _, known, err := decodedX86RawCLMULInstruction(changed, mode); !known || err == nil {
						t.Fatal("mode32 extended physical field borrowed a low-bank source", control.name, known, err)
					}
				}
			})
		}
	}
}
