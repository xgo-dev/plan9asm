package plan9asm

import (
	"reflect"
	"testing"
)

func TestX86SegmentMOVREXCallerFootprintUsesActualDestination(t *testing.T) {
	addresses := []string{"-8(R8)", "-8(R8)(FS)", "-8(R8)(GS)"}
	for _, scale := range []string{"1", "2", "4", "8"} {
		addresses = append(addresses, "-8(R8)(CX*"+scale+")",
			"-8(R8)(FS*"+scale+")", "-8(R8)(GS*"+scale+")")
	}
	if len(addresses) != 15 {
		t.Fatal("complete independent ordinary/segment address footprint changed")
	}
	for _, address := range addresses {
		for _, alias := range []Reg{DH, BH} {
			t.Run(address+"/"+string(alias), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, "MOVB "+address+","+string(alias))
				original := ins
				original.Args = append([]Operand(nil), ins.Args...)
				// The actual REX encoding reads DH/BH's ModRM register
				// number as SI/DI's low byte, not as DX/BX's high byte.
				root, destination := 6, SI
				if alias == BH {
					root, destination = 7, DI
				}
				form, known, err := x86ScalarNativeLoadProperties(ins.Op, ins, "amd64")
				if !known || err != nil || form.destination != destination || form.bytes != 1 {
					t.Fatal("typed native-load footprint differs from the actual REX byte row", form, known, err)
				}
				// This independent denial-only post-consumer runs after a
				// separate transfer validated all reads. It cannot authorize
				// the source address or retain the overwritten caller role.
				before := [16]bool{2: true, 3: true, 6: true, 7: true}
				origins := [16]uint16{2: 3, 3: 4, 6: 7, 7: 8}
				want, wantOrigins := before, origins
				want[root], wantOrigins[root] = false, 0
				after := x86ResultCallerAddressesAfterTransfer(ins, before, before, nil, "amd64")
				if after != want {
					t.Fatal("caller post-consumer retained actual SI/DI or revoked unrelated textual DX/BX", after, want)
				}
				entry := map[int64]bool{2: true, 3: true, 6: true, 7: true}
				if got := x86ResultCallerOriginsAfter(ins, origins, after, entry, "amd64"); got != wantOrigins {
					t.Fatal("caller origin revocation disagrees with the actual written register", got, wantOrigins)
				}
				if !reflect.DeepEqual(ins, original) {
					t.Fatal("post-consumer changed original source operands or Raw")
				}
			})
		}
	}
}
