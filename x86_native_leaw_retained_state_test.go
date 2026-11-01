package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func TestX86NativeLEAWRetainedPointerKeepsDisjointByteAndOriginDomains(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, move := x86ResultPointerWord(arch), "MOVQ"
		if arch == "386" {
			move = "MOVL"
		}
		for _, old := range []string{"caller", "pointer only", "unknown", "numeric"} {
			for missing := -1; missing < int(word); missing++ {
				if old != "numeric" && missing != -1 {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/missing%d", arch, old, missing), func(t *testing.T) {
					state := x86RawMoveInitializedState()
					state.callerAddressFP = map[int64]bool{0: true, word: true, 2 * word: true}
					state.gp[0], state.canonicalGP[0] = 0, 0
					state.pointerGP[0] = old == "caller" || old == "pointer only"
					state.callerAddressGP[0] = old == "caller"
					if old == "caller" {
						state.callerAddressOrigin[0] = uint16(2*word + 1)
					} else if old == "numeric" {
						state.gp[0] = 0xff
						if missing >= 0 {
							state.gp[0] &^= uint8(1) << uint(missing)
						}
					}
					state.gp[6], state.pointerGP[6], state.callerAddressGP[6] = 0, true, true
					state.callerAddressOrigin[6], state.callerAddressOrigin[7] = uint16(word+1), 1
					instruction := x86ScalarLaneInstruction(t, "LEAW -7(SI)(DX*8),AX")
					before, expected := state.clone(), state.clone()
					observed := uint8(3)
					if old == "caller" {
						observed = uint8((uint16(1) << uint(word)) - 1)
					}
					expected.gp[0] &^= 3
					expected.pointerGP[0], expected.callerAddressGP[0], expected.callerAddressOrigin[0] = false, false, 0
					expected.nativeLEAAddressBits = x86NativeLEAAddressBits{register: 0, bytes: observed}
					if accepted, known := x86ResultNativeLEAAddressBitsStep(instruction, &state, nil, arch, true); !known || !accepted {
						t.Fatal("complete new low16 address source lost its independent effect", accepted, known)
					}
					// Use the real shared post-consumers: a mixed partial value
					// must not retain the old full-word caller identity or origin.
					state.callerAddressGP = x86ResultCallerAddressesAfterTransfer(instruction, before.callerAddressGP,
						state.callerAddressGP, state.callerAddressFP, arch)
					state.callerAddressOrigin = x86ResultCallerOriginsAfter(instruction, before.callerAddressOrigin,
						state.callerAddressGP, state.callerAddressFP, arch)
					if !reflect.DeepEqual(state, expected) || x86ResultRead(Operand{Kind: OpReg, Reg: AX}, word, &state, nil, arch) {
						t.Fatal("retained address representation became NUM, pointer, caller origin, canonical or unrelated state")
					}
					store := x86ScalarLaneInstruction(t, move+" AX,1(DI)")
					wanted := old == "caller" || old == "numeric" && missing < 2
					for _, scoped := range []bool{false, true} {
						copy := state.clone()
						accepted, known := x86LoweredScalarNativeStoreWithAddressBits(store, &copy, nil, arch, scoped)
						if !known || accepted != (scoped && wanted) || !reflect.DeepEqual(copy, state) {
							t.Fatal("retained bytes escaped their one-store scope or filled a missing old numerical upper byte", scoped, accepted, wanted)
						}
					}
				})
			}
		}
	}
}
