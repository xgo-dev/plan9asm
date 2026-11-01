package plan9asm

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// Offline decoder regressions captured from the actual Go 1.27.1 linux/arm64
// wrappers in TestARM64ByteCarrierSignedActualWrapper. These bytes grant no
// source/caller authority; the current-Go test independently reproduces them.
// Keep this framework check available to the minimum supported Go version.
func TestARM64ByteCarrierSignedEntrySnapshots(t *testing.T) {
	for _, row := range []struct {
		name, resultRead string
		result           LLVMType
		bytes            int64
	}{
		{"int8", "e0438039", I8, 1}, {"uint8", "e0434039", I8, 1},
		{"int16", "e0238079", I16, 2}, {"uint16", "e0234079", I16, 2},
		{"int32", "e01380b9", I32, 4}, {"uint32", "e01340b9", I32, 4},
	} {
		t.Run(row.name, func(t *testing.T) {
			code, err := hex.DecodeString("fe0f1ef8fd831ff8fd2300d1e00700f900000094" + row.resultRead +
				"fd835ff8fe0742f8c0035fd6000000000000000000000000")
			if err != nil {
				t.Fatal(err)
			}
			name := "example.invalid/signedcarrier.value_" + row.name
			text := gostaticstorage.TextRecord{
				Name: name, ABI: 1, Size: int64(len(code)), Code: code,
				Relocations: []gostaticstorage.TextRelocation{{
					Offset: 16, Size: 4, Type: 9,
					Target: gostaticstorage.TextReference{Name: name, ABI: 0, ABIKnown: true},
				}},
			}
			signature := FuncSig{
				Name: name, Args: []LLVMType{I64}, Ret: row.result,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Type: I64, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: row.result, Field: -1}},
				},
			}
			entry, err := arm64ByteCarrierTypedEntry(text, signature)
			if err != nil || entry.allocation != 32 || entry.dataStart != 8 || entry.dataBytes != 16 ||
				entry.callPC != 16 || entry.continuationPC != 20 || len(entry.resultLoads) != 1 ||
				entry.resultLoads[0].PC != 20 || entry.resultLoads[0].Offset != 16 || entry.resultLoads[0].Bytes != row.bytes {
				t.Fatal("complete compiler wrapper read effects differ", entry, err)
			}
			if row.name == "int32" {
				// The otherwise consistent size/offset must not let a reserved
				// 64-bit sign-extending load impersonate an ordinary i64 read.
				binary.LittleEndian.PutUint32(text.Code[20:], 0xf9800be0)
				signature.Ret, signature.Frame.Results[0].Type = I64, I64
				if _, err := arm64ByteCarrierTypedEntry(text, signature); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("reserved 64-bit sign extension accepted", err)
				}
			}
		})
	}
}
