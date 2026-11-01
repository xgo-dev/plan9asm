package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestSDKAMD64NativeFrameSignedLocalsRepresentation(t *testing.T) {
	for _, locals := range []int32{0, 1, 8, 0x7fffffff, -1, -8, -0x80000000} {
		for _, kind := range []uint8{1, 2} {
			t.Run(fmt.Sprintf("locals-%d/kind-%d", locals, kind), func(t *testing.T) {
				label := "STEXT"
				if kind == 2 {
					label = "STEXTFIPS"
				}
				// The official writer prints uint64(FuncInfo.Locals), whose
				// source type is int32. Preserve that exact representation.
				bits := uint64(int64(locals))
				listing := []byte(fmt.Sprintf("fixture.Entry %s nosplit asm size=1 args=0x0 locals=0x%x\n", label, bits))
				texts := []gostaticstorage.TextRecord{{Name: "fixture.Entry", Kind: kind, Flags: 0x10, Size: 1, Code: []byte{0xc3}}}
				records, err := sdkAMD64FrameNativeRecords(listing, texts)
				if err != nil || len(records) != 1 || records[0].Locals != bits {
					t.Fatalf("canonical signed int32 locals lost their original metadata bits: records=%v error=%v", records, err)
				}
				if records[0].Symbol != texts[0].Name || !records[0].NoSplit || !records[0].ASM || !records[0].ArgsKnown {
					t.Fatal("signed locals changed an independent native frame role", records[0])
				}
			})
		}
	}
}

func TestSDKAMD64NativeFrameRejectsNoncanonicalLocals(t *testing.T) {
	texts := []gostaticstorage.TextRecord{{Name: "fixture.Entry", Kind: 1, Flags: 0x10, Size: 1, Code: []byte{0xc3}}}
	for _, locals := range []string{"80000000", "ffffffff", "100000000", "ffffffff7fffffff", "10000000000000000", "nothex", ""} {
		t.Run("locals-"+locals, func(t *testing.T) {
			listing := []byte("fixture.Entry STEXT nosplit asm size=1 args=0x0 locals=0x" + locals + "\n")
			if _, err := sdkAMD64FrameNativeRecords(listing, texts); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("noncanonical or out-of-range signed locals acquired native metadata", locals, err)
			}
		})
	}
}

func TestSDKAMD64OriginalFrameNativeCompleteMetadata(t *testing.T) {
	texts := []gostaticstorage.TextRecord{{Name: "private", Kind: 1, Flags: 0x10, Size: 1, Code: []byte{0xc3}}, {Name: "sdk.Entry", Kind: 1, Size: 1, Code: []byte{0xc3}}}
	listing := []byte("private STEXT static nosplit asm size=1 align=0x0 args=0xffffffff80000000 locals=0x0 funcid=0x0\n" +
		"sdk.Entry STEXT asm size=1 align=0x0 args=0x61 locals=0x128 funcid=0x0\n")
	records, err := sdkAMD64FrameNativeRecords(listing, texts)
	if err != nil || len(records) != 2 || !records[0].Static || !records[0].NoSplit || records[0].ArgsKnown ||
		records[0].Args != -0x80000000 || records[1].NoSplit || !records[1].ArgsKnown || records[1].Args != 97 || records[1].Locals != 296 {
		t.Fatal("private unknown args or stack-split native frame was disguised as a declared leaf", records, err)
	}
	for _, raw := range []string{
		"sdk.Entry STEXT asm size=1 args=0x61 locals=0x128\n",
		"private STEXT static nosplit asm size=1 args=0xffffffff80000000 locals=0x0\n",
		"private STEXT static nosplit asm size=2 args=0xffffffff80000000 locals=0x0\n",
		"private STEXT foreign size=1 args=0x0 locals=0x0\n",
		string(listing) + string(listing),
	} {
		if _, err := sdkAMD64FrameNativeRecords([]byte(raw), texts); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("partial, reordered, foreign or duplicate native frame inventory survived", raw, err)
		}
	}
}

func TestSDKAMD64NativeFrameTextKindsKeepExactObjectIdentity(t *testing.T) {
	for _, kinds := range [][]uint8{{1, 1}, {2, 2}, {1, 2}, {2, 1}} {
		t.Run(fmt.Sprint(kinds), func(t *testing.T) {
			var listing strings.Builder
			var texts []gostaticstorage.TextRecord
			for index, kind := range kinds {
				name := fmt.Sprintf("fixture.Entry%d", index)
				label := "STEXT"
				if kind == 2 {
					label = "STEXTFIPS"
				}
				fmt.Fprintf(&listing, "%s %s nosplit asm size=1 align=0x0 args=0x0 locals=0x0 funcid=0x0\n", name, label)
				texts = append(texts, gostaticstorage.TextRecord{Name: name, Kind: kind, Flags: 0x10, Size: 1, Code: []byte{0xc3}})
			}
			raw := []byte(listing.String())
			records, err := sdkAMD64FrameNativeRecords(raw, texts)
			if err != nil || len(records) != len(texts) {
				t.Fatal("complete ordinary/FIPS TEXT listing lost native frames", records, err)
			}
			for index, record := range records {
				if record.Symbol != texts[index].Name || !record.NoSplit || !record.ASM || !record.ArgsKnown {
					t.Fatal("native frame identity or attributes changed", record)
				}
				for _, wrongKind := range []uint8{0, 3 - texts[index].Kind, 3} {
					changed := append([]gostaticstorage.TextRecord(nil), texts...)
					changed[index].Kind = wrongKind
					if _, err := sdkAMD64FrameNativeRecords(raw, changed); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("listing borrowed a different object TEXT/storage kind", index, wrongKind, err)
					}
				}
			}
			for _, changed := range []string{
				strings.SplitAfter(listing.String(), "\n")[0],
				listing.String() + listing.String(),
				strings.Replace(listing.String(), " nosplit", " foreign", 1),
				strings.Replace(listing.String(), " asm", " dupok asm", 1),
				strings.Replace(listing.String(), "STEXT", "STEXTFOREIGN", 1),
			} {
				if _, err := sdkAMD64FrameNativeRecords([]byte(changed), texts); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("incomplete, duplicate or unobserved listing acquired native frames", changed, err)
				}
			}
		})
	}
}

func TestSDKAMD64OriginalFrameNativeListingByteBoundary(t *testing.T) {
	source := &GoX86SDKASMDataSource{}
	if err := source.retainSDKFrameListingBytes(sdkAMD64FrameListingBytes); err != nil {
		t.Fatal("exact SDK-primary listing byte boundary", err)
	}
	for _, added := range []int{1, -1} {
		if err := source.retainSDKFrameListingBytes(added); !errors.Is(err, ErrProbeNeedsContext) ||
			source.frameListingBytes != sdkAMD64FrameListingBytes {
			t.Fatal("oversized native listing changed its retained accounting", added, err)
		}
	}
}
