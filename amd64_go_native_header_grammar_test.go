package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// These are format/object-field observations, not captured source permissions.
func nativeHeaderFixture(header string, kind, flags uint8, abi uint16) ([]byte, []gostaticstorage.TextRecord, []gostaticstorage.ASMSourceText) {
	namespace := gostaticstorage.TextSymbolNonpkgDefinition
	if abi == 65535 {
		namespace = gostaticstorage.TextSymbolSelf
	}
	text := gostaticstorage.TextRecord{Name: "fixture.Entry", ABI: abi, Namespace: namespace,
		Kind: kind, Flags: flags, Size: 1, Code: []byte{0xc3}}
	order := gostaticstorage.ASMSourceText{SourceOrdinal: 0, ObjectOrdinal: 0, Name: text.Name,
		ABI: abi, Namespace: namespace}
	return []byte(header + "\n"), []gostaticstorage.TextRecord{text}, []gostaticstorage.ASMSourceText{order}
}

func nativeHeaderRecord(t *testing.T, header string, kind, flags uint8, abi uint16) sdkAMD64FrameNativeRecord {
	t.Helper()
	listing, texts, order := nativeHeaderFixture(header, kind, flags, abi)
	before := append([]gostaticstorage.TextRecord(nil), texts...)
	before[0].Code = append([]byte(nil), texts[0].Code...)
	records, err := sdkAMD64FrameNativeRecordsForSource(listing, texts, order)
	if err != nil || len(records) != 1 {
		t.Fatalf("complete writer header lost its object association: records=%v error=%v header=%q", records, err, header)
	}
	if !reflect.DeepEqual(texts, before) || records[0].Symbol != "fixture.Entry" || records[0].Size != 1 {
		t.Fatal("header parsing rewrote the original object or identity", records)
	}
	return records[0]
}

const nativeHeaderCurrent = "fixture.Entry STEXT nosplit asm size=1 align=0x0 args=0x0 locals=0x0 funcid=0x0"

func TestSDKAMD64NativeHeaderCompleteWriterForms(t *testing.T) {
	for _, row := range []struct {
		name, attributes, tail string
		kind, flags            uint8
		abi                    uint16
	}{
		{"current", "nosplit asm", "size=1 align=0x0 args=0x0 locals=0x0 funcid=0x0", 1, 0x10, 0},
		{"legacy", "nosplit asm", "size=1 args=0x0 locals=0x0 funcid=0x0 align=0x0", 1, 0x10, 0},
		{"minimal-diagnostic", "asm", "size=1 args=0x0 locals=0x0", 1, 0, 0},
		{"static", "static nosplit asm", "size=1 align=0x0 args=0x0 locals=0x0 funcid=0x0", 1, 0x10, 65535},
		{"dupok", "dupok nosplit asm", "size=1 align=0x0 args=0x0 locals=0x0 funcid=0x0", 1, 0x11, 0},
		{"cfunc", "cfunc nosplit", "size=1 align=0x0 args=0x0 locals=0x0 funcid=0x0", 1, 0x10, 0},
		{"topframe", "nosplit topframe asm", "size=1 align=0x0 args=0x0 locals=0x0 funcid=0x0", 1, 0x10, 0},
		{"leaf", "nosplit asm", "size=1 align=0x0 args=0x0 locals=0x0 funcid=0x0 leaf", 1, 0x18, 0},
		{"all-current", "static dupok cfunc nosplit topframe asm", "size=1 align=0x0 args=0xffffffff80000000 locals=0xfffffffffffffff8 funcid=0xff leaf", 2, 0x19, 65535},
		{"all-legacy-format", "static dupok cfunc nosplit topframe asm", "size=1 args=0xffffffff80000000 locals=0xfffffffffffffff8 funcid=0xff align=0x0 leaf", 2, 0x19, 65535},
		{"current-width-boundaries", "nosplit asm", "size=1 align=0x7fff args=0x7fffffff locals=0x7fffffff funcid=0xff", 1, 0x10, 0},
		{"legacy-width-boundaries", "nosplit asm", "size=1 args=0x7fffffff locals=0x7fffffff funcid=0xff align=0x7fffffff", 1, 0x10, 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			kind := "STEXT"
			if row.kind == 2 {
				kind = "STEXTFIPS"
			}
			header := "fixture.Entry " + kind + " " + row.attributes + " " + row.tail
			record := nativeHeaderRecord(t, header, row.kind, row.flags, row.abi)
			if record.Static != (row.abi == 65535) || record.NoSplit != (row.flags&0x10 != 0) ||
				record.ASM != strings.Contains(" "+row.attributes+" ", " asm ") {
				t.Fatal("independent native attributes changed", record)
			}
			if strings.Contains(row.tail, "locals=0xfffffffffffffff8") &&
				(record.Locals != ^uint64(7) || record.ArgsKnown || record.Args != -0x80000000) {
				t.Fatal("writer attributes changed signed locals or the independent argument sentinel", record)
			}
			if strings.Contains(row.tail, "args=0x7fffffff") {
				align := uint64(0x7fff)
				if row.name == "legacy-width-boundaries" {
					align = 0x7fffffff
				}
				if !record.ArgsKnown || record.Args != 0x7fffffff || record.Locals != 0x7fffffff ||
					!record.HasFuncID || record.FuncID != 0xff || !record.HasAlign || record.Align != align {
					t.Fatal("official writer numeric boundary metadata changed", record)
				}
			}
		})
	}
}

func TestSDKAMD64NativeHeaderRetainsObservedMetadata(t *testing.T) {
	base := nativeHeaderRecord(t, nativeHeaderCurrent, 1, 0x10, 0)
	for _, row := range []struct {
		name, header string
		kind, flags  uint8
	}{
		{"kind", strings.Replace(nativeHeaderCurrent, "STEXT", "STEXTFIPS", 1), 2, 0x10},
		{"dupok", strings.Replace(nativeHeaderCurrent, " nosplit", " dupok nosplit", 1), 1, 0x11},
		{"cfunc", strings.Replace(nativeHeaderCurrent, " nosplit", " cfunc nosplit", 1), 1, 0x10},
		{"topframe", strings.Replace(nativeHeaderCurrent, " asm", " topframe asm", 1), 1, 0x10},
		{"leaf", nativeHeaderCurrent + " leaf", 1, 0x18},
		{"funcid", strings.Replace(nativeHeaderCurrent, "funcid=0x0", "funcid=0x1", 1), 1, 0x10},
		{"alignment", strings.Replace(nativeHeaderCurrent, "align=0x0", "align=0x4", 1), 1, 0x10},
		{"absent-funcid", strings.Replace(nativeHeaderCurrent, " funcid=0x0", "", 1), 1, 0x10},
		{"absent-alignment", strings.Replace(nativeHeaderCurrent, " align=0x0", "", 1), 1, 0x10},
		{"legacy-alignment-position", "fixture.Entry STEXT nosplit asm size=1 args=0x0 locals=0x0 funcid=0x0 align=0x0", 1, 0x10},
	} {
		t.Run(row.name, func(t *testing.T) {
			changed := nativeHeaderRecord(t, row.header, row.kind, row.flags, 0)
			if reflect.DeepEqual(base, changed) {
				t.Fatal("distinct observed native metadata was discarded", row.name, base)
			}
		})
	}
}

func TestSDKAMD64NativeHeaderRejectsMalformedWriterForms(t *testing.T) {
	for _, header := range []string{
		strings.Replace(nativeHeaderCurrent, " nosplit", " nosplit nosplit", 1),
		strings.Replace(nativeHeaderCurrent, "nosplit asm", "asm nosplit", 1),
		strings.Replace(nativeHeaderCurrent, "nosplit asm", "nosplit dupok asm", 1),
		strings.Replace(nativeHeaderCurrent, "nosplit asm", "nosplit asm topframe", 1),
		strings.Replace(nativeHeaderCurrent, " nosplit", " foreign nosplit", 1),
		strings.Replace(nativeHeaderCurrent, " nosplit", " noframe nosplit", 1),
		strings.Replace(nativeHeaderCurrent, "STEXT", "STEXTFOREIGN", 1),
		nativeHeaderCurrent + " leaf leaf",
		nativeHeaderCurrent + " junk",
		nativeHeaderCurrent + " align=0x0",
		strings.Replace(nativeHeaderCurrent, "size=1", "size=1 size=1", 1),
		strings.Replace(nativeHeaderCurrent, "size=1", "size=9223372036854775808", 1),
		strings.Replace(nativeHeaderCurrent, "args=0x0", "args=0x80000000", 1),
		strings.Replace(nativeHeaderCurrent, "args=0x0", "args=0xffffffff", 1),
		strings.Replace(nativeHeaderCurrent, "args=0x0", "args=0xffffffffffffffff", 1),
		strings.Replace(nativeHeaderCurrent, "locals=0x0", "locals=0x80000000", 1),
		strings.Replace(nativeHeaderCurrent, "locals=0x0", "locals=0x10000000000000000", 1),
		strings.Replace(nativeHeaderCurrent, "funcid=0x0", "funcid=0x100", 1),
		strings.Replace(nativeHeaderCurrent, "align=0x0", "align=0x8000", 1),
		"fixture.Entry STEXT nosplit asm size=1 args=0x0 locals=0x0 funcid=0x0 align=0x80000000",
	} {
		t.Run(header, func(t *testing.T) {
			listing, texts, order := nativeHeaderFixture(header, 1, 0x10, 0)
			if _, err := sdkAMD64FrameNativeRecordsForSource(listing, texts, order); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("malformed or out-of-range header acquired metadata", header, err)
			}
		})
	}
}

func TestSDKAMD64NativeHeaderObjectAttributeIdentity(t *testing.T) {
	for _, row := range []struct {
		name, attributes, tail string
		mask                   uint8
	}{
		{"dupok", "dupok nosplit asm", "", 0x01},
		{"nosplit", "nosplit asm", "", 0x10},
		{"leaf", "nosplit asm", " leaf", 0x08},
	} {
		t.Run(row.name, func(t *testing.T) {
			header := "fixture.Entry STEXT " + row.attributes + " size=1 align=0x0 args=0x0 locals=0x0 funcid=0x0" + row.tail
			flags := uint8(0x10) | row.mask
			nativeHeaderRecord(t, header, 1, flags, 0)
			listing, texts, order := nativeHeaderFixture(header, 1, flags^row.mask, 0)
			if _, err := sdkAMD64FrameNativeRecordsForSource(listing, texts, order); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("header borrowed a different actual object attribute", row.name, err)
			}
		})
	}
	for _, mask := range []uint8{0x01, 0x08, 0x10} {
		listing, texts, order := nativeHeaderFixture("fixture.Entry STEXT asm size=1 align=0x0 args=0x0 locals=0x0 funcid=0x0", 1, mask, 0)
		if _, err := sdkAMD64FrameNativeRecordsForSource(listing, texts, order); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("unprinted object attribute was silently ignored", mask, err)
		}
	}
}

func TestGoAMD64FrameSplitSelectorUsesCompleteWriterHeader(t *testing.T) {
	for _, attributes := range []string{"asm", "dupok asm", "cfunc asm", "topframe asm", "static dupok cfunc topframe asm"} {
		t.Run(attributes, func(t *testing.T) {
			header := "fixture.Entry STEXT " + attributes + " size=1 align=0x0 args=0x0 locals=0x0 funcid=0x0\n"
			if !goAMD64FrameSplitListing([]byte(header)) {
				t.Fatal("complete split header disappeared before its later role check", header)
			}
			nosplit := strings.Replace(header, " asm ", " nosplit asm ", 1)
			if strings.Contains(attributes, "topframe") {
				nosplit = strings.Replace(header, " topframe ", " nosplit topframe ", 1)
			}
			if goAMD64FrameSplitListing([]byte(nosplit)) {
				t.Fatal("NOSPLIT metadata was interpreted as split entry permission", nosplit)
			}
		})
	}
}
