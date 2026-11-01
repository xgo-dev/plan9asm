package plan9asm

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestSDKAMD64NativeFrameMixedNamespaceSourceOrder(t *testing.T) {
	member := gostaticstorage.ASMDataMember{Flags: 4, Texts: []gostaticstorage.TextRecord{
		{Name: "private", ABI: 65535, Namespace: gostaticstorage.TextSymbolSelf, Kind: 1, Flags: 0x10, Size: 1, Code: []byte{0xc3}},
		{Name: "foreign.Entry", ABI: 1, Namespace: gostaticstorage.TextSymbolNonpkgDefinition, Index: 10, Kind: 1, Flags: 0x10, Size: 1, Code: []byte{0xc3}},
		{Name: "fixture.Own", Namespace: gostaticstorage.TextSymbolNonpkgDefinition, Index: 11, Relative: 1, Kind: 1, Flags: 0x10, Size: 1, Code: []byte{0xc3}},
	}}
	source := []byte("TEXT foreign·Entry<ABIInternal>(SB),4,$0-0\nRET\nTEXT private<>(SB),4,$0-0\nRET\nTEXT ·Own(SB),4,$0-0\nRET\n")
	order, err := gostaticstorage.ASMSourceTextOrder(source, "fixture", member)
	if err != nil || len(order) != 3 {
		t.Fatal("complete physical source association", err)
	}
	listing := []byte("foreign.Entry STEXT nosplit asm size=1 args=0x0 locals=0x0\nprivate STEXT static nosplit asm size=1 args=0x0 locals=0x0\nfixture.Own STEXT nosplit asm size=1 args=0x0 locals=0x0\n")
	before := append([]gostaticstorage.TextRecord(nil), member.Texts...)
	records, err := sdkAMD64FrameNativeRecordsForSource(listing, member.Texts, order)
	if err != nil || len(records) != 3 {
		t.Fatal("source-order listing must join the unchanged physical object", err)
	}
	if records[0].Symbol != "foreign.Entry" || records[1].Symbol != "private" || !records[1].Static ||
		records[2].Symbol != "fixture.Own" || !reflect.DeepEqual(before, member.Texts) {
		t.Fatal("native metadata lost source order or rewrote original evidence")
	}
	for _, mutate := range []func([]gostaticstorage.ASMSourceText){
		func(m []gostaticstorage.ASMSourceText) { m[0].SourceOrdinal++ },
		func(m []gostaticstorage.ASMSourceText) { m[0].ObjectOrdinal = m[1].ObjectOrdinal },
		func(m []gostaticstorage.ASMSourceText) { m[0].ObjectOrdinal = 3 },
		func(m []gostaticstorage.ASMSourceText) { m[0].Name += "foreign" },
		func(m []gostaticstorage.ASMSourceText) { m[0].ABI = 0 },
		func(m []gostaticstorage.ASMSourceText) { m[0].Namespace = gostaticstorage.TextSymbolSelf },
		func(m []gostaticstorage.ASMSourceText) { m[0].Index++ },
		func(m []gostaticstorage.ASMSourceText) { m[0].Relative++ },
	} {
		changed := append([]gostaticstorage.ASMSourceText(nil), order...)
		mutate(changed)
		if _, err := sdkAMD64FrameNativeRecordsForSource(listing, member.Texts, changed); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("unclosed/duplicate physical mapping became native source metadata", err)
		}
	}
	if _, err := sdkAMD64FrameNativeRecordsForSource(listing, member.Texts, order[:2]); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("missing source ordinal became native metadata", err)
	}
	wrongStatic := bytes.Replace(listing, []byte(" STEXT static"), []byte(" STEXT"), 1)
	if _, err := sdkAMD64FrameNativeRecordsForSource(wrongStatic, member.Texts, order); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("static object acquired a named listing role", err)
	}
}
