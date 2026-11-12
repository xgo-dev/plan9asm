package gotoolprofile

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestDataOnlyNativeListingRequiresSelectedProducerGrammar(t *testing.T) {
	const legacy = "pkg.data SDATA size=8\n" +
		"\t0x0000 00 00 00 00 00 00 00 00                          ........\n" +
		"pkg.zero SBSS size=16\n"
	current := strings.ReplaceAll(strings.ReplaceAll(legacy, "size=8\n", "size=8 align=0x0\n"),
		"size=16\n", "size=16 align=0x0\n")
	for minor := 20; minor <= 27; minor++ {
		version := fmt.Sprintf("go1.%d.1", minor)
		t.Run(version, func(t *testing.T) {
			accepted, refused := legacy, current
			if minor == 27 {
				accepted, refused = current, legacy
			}
			got, err := DataOnlySymbolsFromListingForGoVersion([]byte(accepted), version)
			want := []DataOnlySymbol{{Name: "pkg.data", Kind: "SDATA", Size: 8}, {Name: "pkg.zero", Kind: "SBSS", Size: 16}}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("producer inventory mismatch: %+v %v", got, err)
			}
			for _, malformed := range []string{refused, accepted + refused,
				strings.Replace(accepted, "SDATA", "STEXT", 1), accepted + "tool warning\n"} {
				if _, err := DataOnlySymbolsFromListingForGoVersion([]byte(malformed), version); err == nil {
					t.Fatal("wrong producer or non-data listing accepted", malformed)
				}
			}
		})
	}
	for _, version := range []string{"", "go1.19.13", "go1.28.1", "unknown"} {
		if _, err := DataOnlySymbolsFromListingForGoVersion([]byte(current), version); err == nil {
			t.Fatal("unknown producer acquired a listing grammar", version)
		}
	}
	if _, err := DataOnlySymbolsFromListing([]byte(legacy)); err == nil {
		t.Fatal("current-only entry silently accepted a missing alignment field")
	}
}

func TestDataOnlyNativeListingCompleteGrammar(t *testing.T) {
	const listing = "pkg.data SDATA size=8 align=0x0\n\t0x0000 f0 de bc 9a 78 56 34 12                          ....xV4.\n" +
		"pkg.zero SBSS size=16 align=0x0\n" +
		"local SRODATA static dupok size=8 align=0x0\n\t0x0000 00 00 00 00 00 00 00 00                          ........\n\trel 0+8 t=R_ADDR pkg.data+0\n"
	want := []DataOnlySymbol{
		{Name: "local", Kind: "SRODATA", Static: true, Size: 8},
		{Name: "pkg.data", Kind: "SDATA", Size: 8},
		{Name: "pkg.zero", Kind: "SBSS", Size: 16},
	}
	got, err := DataOnlySymbolsFromListing([]byte(listing))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("complete data/relocation listing: got=%+v err=%v", got, err)
	}
	for name, source := range map[string]string{
		"empty":            "",
		"TEXT":             "pkg.fn STEXT nosplit size=1 args=0x0 locals=0x0 funcid=0x0\n",
		"mixed TEXT":       listing + "pkg.fn STEXT size=1 align=0x0\n",
		"unknown kind":     "pkg.other SUNDEFINED size=8 align=0x0\n",
		"unknown record":   listing + "tool warning\n",
		"headerless data":  "\t0x0000 00 00                          ..\n",
		"instruction body": "pkg.data SDATA size=8 align=0x0\n\t0x0000 00000 (source.s:2) RET\n",
		"duplicate":        listing + "pkg.zero SBSS size=16 align=0x0\n",
		"missing newline":  "pkg.zero SBSS size=16 align=0x0",
		"overflow size":    "pkg.zero SBSS size=9223372036854775808 align=0x0\n",
		"negative size":    "pkg.zero SBSS size=-1 align=0x0\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DataOnlySymbolsFromListing([]byte(source)); err == nil {
				t.Fatal("non-data or incomplete original listing was accepted")
			}
		})
	}
	for _, kind := range []string{"SRODATA", "SRODATAFIPS", "SDATA", "SDATAFIPS", "SNOPTRDATA", "SNOPTRDATAFIPS", "SBSS", "SNOPTRBSS", "STLSBSS"} {
		t.Run(kind, func(t *testing.T) {
			if _, err := DataOnlySymbolsFromListing([]byte("pkg.symbol " + kind + " size=8 align=0x0\n")); err != nil {
				t.Fatal(err)
			}
		})
	}
}
