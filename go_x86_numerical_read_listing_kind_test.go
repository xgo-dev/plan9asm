package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const numericalListingKindTestRow = "\t0x0000 00000 (original.s:4)\tRET\n"

// cmd/internal/obj/objfile.go emits these flags in this exact order for any
// IsText kind. This is display ownership only, never an instruction, storage
// or ABI permission. Real current-SDK producer priors live in the paired test.
func TestGoX86NumericalNativeListingCompleteTextKindHeaders(t *testing.T) {
	flags := []string{"static", "dupok", "cfunc", "nosplit", "topframe", "asm", "leaf"}
	for _, kind := range []string{"STEXT", "STEXTFIPS"} {
		for bits := 0; bits < 1<<len(flags); bits++ {
			t.Run(fmt.Sprintf("%s/flags%02x", kind, bits), func(t *testing.T) {
				var attributes []string
				for index, flag := range flags[:len(flags)-1] {
					if bits&(1<<index) != 0 {
						attributes = append(attributes, flag)
					}
				}
				header := "sample.owner " + kind + " "
				if len(attributes) != 0 {
					header += strings.Join(attributes, " ") + " "
				}
				header += "size=1 align=0x0 args=0xffffffff locals=0x0 funcid=0x0"
				if bits&(1<<(len(flags)-1)) != 0 {
					header += " leaf"
				}
				rows, err := numericalListingRows([]byte(header + "\n" + numericalListingKindTestRow))
				if err != nil || len(rows) != 1 || len(rows["sample.owner"][0]) != 1 ||
					rows["sample.owner"][0][0].ins.Op != OpRET {
					t.Fatal("complete writer-ordered text header lost its own native PC", header, rows, err)
				}
			})
		}
	}
	for _, header := range []string{
		"sample.owner STEXT nosplit size=1 args=0x0 locals=0x0",
		"sample.owner STEXT nosplit asm size=1 args=0x0 locals=0x0 funcid=0x0 align=0x0",
		"sample.owner STEXT static nosplit size=1 args=0xffffffff locals=0x0",
	} {
		if rows, err := numericalListingRows([]byte(header + "\n" + numericalListingKindTestRow)); err != nil || len(rows["sample.owner"][0]) != 1 {
			t.Fatal("original historical writer grammar regressed", header, rows, err)
		}
	}
}

func TestGoX86NumericalNativeListingUnknownOwnersFailClosed(t *testing.T) {
	const first = "sample.first STEXT nosplit asm size=1 align=0x0 args=0x0 locals=0x0 funcid=0x0\n"
	const second = "sample.second STEXTFIPS nosplit asm size=1 align=0x0 args=0x0 locals=0x0 funcid=0x0\n"
	rows, err := numericalListingRows([]byte(first + numericalListingKindTestRow + second + numericalListingKindTestRow))
	if err != nil || len(rows) != 2 || len(rows["sample.first"][0]) != 1 || len(rows["sample.second"][0]) != 1 {
		t.Error("mixed legitimate text kinds did not retain separate complete owners", rows, err)
	}
	for _, kind := range []string{"STEXT", "STEXTFIPS"} {
		base := "foreign.owner " + kind + " nosplit asm size=1 align=0x0 args=0x0 locals=0x0 funcid=0x0"
		for name, changed := range map[string]string{
			"unknown-kind":   strings.Replace(base, kind, kind+"UNKNOWN", 1),
			"foreign-kind":   strings.Replace(base, kind, "MYSTERY", 1),
			"unknown-flag":   strings.Replace(base, "nosplit", "mystery nosplit", 1),
			"duplicate-kind": strings.Replace(base, kind, kind+" "+kind, 1),
			"duplicate-flag": strings.Replace(base, "nosplit", "nosplit nosplit", 1),
			"flag-order":     strings.Replace(base, "nosplit asm", "asm nosplit", 1),
			"size":           strings.Replace(base, "size=1", "size=x", 1),
			"missing-size":   strings.Replace(base, "size=1 ", "", 1),
			"args":           strings.Replace(base, "args=0x0", "args=unknown", 1),
			"missing-args":   strings.Replace(base, "args=0x0 ", "", 1),
			"locals":         strings.Replace(base, "locals=0x0", "locals=0x", 1),
			"funcid":         strings.Replace(base, "funcid=0x0", "funcid=0xg", 1),
			"align":          strings.Replace(base, "align=0x0", "align=unknown", 1),
			"trailing":       base + " foreign",
			"missing-name":   strings.TrimPrefix(base, "foreign.owner "),
		} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				// Check both the first header and a header after a valid owner:
				// the latter must not silently append a foreign PC to that owner.
				for _, prefix := range []string{"", first + numericalListingKindTestRow} {
					rows, err := numericalListingRows([]byte(prefix + changed + "\n" + numericalListingKindTestRow))
					if rows != nil || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("unknown complete listing header borrowed the preceding owner", changed, rows, err)
					}
				}
			})
		}
	}
	for name, listing := range map[string]string{
		"duplicate":  first + numericalListingKindTestRow + first + numericalListingKindTestRow,
		"mixed-kind": first + numericalListingKindTestRow + strings.Replace(second, "sample.second", "sample.first", 1) + numericalListingKindTestRow,
		"data-owner": first + numericalListingKindTestRow + "sample.data SRODATA size=1 align=0x1\n" + numericalListingKindTestRow,
		"unbound":    numericalListingKindTestRow,
	} {
		t.Run(name, func(t *testing.T) {
			if rows, err := numericalListingRows([]byte(listing)); rows != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("duplicate, mixed-kind or non-text owner supplied a native PC", rows, err)
			}
		})
	}
}

func TestGoX86NumericalNativeListingTruncatedNonTextCannotBorrowOwner(t *testing.T) {
	const text = "sample.first STEXT nosplit asm size=1 align=0x0 args=0x0 locals=0x0 funcid=0x0\n"
	for name, header := range map[string]string{
		"rodata":       "sample.data SRODATA",
		"data":         "sample.data SDATA align=0x1",
		"bss":          "sample.data SNOPTRBSS dupok",
		"unknown-kind": "sample.future SFUTURE",
		"foreign-kind": "sample.future MYSTERY",
	} {
		for _, previous := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/previous=%t", name, previous), func(t *testing.T) {
				prefix := ""
				if previous {
					prefix = text + numericalListingKindTestRow
				}
				listing := prefix + header + "\n" + numericalListingKindTestRow
				if rows, err := numericalListingRows([]byte(listing)); rows != nil || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("truncated non-text header borrowed the preceding native owner", header, rows, err)
				}
			})
		}
	}
	// A real non-text display has data bytes, not Prog rows. It terminates the
	// previous body without preventing a later complete TEXT from owning PCs.
	listing := text + numericalListingKindTestRow + "sample.data SRODATA size=1 align=0x1\n\t0x0000 00 .\n" +
		strings.Replace(text, "sample.first", "sample.second", 1) + numericalListingKindTestRow
	if rows, err := numericalListingRows([]byte(listing)); err != nil || len(rows) != 2 ||
		len(rows["sample.first"][0]) != 1 || len(rows["sample.second"][0]) != 1 {
		t.Fatal("non-text display changed the two independent native body owners", rows, err)
	}
}
