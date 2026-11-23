// Package x86cmov defines the Go x86 conditional-move instruction family.
package x86cmov

// Visit enumerates the source names in Go's yml_rl table. Source mode and
// operand legality are checked separately by the translator.
func Visit(visit func(name string, bits int, condition string)) {
	widths := [...]struct {
		suffix string
		bits   int
	}{{"W", 16}, {"L", 32}, {"Q", 64}}

	for _, width := range widths {
		for _, condition := range [...]string{
			"CC", "CS", "EQ", "GE", "GT", "HI", "LE", "LS",
			"LT", "MI", "NE", "OC", "OS", "PC", "PL", "PS",
		} {
			visit("CMOV"+width.suffix+condition, width.bits, condition)
		}
	}
}
