// Package x86x87 defines shared x87 instruction formats.
package x86x87

// VisitArithmetic enumerates Go's x87 arithmetic stems and legal suffixes.
// 386 and amd64 use the same rows.
func VisitArithmetic(visit func(stem, suffix string)) {
	for _, stem := range [...]string{"FADD", "FMUL", "FSUB", "FSUBR", "FDIV", "FDIVR"} {
		for _, suffix := range [...]string{"W", "L", "F", "D", "DP"} {
			visit(stem, suffix)
		}
	}
}
