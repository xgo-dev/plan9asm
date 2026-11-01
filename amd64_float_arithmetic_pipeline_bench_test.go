package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Keep the public translation workload independent of the production registry.
// Every arithmetic family and precision remains present before and after a
// normalization change; no source/tool subprocess runs inside the timer.
func BenchmarkX86FloatingArithmeticTranslate(b *testing.B) {
	var source strings.Builder
	source.WriteString("TEXT arithmetic(SB),4,$0-0\nVPXOR Y0,Y0,Y0\nVPXOR Y1,Y1,Y1\nVPXOR Y2,Y2,Y2\n")
	var names []string
	names = append(names, x86FloatAddSubOpcodes()...)
	names = append(names, x86FloatMulDivOpcodes()...)
	for _, member := range x86FloatingMinMaxCases {
		names = append(names, member.op)
	}
	if len(names) != 48 {
		b.Fatal("complete named floating arithmetic inventory changed", len(names))
	}
	for _, name := range names {
		operands := "X1,X2"
		if strings.HasPrefix(name, "V") {
			operands = "X0,X1,X2"
		}
		fmt.Fprintf(&source, "%s %s\n", name, operands)
	}
	source.WriteString("RET\n")
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		b.Fatal(err)
	}
	options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"arithmetic": {Name: "arithmetic", Ret: Void}}}
	if _, err := Translate(file, options); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(source.Len()))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := Translate(file, options); err != nil {
			b.Fatal(err)
		}
	}
}
