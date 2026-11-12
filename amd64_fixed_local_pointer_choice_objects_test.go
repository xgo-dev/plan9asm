package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalPointerChoiceProgram(t *testing.T, data string, rows []fixedLocalPointerChoiceCase) (string, string) {
	t.Helper()
	var assembly, declarations strings.Builder
	assembly.WriteString(data)
	for index, row := range rows {
		_, _, source := fixedLocalPointerChoiceFixture(t, row.body)
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(source, "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(p,q *uint64,a uint64) uint64\n", name)
		t.Logf("complete function example.invalid/framefixture.%s: %s", name, row.name)
	}
	t.Logf("complete assembly: functions=%d sha256=%x", len(rows), sha256.Sum256([]byte(assembly.String())))
	return assembly.String(), declarations.String()
}

func TestGoAMD64FixedLocalNativePointerChoiceObjects(t *testing.T) {
	rows := fixedLocalNativePointerChoiceCases()
	if len(rows) != 3 {
		t.Fatal("expected one native-input CMOV and two CFG joins", len(rows))
	}
	assembly, declarations := fixedLocalPointerChoiceProgram(t, "", rows)
	fixedLocalCompleteVectorObjects(t, assembly, declarations, len(rows))
}
