package plan9asm

import (
	"strings"
	"testing"
)

func TestX86InsertExtractOracleCannotWrapFailureToSuccess(t *testing.T) {
	rows := x86InsertExtractNumericalRows()
	if len(rows) != 290 {
		t.Fatalf("complete independent insert/extract matrix: got %d, want 290", len(rows))
	}
	// This is a live entry, not one of the separately owned masked native
	// stores. Its old index+1 exit status was 256 and wrapped to success.
	if strings.Contains(rows[255], "K1") {
		t.Fatalf("selected mutation no longer belongs to this runtime matrix: %s", rows[255])
	}
	program := `#include <stdio.h>
static void transfer255(void) {}
static int check(void (*fn)(void), ...) { return 1; }
int main(void) {
` + x86InsertExtractRuntimeCheck("transfer255", make([]int, 13)...) + "return 0;\n}\n"
	requireX86GeneratedOracleFailure(t, program, "transfer255 numerical/canary failure")
}
