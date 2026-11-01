package goasmoracle

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestTrailingListingRequiresExactPhysicalStatement(t *testing.T) {
	source, _ := oracleFixture(t)
	if err := os.WriteFile(source, []byte("TEXT probe(SB),4,$3-0\nRET\n"), 0600); err != nil {
		t.Fatal(err)
	}
	output := "asm: 00001 (" + source + ":1) TEXT probe(SB), NOSPLIT, $3-0: concrete frame error\n"
	wantOriginal := []string{"TEXT", "probe", "(", "SB", ")", ",", "4", ",", "$", "3", "-", "0"}
	wantListing := []string{"TEXT", "probe", "(", "SB", ")", ",", "NOSPLIT", ",", "$", "3", "-", "0"}
	match := func(original, listing []string, detail string) bool {
		return reflect.DeepEqual(original, wantOriginal) && reflect.DeepEqual(listing, wantListing) &&
			detail == "concrete frame error"
	}
	if !SourceDiagnosticLineWithTrailingListing(source, output, 1, match) {
		t.Fatal("complete explicitly selected trailing diagnostic was lost")
	}
	if SourceDiagnosticLine(source, output, 1) || SourceDiagnosticLineWithListing(source, output, 1,
		func(_, _ []string) bool { t.Fatal("ordinary matcher saw a bare backend prefix"); return true }) {
		t.Fatal("default route acquired trailing-diagnostic authority")
	}
	for _, changed := range []string{
		strings.Replace(output, source+":1", source+":2", 1),
		strings.Replace(output, source+":1", "foreign"+source+":1", 1),
		strings.Replace(output, source+":1", source+":01", 1),
		strings.Replace(output, "00001", "1", 1),
		strings.Replace(output, "asm: 00001", "00001", 1),
		strings.Replace(output, "asm: 00001", "asm: unknown 00001", 1),
		strings.Replace(output, "TEXT probe", "TEXT other", 1),
		strings.Replace(output, "NOSPLIT, $3-0", "NOSPLIT", 1),
		strings.Replace(output, ": concrete frame error", "", 1),
		strings.Replace(output, "concrete frame error", "concrete /*hidden*/ frame error", 1),
		strings.Replace(output, "concrete frame error", "unknown frame error", 1),
	} {
		if SourceDiagnosticLineWithTrailingListing(source, changed, 1, match) {
			t.Errorf("changed complete trailing diagnostic acquired a role: %q", changed)
		}
	}
	for _, focus := range []int{-1, 2} {
		if SourceDiagnosticLineWithTrailingListing(source, output, focus, match) {
			t.Errorf("wrong focus %d acquired a trailing role", focus)
		}
	}
	if SourceDiagnosticLineWithTrailingListing(source, output, 1, nil) ||
		SourceDiagnosticLineWithTrailingListing(source+".missing", output, 1, match) {
		t.Fatal("missing matcher or physical source acquired a role")
	}
}
