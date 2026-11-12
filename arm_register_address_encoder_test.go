package plan9asm

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
)

func TestARMRegisterAddressGrammarMatchesGoEncoder(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/arm/asm5.go"))
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`\{AMOVW, C_(RACON|LACON), C_NONE, C_REG, (\d+),[^\n]*C_SBIT\}`).FindAllStringSubmatch(string(source), -1)
	if len(rows) != 2 {
		t.Fatalf("Go register-address family has %d rows, want both small and large classes", len(rows))
	}
	want := map[string]string{"RACON": "4", "LACON": "34"}
	for _, row := range rows {
		if want[row[1]] != row[2] {
			t.Fatalf("unexpected Go register-address row: %s", row[0])
		}
		delete(want, row[1])
	}
	if len(want) != 0 {
		t.Fatalf("missing Go register-address classes: %v", want)
	}
}
