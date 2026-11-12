//go:build go1.27

package gostaticstorage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGoASMTextMixedNamespaceSourceOrder(t *testing.T) {
	directory, driver, _ := fixture(t)
	oracle := officialReaderForSource(t, driver, sdkTextReaderSource)
	builtin, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(driver)), builtinSourceRole))
	if err != nil {
		t.Fatal(err)
	}
	// An ordinary standalone encoder fixture, not an SDK/native-entry role.
	// Source interleaves foreign, package and static definitions deliberately.
	source := []byte(`TEXT foreign∕pkg·First(SB),4,$0-0
	MOVQ $101, AX
	RET
TEXT ·OwnOne(SB),4,$0-0
	MOVQ $202, AX
	RET
TEXT private<>(SB),4,$0-0
	XORQ AX, AX
	RET
TEXT foreign∕pkg·Second(SB),4,$0-0
	MOVQ $303, AX
	RET
TEXT ·OwnTwo(SB),4,$0-0
	MOVQ $404, AX
	RET
`)
	name := filepath.Join(directory, "mixed.asm")
	if err := os.WriteFile(name, source, 0600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			environment := fixtureEnv(t, target)
			objectPath := filepath.Join(t.TempDir(), "mixed.o")
			run(t, driver, directory, environment, "tool", "asm", "-p", fixtureModule, "-o", objectPath, name)
			object, err := os.ReadFile(objectPath)
			if err != nil {
				t.Fatal(err)
			}
			var actual []TextMember
			if err := json.Unmarshal(run(t, oracle, directory, environment, objectPath), &actual); err != nil || len(actual) != 1 {
				t.Fatal("actual original Go TEXT reader", err)
			}
			for _, record := range actual[0].Texts {
				t.Logf("physical TEXT namespace=%d index=%d relative=%d name=%q ABI=%d", record.Namespace, record.Index, record.Relative, record.Name, record.ABI)
			}
			observed, err := ObserveAMD64AssemblyData(source, object, builtin, fixtureModule, target)
			if err != nil {
				t.Fatal("complete source TEXT association failed", err)
			}
			if !reflect.DeepEqual(observed.Member.Texts, actual[0].Texts) {
				t.Fatal("source association reordered/rewrote original physical records")
			}
			var order []int
			for ordinal, association := range observed.TextOrder {
				if association.SourceOrdinal != ordinal {
					t.Fatal("source TEXT ordinal changed", association)
				}
				order = append(order, association.ObjectOrdinal)
			}
			if !reflect.DeepEqual(order, []int{1, 2, 0, 3, 4}) {
				t.Fatal("actual original namespace/index association differs", order)
			}
		})
	}
}
