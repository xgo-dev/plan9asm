package goasmrules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Every actual SDK row must reach the existing cold physical grammar. These
// witnesses do not establish Go encoder selection, LLVM objects or execution.
func TestX86AllOfficialAVXRowsHaveImmutableWitnesses(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil || len(rules) == 0 {
		t.Fatal("complete actual SDK AVX table", len(rules), err)
	}
	for index, original := range rules {
		id := fmt.Sprintf("avx/%d/%s/%s/%d", index, original.Opcode, original.Ytab, original.RowIndex)
		t.Run(id, func(t *testing.T) {
			before, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			witnesses, witnessError := x86PackedAVXRowWitnesses(original)
			after, err := json.Marshal(original)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("cold grammar changed the original SDK row", err)
			}
			if witnessError != nil || len(witnesses) == 0 {
				t.Fatalf("original row has no physical witnesses: %v; source=%s", witnessError, before)
			}
			for _, witness := range witnesses {
				if strings.TrimSpace(witness.Instruction) == "" || len(witness.Encoding) == 0 {
					t.Fatal("physical witness lost source or encoding", witness)
				}
			}
		})
	}
	t.Logf("%d actual SDK AVX source rows checked; no object or runtime claim", len(rules))
}
