//go:build go1.27

package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// The table oracle is independent of the translator's six semantic entries.
// A name count alone would miss the tuple, zeroing, LL and mask-row attributes.
func TestX86FourSourceCompleteOfficialGoEncoderRows(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]int)
	for _, rule := range rules {
		if !strings.HasPrefix(rule.Opcode, "V4FM") && !strings.HasPrefix(rule.Opcode, "V4FNM") &&
			!strings.HasPrefix(rule.Opcode, "VP4DPW") {
			continue
		}
		opcode, exists := map[string]int{
			"V4FMADDPS": 0x9a, "V4FMADDSS": 0x9b,
			"V4FNMADDPS": 0xaa, "V4FNMADDSS": 0xab,
			"VP4DPWSSD": 0x52, "VP4DPWSSDS": 0x53,
		}[rule.Opcode]
		if !exists || rule.RowIndex < 0 || rule.RowIndex > 1 {
			t.Fatal("official four-source family acquired an unobserved name or row", rule)
		}
		table, source, destination, length := "_yv4fmaddps", "YzrMulti4", "Yzr", "evex512"
		if strings.HasSuffix(rule.Opcode, "SS") {
			table, source, destination, length = "_yv4fmaddss", "YxrEvexMulti4", "YxrEvex", "evex128"
		}
		classes, zcase, advance := []string{"Ym", source, destination}, "Zevex_rm_v_r", 0
		if rule.RowIndex == 1 {
			classes, zcase, advance = []string{"Ym", source, "Yknot0", destination}, "Zevex_rm_v_k_r", 3
		}
		attributes := []string{
			"avxEscape | " + length + " | evexF2 | evex0F38 | evexW0",
			"evexN16 | evexZeroingEnabled", fmt.Sprintf("0x%02X", opcode),
		}
		if rule.Ytab != table || rule.Prefix != "Pavx" || rule.EncodingOffset != 0 ||
			rule.ZOffset != advance || rule.ZCase != zcase || !reflect.DeepEqual(rule.Classes, classes) ||
			!reflect.DeepEqual(rule.OpBytes, attributes) {
			t.Fatal("complete four-source operand/tuple/mask/zeroing/encoding row changed", rule, attributes)
		}
		counts[rule.Opcode]++
	}
	want := map[string]int{
		"V4FMADDPS": 2, "V4FMADDSS": 2, "V4FNMADDPS": 2,
		"V4FNMADDSS": 2, "VP4DPWSSD": 2, "VP4DPWSSDS": 2,
	}
	if !reflect.DeepEqual(counts, want) {
		t.Fatal("complete six-name twelve-row four-source directory changed", counts)
	}
}
