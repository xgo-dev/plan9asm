//go:build unix

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Inventory is independent of the future scheduling change. These are the
// original full payloads, not new reduced numerical examples or source proofs.
func TestFixedLocalWideAPILeasePreservesCompletePayloadInventory(t *testing.T) {
	for _, row := range []struct {
		all   bool
		count int
	}{{false, 28}, {true, 340}} {
		assembly, declarations, cases := fixedLocalPackedRuntimeProgram(row.all)
		file, err := Parse(ArchAMD64, assembly)
		if err != nil {
			t.Fatal("original complete numerical source no longer parses", err)
		}
		if len(cases) != row.count || len(file.Funcs) != row.count {
			t.Fatal("original complete numerical source changed", row.all, len(cases), err)
		}
		var assembled, declared strings.Builder
		for batch := 0; batch < (row.count+63)/64; batch++ {
			start, end, ok := fixedLocalObjectBatchRange(row.count, batch)
			if !ok || end-start > 64 || end <= start {
				t.Fatal("lost bounded complete-source batch", row.all, batch, start, end)
			}
			// Split at original TEXT boundaries without changing a single raw
			// byte or renaming ValueN; the future real producer must agree.
			for index := start; index < end; index++ {
				begin := strings.Index(assembly, fmt.Sprintf("TEXT ·Value%d(SB)", index))
				finish := len(assembly)
				if index+1 < row.count {
					finish = strings.Index(assembly, fmt.Sprintf("TEXT ·Value%d(SB)", index+1))
				}
				if begin < 0 || finish <= begin || file.Funcs[index].Sym != fmt.Sprintf("·Value%d", index) {
					t.Fatal("missing or substituted original source member", index)
				}
				assembled.WriteString(assembly[begin:finish])
				fmt.Fprintf(&declared, "func Value%d(a, mask uint64) uint64\n", index)
			}
		}
		if assembled.String() != assembly || declared.String() != declarations {
			t.Fatal("source batches changed, cropped or duplicated original full ASM/declarations")
		}
		for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
			goOracle, cOracle := fixedLocalPackedRuntimeOracles(cases, triple)
			if strings.Count(goOracle, "{Value") != row.count || strings.Count(cOracle, "{value") != row.count ||
				strings.Count(cOracle, "extern uint64_t value") != row.count {
				t.Fatal("original Go/C oracle lost a complete source member", triple, row.count)
			}
			for index, entry := range cases {
				goRow := fmt.Sprintf("{Value%d,%d,%d,%d,%d},\n", index, entry.width, entry.bits, entry.word, entry.mode)
				cRow := fmt.Sprintf("{value%d,%d,%d,%d,%d},\n", index, entry.width, entry.bits, entry.word, entry.mode)
				if strings.Count(goOracle, goRow) != 1 || strings.Count(cOracle, cRow) != 1 {
					t.Fatal("original oracle source width/lane/merge/canary axis changed", triple, index)
				}
			}
			for _, required := range []string{
				"const uint64_t values[]={0,1,UINT64_MAX,UINT64_C(0x8000000000000000),UINT64_C(0x123456789abcdef0),UINT64_C(0x7ff81234567890ab)};",
				"const uint64_t masks[]={0,1,UINT64_MAX,UINT64_C(0x5555555555555555),UINT64_C(0xaaaaaaaaaaaaaaaa),UINT64_C(0x8000000000000000)};",
				"for(unsigned v=0;v<6;v++) for(unsigned m=0;m<6;m++)",
				"for(unsigned bit=0;bit<64;bit++)",
			} {
				if !strings.Contains(cOracle, required) {
					t.Fatal("lease repair cannot reduce original C inputs/masks/whole-byte observations", required)
				}
			}
			batches := fixedLocalPackedLeaseBatches(t, row.all, triple)
			if len(batches) != (row.count+63)/64 {
				t.Fatal("source batches omitted a member", triple, len(batches))
			}
			var batchAssembly, batchDeclarations, batchRows, batchPrototypes strings.Builder
			for index, batch := range batches {
				start, end, ok := fixedLocalObjectBatchRange(row.count, index)
				if !ok || batch.start != start || batch.end != end {
					t.Fatal("source batch changed its exact original range", index, batch.start, batch.end)
				}
				observed, err := Parse(ArchAMD64, batch.assembly)
				if err != nil || observed == nil || len(observed.Funcs) != end-start {
					t.Fatal("source batch is not an independently complete source", index, err)
				}
				batchAssembly.WriteString(batch.assembly)
				batchDeclarations.WriteString(batch.declarations)
				batchRows.WriteString(batch.rows)
				batchPrototypes.WriteString(batch.prototypes)
				if strings.Count(batch.oracle, "{value") != end-start {
					t.Fatal("C batch contains an omitted or foreign active oracle row", index)
				}
			}
			if batchAssembly.String() != assembly || batchDeclarations.String() != declarations ||
				!strings.Contains(cOracle, batchRows.String()) || !strings.Contains(cOracle, batchPrototypes.String()) {
				t.Fatal("the bounded source/C union differs from the complete original payload", triple)
			}
		}
	}
}

type fixedLocalPackedLeaseBatch struct {
	start, end                                       int
	assembly, declarations, oracle, rows, prototypes string
}

// This fixture partitions only original input text, before any source owner
// exists. Each future consumer must create a separate real package/capture for
// a batch; it cannot crop a File and borrow the full 340-function capability.
func fixedLocalPackedLeaseBatches(t *testing.T, all bool, triple string) []fixedLocalPackedLeaseBatch {
	t.Helper()
	assembly, declarations, cases := fixedLocalPackedRuntimeProgram(all)
	_, oracle := fixedLocalPackedRuntimeOracles(cases, triple)
	const table = "static const struct entry cases[]={\n"
	prototypeStart := strings.Index(oracle, "extern uint64_t value0(")
	prototypeEnd := strings.Index(oracle, "\nstruct entry {")
	rowStart := strings.Index(oracle, table) + len(table)
	rowEnd := strings.Index(oracle, "\n};\nint main(void)")
	if prototypeStart < 0 || prototypeEnd <= prototypeStart || rowStart < len(table) || rowEnd <= rowStart {
		t.Fatal("original C oracle lost its independent declaration/case boundaries")
	}
	text := strings.SplitAfter(assembly, "RET\n")
	decls := strings.SplitAfter(declarations, "\n")
	prototypes := strings.SplitAfter(oracle[prototypeStart:prototypeEnd], "\n")
	rows := strings.SplitAfter(oracle[rowStart:rowEnd], "\n")
	for name, entries := range map[string][]string{"assembly": text, "declarations": decls, "C prototypes": prototypes, "C rows": rows} {
		if len(entries) != len(cases)+1 || entries[len(cases)] != "" {
			t.Fatal("original fixture has ambiguous source boundaries", name, len(entries), len(cases))
		}
	}
	var batches []fixedLocalPackedLeaseBatch
	for index := 0; index < (len(cases)+63)/64; index++ {
		start, end, ok := fixedLocalObjectBatchRange(len(cases), index)
		if !ok {
			t.Fatal("missing bounded original source range", index)
		}
		batch := fixedLocalPackedLeaseBatch{
			start: start, end: end,
			assembly:     strings.Join(text[start:end], ""),
			declarations: strings.Join(decls[start:end], ""),
			rows:         strings.Join(rows[start:end], ""),
			prototypes:   strings.Join(prototypes[start:end], ""),
		}
		batch.oracle = oracle[:prototypeStart] + batch.prototypes + oracle[prototypeEnd:rowStart] + batch.rows + oracle[rowEnd:]
		batches = append(batches, batch)
	}
	return batches
}
