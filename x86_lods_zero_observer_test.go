package plan9asm

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var x86LODSObserverSSA = `%[-A-Za-z0-9._]+`

// This deliberately recognizes only the straight-line four-cell observation
// emitted by this fixture. It is not an LLVM interpreter or a native execution
// oracle. In particular, an unclassified store or call cannot be ignored.
func x86LODSCheckZeroOutputStores(body string, row x86LODSStateCase) error {
	word := 8
	if row.arch == "386" {
		word = 4
	}
	bits := 8 * word
	expected := x86LODSStateExpected(row)
	ssa := x86LODSObserverSSA
	assignment := func(expression string) *regexp.Regexp {
		return regexp.MustCompile(`^(` + ssa + `) = ` + expression + `$`)
	}
	outputInteger := assignment(fmt.Sprintf(`ptrtoint ptr %%out to i%d`, bits))
	sourceInteger := assignment(fmt.Sprintf(`ptrtoint ptr %%source to i%d`, bits))
	addition := assignment(fmt.Sprintf(`add i%d (%s), (-?[0-9]+)`, bits, ssa))
	pointer := assignment(fmt.Sprintf(`inttoptr i%d (%s) to ptr`, bits, ssa))
	privateGEP := assignment(fmt.Sprintf(`getelementptr inbounds(?: nuw)? i8, ptr (%s), i%d ([0-9]+)`, ssa, bits))
	privateInteger := assignment(fmt.Sprintf(`ptrtoint ptr (%s) to i%d`, ssa, bits))
	privateAlloca := assignment(`alloca \[256 x i8\], align 1`)
	// Native output MOVs retain volatile; private numerical cells need not.
	// Both spellings still require the same complete width/value/address proof.
	store := regexp.MustCompile(`^store(?: volatile)? i([0-9]+) ([^ ,]+), ptr (` + ssa + `), align ([0-9]+)$`)
	directionCall := regexp.MustCompile(`^(?:tail )?call void asm sideeffect "(?:cld|std)", "~\{dirflag\}"\(\)(?: #[0-9]+)?$`)
	lifetimeCall := regexp.MustCompile(`^call void @llvm\.lifetime\.(?:start|end)\.p0\(ptr nonnull (` + ssa + `)\)$`)

	outputInts, sourceInts := map[string]bool{}, map[string]bool{}
	privateBases, privateOffsets := map[string]bool{}, map[string]int{}
	outputOffsets, addressOffsets := map[string]int{}, map[string]int{"%out": 0}
	privateAddresses := map[string]bool{}
	seen := [4]bool{}
	privateStores, outputAlloca := 0, false
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "br ") || strings.HasPrefix(line, "switch ") ||
			strings.HasPrefix(line, "indirectbr ") || strings.HasPrefix(line, "invoke ") || strings.Contains(line, "callbr ") ||
			strings.Contains(line, "atomicrmw ") || strings.Contains(line, "cmpxchg ") ||
			(strings.HasSuffix(line, ":") && line != "entry:") {
			return fmt.Errorf("observer is not single-entry straight-line: %s", line)
		}
		if strings.Contains(line, "call ") && !directionCall.MatchString(line) {
			match := lifetimeCall.FindStringSubmatch(line)
			if match == nil || !privateBases[match[1]] {
				return fmt.Errorf("unclassified observer call: %s", line)
			}
		}
		if line == fmt.Sprintf("%%out = alloca [4 x i%d], align %d", bits, word) {
			outputAlloca = true
		}
		if match := privateAlloca.FindStringSubmatch(line); match != nil {
			privateBases[match[1]] = true
		}
		if match := outputInteger.FindStringSubmatch(line); match != nil {
			outputInts[match[1]] = true
		}
		if match := sourceInteger.FindStringSubmatch(line); match != nil {
			sourceInts[match[1]] = true
		}
		if match := privateGEP.FindStringSubmatch(line); match != nil && privateBases[match[2]] {
			offset, _ := strconv.Atoi(match[3])
			privateOffsets[match[1]] = offset
		}
		if match := privateInteger.FindStringSubmatch(line); match != nil {
			if offset, ok := privateOffsets[match[2]]; ok {
				privateOffsets[match[1]] = offset
			}
		}
		if match := addition.FindStringSubmatch(line); match != nil {
			delta, _ := strconv.Atoi(match[3])
			if outputInts[match[2]] {
				outputOffsets[match[1]] = delta
			}
			if offset, ok := privateOffsets[match[2]]; ok && delta == -word {
				privateOffsets[match[1]] = offset + delta
			}
		}
		if match := pointer.FindStringSubmatch(line); match != nil {
			if offset, ok := outputOffsets[match[2]]; ok {
				addressOffsets[match[1]] = offset
			}
			if offset, ok := privateOffsets[match[2]]; ok && offset >= 0 && offset+word <= 256 {
				privateAddresses[match[1]] = true
			}
		}
		if !strings.HasPrefix(line, "store ") {
			continue
		}
		match := store.FindStringSubmatch(line)
		if match == nil || match[1] != strconv.Itoa(bits) {
			return fmt.Errorf("unclassified or wrong-width observer store: %s", line)
		}
		value, destination := match[2], match[3]
		if privateAddresses[destination] {
			privateStores++
			if privateStores > 1 || value != strconv.FormatUint(expected.flags|2, 10) {
				return fmt.Errorf("private PUSHF cell changed: %s", line)
			}
			continue
		}
		offset, ok := addressOffsets[destination]
		if !ok || offset < 0 || offset%word != 0 || offset >= 4*word || match[4] != strconv.Itoa(word) {
			return fmt.Errorf("store is not an exact output cell: %s", line)
		}
		cell := offset / word
		if seen[cell] {
			return fmt.Errorf("output cell written more than once: %s", line)
		}
		seen[cell] = true
		want := []string{strconv.FormatUint(expected.ax, 10), "source", "0", strconv.FormatUint(expected.flags, 10)}[cell]
		if (cell == 1 && !sourceInts[value]) || (cell != 1 && value != want) {
			return fmt.Errorf("output cell %d got %s, want %s", cell, value, want)
		}
	}
	if !outputAlloca || seen != [4]bool{true, true, true, true} {
		return fmt.Errorf("missing fresh output or one of its four complete stores: %t %v", outputAlloca, seen)
	}
	return nil
}

func x86LODSZeroStoreTemplate(row x86LODSStateCase) string {
	word := 8
	if row.arch == "386" {
		word = 4
	}
	bits, expected := 8*word, x86LODSStateExpected(row)
	var body strings.Builder
	body.WriteString("entry:\n")
	fmt.Fprintf(&body, "%%out = alloca [4 x i%d], align %d\n", bits, word)
	fmt.Fprintf(&body, "%%oi = ptrtoint ptr %%out to i%d\n%%si = ptrtoint ptr %%source to i%d\n", bits, bits)
	fmt.Fprintf(&body, "store i%d %d, ptr %%out, align %d\n", bits, expected.ax, word)
	for index, value := range []string{"%si", "0", strconv.FormatUint(expected.flags, 10)} {
		fmt.Fprintf(&body, "%%add%d = add i%d %%oi, %d\n%%ptr%d = inttoptr i%d %%add%d to ptr\nstore i%d %s, ptr %%ptr%d, align %d\n",
			index, bits, (index+1)*word, index, bits, index, bits, value, index, word)
	}
	if row.arch == "386" {
		body.WriteString("%stack = alloca [256 x i8], align 1\n")
		body.WriteString("%sp = getelementptr inbounds nuw i8, ptr %stack, i32 72\n")
		body.WriteString("%spi = ptrtoint ptr %sp to i32\n%pushed = add i32 %spi, -4\n")
		body.WriteString("%flags_slot = inttoptr i32 %pushed to ptr\n")
		fmt.Fprintf(&body, "store i32 %d, ptr %%flags_slot, align 1\n", expected.flags|2)
	}
	return body.String()
}

func TestX86LODSZeroStoreObserverRejectsEveryFieldAndUnknownEffect(t *testing.T) {
	observations := 0
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range x86LODSStateCases(arch) {
			if row.prefix == "" || row.count != 0 {
				continue
			}
			for _, api := range []string{"text", "module", "Go"} {
				observations++
				t.Run(arch+"/"+row.name+"/"+api, func(t *testing.T) {
					body := x86LODSZeroStoreTemplate(row)
					if err := x86LODSCheckZeroOutputStores(body, row); err != nil {
						t.Fatal("independent correct output template rejected", err)
					}
					word := 8
					if arch == "386" {
						word = 4
					}
					bits := 8 * word
					for name, changed := range map[string]string{
						"AX":                 strings.Replace(body, fmt.Sprintf("store i%d %d,", bits, x86LODSStateSeed(arch)), fmt.Sprintf("store i%d 7,", bits), 1),
						"SI":                 strings.Replace(body, fmt.Sprintf("store i%d %%si,", bits), fmt.Sprintf("store i%d 7,", bits), 1),
						"CX":                 strings.Replace(body, fmt.Sprintf("store i%d 0,", bits), fmt.Sprintf("store i%d 7,", bits), 1),
						"FLAGS":              strings.Replace(body, fmt.Sprintf("store i%d %d,", bits, x86LODSStateExpected(row).flags), fmt.Sprintf("store i%d 7,", bits), 1),
						"offset":             strings.Replace(body, fmt.Sprintf("%%oi, %d", 2*word), fmt.Sprintf("%%oi, %d", 2*word+1), 1),
						"width":              strings.Replace(body, fmt.Sprintf("store i%d ", bits), "store i8 ", 1),
						"late-overwrite":     body + fmt.Sprintf("store i%d 7, ptr %%out, align %d\n", bits, word),
						"missing":            strings.Replace(body, fmt.Sprintf("store i%d 0, ptr %%ptr1, align %d\n", bits, word), "", 1),
						"unknown-call":       body + "call void @unknown()\n",
						"branch":             body + "br label %later\nlater:\n",
						"foreign-store":      body + fmt.Sprintf("store i%d 0, ptr %%other, align %d\n", bits, word),
						"private-unbound":    body + fmt.Sprintf("store i%d %d, ptr %%unbound_stack, align 1\n", bits, x86LODSStateExpected(row).flags|2),
						"output-lifetime":    body + "call void @llvm.lifetime.end.p0(ptr nonnull %out)\n",
						"missing-fresh-base": strings.Replace(body, "alloca [4 x", "alloca [5 x", 1),
					} {
						if changed == body || x86LODSCheckZeroOutputStores(changed, row) == nil {
							t.Fatal("observer failed to reject mutation", name)
						}
					}
				})
			}
		}
	}
	if observations != 84 {
		t.Fatal("zero-state three-API observation denominator changed", observations)
	}
}
