package plan9asm

import (
	"fmt"
	"regexp"
	"strings"
)

// Keep this reader independent of the LLVM-backed fixture so its text boundary
// and strict mutation controls can also run as an explicit Go file pair.
func x86StringMemoryIRAccessError(body string, width, reads, writes int) error {
	// LLVM's Windows textual printer uses CRLF. Normalize only that transport
	// boundary, retaining the same exact volatile width/alignment predicates.
	body = strings.ReplaceAll(body, "\r\n", "\n")
	typ := fmt.Sprintf("i%d", 8*width)
	read := regexp.MustCompile(`(?m)^  %[^\n]+ = load volatile ` + typ + `, ptr [^\n]+, align 1(?:,|$)`)
	write := regexp.MustCompile(`(?m)^  store volatile ` + typ + ` [^\n]+, ptr [^\n]+, align 1(?:,|$)`)
	gotReads, gotWrites := len(read.FindAllString(body, -1)), len(write.FindAllString(body, -1))
	// The observed original helper, or its optimized entry/helper closure,
	// has no other memory-storage role. Count every load/store instruction
	// independently before checking the expected volatile type/alignment.
	// An extra access cannot disappear merely by failing that exact predicate.
	allReads := regexp.MustCompile(`(?m)^[ \t]*%[^\n=]+ = load\b[^\n]*$`)
	allWrites := regexp.MustCompile(`(?m)^[ \t]*store\b[^\n]*$`)
	if totalReads, totalWrites := len(allReads.FindAllString(body, -1)), len(allWrites.FindAllString(body, -1)); totalReads != gotReads || totalWrites != gotWrites {
		return fmt.Errorf("string memory has an unexpected volatility, width or alignment: total read/write %d/%d, exact %d/%d\n%s",
			totalReads, totalWrites, gotReads, gotWrites, body)
	}
	if gotReads != reads || gotWrites != writes {
		return fmt.Errorf("lost or invented observable native memory: got read/write %d/%d, want %d/%d\n%s",
			gotReads, gotWrites, reads, writes, body)
	}
	return nil
}
