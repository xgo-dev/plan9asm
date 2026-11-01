package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86StringMemoryIRReaderLineEndingsAndMetadata(t *testing.T) {
	for _, width := range []int{1, 2, 4, 8} {
		for _, ending := range []string{"LF", "CRLF"} {
			for _, metadata := range []string{"", ", !alias.scope !7"} {
				for _, terminalNewline := range []bool{false, true} {
					name := fmt.Sprintf("width=%d/%s/metadata=%t/newline=%t", width, ending, metadata != "", terminalNewline)
					t.Run(name, func(t *testing.T) {
						typ := fmt.Sprintf("i%d", 8*width)
						body := "  %value = load volatile " + typ + ", ptr %source, align 1" + metadata + "\n" +
							"  store volatile " + typ + " %value, ptr %destination, align 1" + metadata
						if terminalNewline {
							body += "\n"
						}
						if ending == "CRLF" {
							body = strings.ReplaceAll(body, "\n", "\r\n")
						}
						if err := x86StringMemoryIRAccessError(body, width, 1, 1); err != nil {
							t.Fatal(err)
						}
					})
				}
			}
		}
	}
}

func TestX86StringMemoryIRReaderRejectsMemoryMutations(t *testing.T) {
	for _, width := range []int{1, 2, 4, 8} {
		typ := fmt.Sprintf("i%d", 8*width)
		read := "  %value = load volatile " + typ + ", ptr %source, align 1\n"
		write := "  store volatile " + typ + " %value, ptr %destination, align 1\n"
		for _, ending := range []string{"LF", "CRLF"} {
			for _, row := range []struct {
				name, body    string
				reads, writes int
			}{
				{"missing-read", write, 1, 1},
				{"missing-write", read, 1, 1},
				{"duplicate-read", read + read + write, 1, 1},
				{"duplicate-write", read + write + write, 1, 1},
				{"nonvolatile-read", strings.Replace(read, "load volatile", "load", 1) + write, 1, 1},
				{"nonvolatile-write", read + strings.Replace(write, "store volatile", "store", 1), 1, 1},
				{"wrong-read-width", strings.Replace(read, typ, "i128", 1) + write, 1, 1},
				{"wrong-write-width", read + strings.Replace(write, typ, "i128", 1), 1, 1},
				{"wrong-read-alignment", strings.Replace(read, "align 1", "align 16", 1) + write, 1, 1},
				{"wrong-write-alignment", read + strings.Replace(write, "align 1", "align 16", 1), 1, 1},
				{"zero-count-extra-volatile-read", read, 0, 0},
				{"zero-count-extra-volatile-write", write, 0, 0},
				{"zero-count-nonvolatile-read", strings.Replace(read, "load volatile", "load", 1), 0, 0},
				{"zero-count-nonvolatile-write", strings.Replace(write, "store volatile", "store", 1), 0, 0},
				{"zero-count-wrong-read-width", strings.Replace(read, typ, "i128", 1), 0, 0},
				{"zero-count-wrong-write-width", strings.Replace(write, typ, "i128", 1), 0, 0},
				{"zero-count-wrong-read-alignment", strings.Replace(read, "align 1", "align 16", 1), 0, 0},
				{"zero-count-wrong-write-alignment", strings.Replace(write, "align 1", "align 16", 1), 0, 0},
				{"zero-count-nonvolatile-wrong-read-alignment", strings.ReplaceAll(strings.Replace(read, "load volatile", "load", 1), "align 1", "align 16"), 0, 0},
				{"zero-count-nonvolatile-wrong-write-alignment", strings.ReplaceAll(strings.Replace(write, "store volatile", "store", 1), "align 1", "align 16"), 0, 0},
				{"extra-wrong-read-width", read + write + strings.Replace(read, typ, "i128", 1), 1, 1},
				{"extra-wrong-write-width", read + write + strings.Replace(write, typ, "i128", 1), 1, 1},
				{"extra-wrong-read-alignment", read + write + strings.Replace(read, "align 1", "align 16", 1), 1, 1},
				{"extra-wrong-write-alignment", read + write + strings.Replace(write, "align 1", "align 16", 1), 1, 1},
				{"extra-nonvolatile-wrong-read-alignment", read + write + strings.ReplaceAll(strings.Replace(read, "load volatile", "load", 1), "align 1", "align 16"), 1, 1},
				{"extra-nonvolatile-wrong-write-alignment", read + write + strings.ReplaceAll(strings.Replace(write, "store volatile", "store", 1), "align 1", "align 16"), 1, 1},
			} {
				t.Run(fmt.Sprintf("width=%d/%s/%s", width, ending, row.name), func(t *testing.T) {
					body := row.body
					if ending == "CRLF" {
						body = strings.ReplaceAll(body, "\n", "\r\n")
					}
					if err := x86StringMemoryIRAccessError(body, width, row.reads, row.writes); err == nil {
						t.Fatal("invalid memory observation was accepted", body)
					}
				})
			}
		}
	}
}

func TestX86StringMemoryIRReaderEmptyZeroCount(t *testing.T) {
	for _, body := range []string{"", "entry:\n  ret void\n", "entry:\r\n  ret void\r\n"} {
		if err := x86StringMemoryIRAccessError(body, 4, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
}
