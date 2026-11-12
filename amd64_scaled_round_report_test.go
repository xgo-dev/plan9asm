package plan9asm

import (
	"strings"
	"testing"
)

func TestX86ScaledRoundOriginalCReportExactLineTransport(t *testing.T) {
	const line = "original C exact IEEE observations 35328 failures 0"
	for _, test := range []struct {
		name, output string
		accepted     bool
	}{
		{"LF", line + "\n", true},
		{"Windows-CRLF", line + "\r\n", true},
		{"missing-terminator", line, false},
		{"CR-only", line + "\r", false},
		{"LF-CR", line + "\n\r", false},
		{"CR-CRLF", line + "\r\r\n", false},
		{"empty", "", false},
		{"truncated", line[:len(line)-1] + "\n", false},
		{"leading-space", " " + line + "\n", false},
		{"trailing-space", line + " \r\n", false},
		{"tab", line + "\t\n", false},
		{"NUL", line + "\x00\n", false},
		{"extra-before", "compiler warning\n" + line + "\n", false},
		{"extra-after", line + "\r\nwarning\r\n", false},
		{"extra-empty-line", line + "\n\n", false},
		{"duplicate-LF", line + "\n" + line + "\n", false},
		{"duplicate-CRLF", line + "\r\n" + line + "\r\n", false},
		{"mixed-line-endings", line + "\n" + line + "\r\n", false},
		{"lower-count", strings.Replace(line, "35328", "35327", 1) + "\n", false},
		{"higher-count", strings.Replace(line, "35328", "35329", 1) + "\r\n", false},
		{"leading-zero-count", strings.Replace(line, "35328", "035328", 1) + "\n", false},
		{"signed-count", strings.Replace(line, "35328", "+35328", 1) + "\n", false},
		{"nonzero-failures", strings.Replace(line, "failures 0", "failures 1", 1) + "\r\n", false},
		{"signed-zero-failures", strings.Replace(line, "failures 0", "failures -0", 1) + "\n", false},
		{"extra-zero-failures", line + "0\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := x86ScaledRoundOriginalCReportComplete([]byte(test.output)); got != test.accepted {
				t.Fatalf("exact original C report acceptance=%t, want %t for %q", got, test.accepted, test.output)
			}
		})
	}
}
