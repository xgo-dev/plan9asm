package plan9asm

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestARM64ByteCarrierCallPositionSpelling(t *testing.T) {
	directory := t.TempDir()
	const filename = "original_arm64.s"
	const raw = "CALL ·callee(SB)"
	source := &GoARM64ByteCarrierSource{
		request: GoARM64ByteCarrierCaptureRequest{
			Directory: directory, AssemblyFile: filename,
		},
		report: arm64ByteCarrierReport{
			Sources: map[string][]byte{
				filename: []byte("TEXT ·caller(SB),$0-0\n\t" + raw + "\nRET\n"),
			},
		},
	}
	path := filepath.Join(directory, filename)
	position := gostaticstorage.TextPosition{Start: 4, End: 8, File: path, Line: 2}
	tests := []struct {
		name     string
		position gostaticstorage.TextPosition
		pc       int64
		raw      string
		valid    bool
	}{
		{"native", position, 4, raw, true},
		{"object-slashes", position, 4, raw, true},
		{"foreign-file", position, 4, raw, false},
		{"relative-file", position, 4, raw, false},
		{"unbound-sdk-file", position, 4, raw, false},
		{"dot-alias", position, 4, raw, false},
		{"repeated-slash", position, 4, raw, false},
		{"different-line", position, 4, raw, false},
		{"missing-line", position, 4, raw, false},
		{"past-source", position, 4, raw, false},
		{"pc-before", position, 0, raw, false},
		{"pc-after", position, 8, raw, false},
		{"partial-instruction", position, 4, raw, false},
		{"different-source", position, 4, "CALL ·other(SB)", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			switch test.name {
			case "object-slashes":
				test.position.File = filepath.ToSlash(path)
			case "foreign-file":
				test.position.File = filepath.Join(directory, "other_arm64.s")
			case "relative-file":
				test.position.File = filename
			case "unbound-sdk-file":
				test.position.File = "$GOROOT/" + filename
			case "dot-alias":
				test.position.File = filepath.ToSlash(directory) + "/./" + filename
			case "repeated-slash":
				test.position.File = filepath.ToSlash(directory) + "//" + filename
			case "different-line":
				test.position.Line = 1
			case "missing-line":
				test.position.Line = 0
			case "past-source":
				test.position.Line = 5
			case "partial-instruction":
				test.position.End = 7
			}
			text := gostaticstorage.TextRecord{
				Positions: []gostaticstorage.TextPosition{test.position},
			}
			actual, err := source.callPosition(text, test.pc, test.raw)
			if test.valid {
				if err != nil || actual != test.position {
					t.Fatalf("actual position must remain unchanged: got %+v, %v", actual, err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unbound source/line/PC accepted: got %+v, %v", actual, err)
			}
		})
	}
}
