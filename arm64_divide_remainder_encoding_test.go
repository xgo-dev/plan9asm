package plan9asm

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestARM64DivideRemainderOriginalGoMachineExpansion(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT expansion(SB),4,$0-0\n")
	var expected []byte
	registers := map[Reg]uint32{"R0": 0, "R1": 1, "R2": 2, "R27": 27, ZR: 31}
	cases := arm64RemainderScratchCases()
	for _, tc := range cases {
		if tc.two {
			fmt.Fprintf(&source, "%s %s,%s\n", tc.op, tc.divisor, tc.dest)
		} else {
			fmt.Fprintf(&source, "%s %s,%s,%s\n", tc.op, tc.divisor, tc.dividend, tc.dest)
		}
		size := uint32(1 << 31)
		if strings.HasSuffix(tc.op, "W") {
			size = 0
		}
		division := uint32(0x1ac00c00)
		if strings.HasPrefix(tc.op, "U") {
			division = 0x1ac00800
		}
		divisor, dividend, destination := registers[tc.divisor], registers[tc.dividend], registers[tc.dest]
		quotient := destination
		if strings.Contains(tc.op, "REM") {
			quotient = 27
		}
		word := size | division | divisor<<16 | dividend<<5 | quotient
		var encoded [4]byte
		binary.LittleEndian.PutUint32(encoded[:], word)
		expected = append(expected, encoded[:]...)
		if strings.Contains(tc.op, "REM") {
			word = size | 0x1b008000 | divisor<<16 | dividend<<10 | 27<<5 | destination
			binary.LittleEndian.PutUint32(encoded[:], word)
			expected = append(expected, encoded[:]...)
		}
	}
	source.WriteString("RET\n")
	expected = append(expected, 0xc0, 0x03, 0x5f, 0xd6)
	for _, goos := range []string{"linux", "darwin"} {
		dir := t.TempDir()
		asm := filepath.Join(dir, "expansion.s")
		if err := os.WriteFile(asm, []byte(source.String()), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		command := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-o", filepath.Join(dir, "expansion.o"), asm)
		command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=arm64")
		listing, err := command.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("%s actual Go expansion object: %v\n%s", goos, err, listing)
		}
		var actual []byte
		// Instruction listing rows also start with a hexadecimal PC, then a
		// decimal line counter. Require a complete machine word's byte field
		// so that counter cannot impersonate the object-byte dump.
		for _, row := range regexp.MustCompile(`(?m)^\s*0x[0-9a-f]+((?: [0-9a-f]{2}){4,16})(?:\s|$)`).FindAllSubmatch(listing, -1) {
			decoded, err := hex.DecodeString(strings.ReplaceAll(string(row[1]), " ", ""))
			if err != nil {
				t.Fatal(err)
			}
			actual = append(actual, decoded...)
		}
		if len(actual) < len(expected) {
			t.Fatalf("%s Go byte dump truncated: %d actual bytes for %d expected bytes", goos, len(actual), len(expected))
		}
		if !bytes.Equal(actual[:len(expected)], expected) {
			for index, want := range expected {
				if got := actual[index]; got != want {
					t.Fatalf("%s Go DIV/REM expansion byte %d: got %#x, want %#x", goos, index, got, want)
				}
			}
		}
	}
	t.Logf("%d original Go W/X DIV/REM forms: exact DIV/R27/MSUB and RET bytes on Linux and Darwin", len(cases))
}
