package plan9asm

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"testing"
)

func TestX86CRC32CompleteOfficialGoRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for table, want := range map[string]string{
		"ycrc32b": "{Zlitm_r,0,argList{Ymb,Yrl}},",
		"ycrc32l": "{Zlitm_r,0,argList{Yml,Yrl}},",
	} {
		match := regexp.MustCompile(`(?s)var ` + table + ` = \[\]ytab\{(.*?)\n\}`).FindSubmatch(data)
		if len(match) != 2 || regexp.MustCompile(`\s+`).ReplaceAllString(string(match[1]), "") != want {
			t.Fatal("complete official Go CRC rows changed", table)
		}
	}
	actual := regexp.MustCompile(`\{ACRC32[BWLQ], [^\n]+`).FindAllString(string(data), -1)
	want := []string{
		"{ACRC32B, ycrc32b, Px, opBytes{0xf2, 0x0f, 0x38, 0xf0, 0}},",
		"{ACRC32L, ycrc32l, Px, opBytes{0xf2, 0x0f, 0x38, 0xf1, 0}},",
		"{ACRC32Q, ycrc32l, Pw, opBytes{0xf2, 0x0f, 0x38, 0xf1, 0}},",
		"{ACRC32W, ycrc32l, Pe, opBytes{0xf2, 0x0f, 0x38, 0xf1, 0}},",
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatal("complete opcode/table/prefix/byte attributes changed", actual)
	}
}

func TestX86CRC32OriginalGoByteViews(t *testing.T) {
	for _, row := range []struct {
		arch, instruction string
		bytes             []byte
	}{
		{"amd64", "CRC32B BX,AX", []byte{0xf2, 0x0f, 0x38, 0xf0, 0xc3}},
		{"amd64", "CRC32W BX,AX", []byte{0x66, 0xf2, 0x0f, 0x38, 0xf1, 0xc3}},
		{"amd64", "CRC32L BX,AX", []byte{0xf2, 0x0f, 0x38, 0xf1, 0xc3}},
		{"amd64", "CRC32Q BX,AX", []byte{0xf2, 0x48, 0x0f, 0x38, 0xf1, 0xc3}},
		{"amd64", "CRC32B SI,AX", []byte{0xf2, 0x0f, 0x38, 0xf0, 0xc6}},
		{"amd64", "CRC32B DI,AX", []byte{0xf2, 0x0f, 0x38, 0xf0, 0xc7}},
		{"amd64", "CRC32B BP,AX", []byte{0xf2, 0x0f, 0x38, 0xf0, 0xc5}},
		{"amd64", "CRC32B SP,AX", []byte{0xf2, 0x0f, 0x38, 0xf0, 0xc4}},
		{"amd64", "CRC32B SI,R8", []byte{0xf2, 0x44, 0x0f, 0x38, 0xf0, 0xc6}},
		{"amd64", "CRC32B AH,R8", []byte{0xf2, 0x44, 0x0f, 0x38, 0xf0, 0xc4}},
		{"amd64", "CRC32B SIB,AX", []byte{0xf2, 0x40, 0x0f, 0x38, 0xf0, 0xc6}},
		{"386", "CRC32B BX,AX", []byte{0xf2, 0x0f, 0x38, 0xf0, 0xc3}},
		{"386", "CRC32W BX,AX", []byte{0x66, 0xf2, 0x0f, 0x38, 0xf1, 0xc3}},
		{"386", "CRC32L BX,AX", []byte{0xf2, 0x0f, 0x38, 0xf1, 0xc3}},
		{"386", "CRC32B BP,AX", []byte{0x87, 0xdd, 0xf2, 0x0f, 0x38, 0xf0, 0xc3, 0x87, 0xdd}},
		{"386", "CRC32B SI,AX", []byte{0x87, 0xde, 0xf2, 0x0f, 0x38, 0xf0, 0xc3, 0x87, 0xde}},
		{"386", "CRC32B DI,AX", []byte{0x87, 0xdf, 0xf2, 0x0f, 0x38, 0xf0, 0xc3, 0x87, 0xdf}},
	} {
		t.Run(row.arch+"/"+row.instruction, func(t *testing.T) {
			actual := x86OrderingHintGoBytes(t, row.arch, "TEXT crc(SB),4,$0-0\n"+row.instruction+"\nRET\n")
			if !bytes.Equal(actual, append(append([]byte(nil), row.bytes...), 0xc3)) {
				t.Fatalf("actual Go byte view %x, independent complete row %x", actual, row.bytes)
			}
		})
	}
}
