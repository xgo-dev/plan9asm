package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

// Go's objfile printer emits sixteen three-character byte columns, two spaces,
// then ASCII. Splitting the whole line into words confuses ASCII such as "A2"
// with another byte. Keep the original line, including trailing ASCII spaces.
func goAssemblyListingByteRow(line string) (int, []byte, error) {
	fail := func() (int, []byte, error) {
		return 0, nil, fmt.Errorf("invalid Go assembly listing byte columns")
	}
	line = strings.TrimLeft(line, "\t ")
	separator := strings.IndexByte(line, ' ')
	if separator < 3 || !strings.HasPrefix(line, "0x") {
		return fail()
	}
	offset, err := strconv.ParseUint(line[2:separator], 16, 31)
	body := line[separator:]
	if err != nil || len(body) < 51 || body[48:50] != "  " {
		return fail()
	}
	code, ascii := make([]byte, 0, 16), make([]byte, 0, 16)
	padding := false
	for index := 0; index < 48; index += 3 {
		column := body[index : index+3]
		if column == "   " {
			padding = true
			continue
		}
		value, err := strconv.ParseUint(column[1:], 16, 8)
		if padding || column[0] != ' ' || err != nil {
			return fail()
		}
		code = append(code, byte(value))
		if value < ' ' || value > '~' {
			value = '.'
		}
		ascii = append(ascii, byte(value))
	}
	if len(code) == 0 || body[50:] != string(ascii) {
		return fail()
	}
	return int(offset), code, nil
}
