package plan9asm

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type arm64RawFrameSourceLine struct {
	line int
	text string
}

type arm64RawFrameSourceFunction struct {
	line int
	body []arm64RawFrameSourceLine
}

type arm64RawFrameListingRow struct {
	pc, line int
	text     string
}

type arm64RawFrameListingFunction struct {
	symbol string
	size   int
	text   bool
	meta   uint8
	rows   []arm64RawFrameListingRow
	bytes  []byte
}

// These are fixture-specific observers, not a frame-permission producer.
// Each function must retain its own original source positions, explicit raw
// LR/SP restoration and independently observed Go machine words. There is no
// version guess: either exact, equivalent obj7 epilogue is accepted.
func checkARM64RawPrivateFrameGoListing(sourcePath, source, listing string) error {
	sourceHeader := regexp.MustCompile(`^TEXT ·(rawFrame_[A-Za-z0-9_]+)\(SB\),4,\$120-16$`)
	wanted := make(map[string]*arm64RawFrameSourceFunction)
	var currentSource *arm64RawFrameSourceFunction
	for index, line := range strings.Split(source, "\n") {
		text := strings.Join(strings.Fields(line), " ")
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "TEXT ") {
			match := sourceHeader.FindStringSubmatch(text)
			if match == nil || wanted[match[1]] != nil {
				return fmt.Errorf("unexpected/duplicate original TEXT at line %d", index+1)
			}
			currentSource = &arm64RawFrameSourceFunction{line: index + 1}
			wanted[match[1]] = currentSource
		} else if currentSource == nil {
			return fmt.Errorf("original instruction outside TEXT at line %d", index+1)
		} else {
			currentSource.body = append(currentSource.body, arm64RawFrameSourceLine{index + 1, text})
		}
	}
	if sourcePath == "" || len(wanted) == 0 || len(listing) > 32<<20 {
		return fmt.Errorf("empty original functions or overlong Go listing")
	}
	header := regexp.MustCompile(`^((?:main|"")\.(rawFrame_[A-Za-z0-9_]+)) STEXT nosplit asm size=([0-9]+) (?:args=0x10 locals=0x88 funcid=0x0 align=0x0|align=0x0 args=0x10 locals=0x88 funcid=0x0) leaf$`)
	row := regexp.MustCompile(`^\s*0x([0-9a-f]+)\s+([0-9]+)\s+\((.*):([0-9]+)\)\s+(.*)$`)
	observed := make(map[string]*arm64RawFrameListingFunction)
	var current *arm64RawFrameListingFunction
	for _, line := range strings.Split(listing, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if match := header.FindStringSubmatch(line); match != nil {
			if wanted[match[2]] == nil || observed[match[2]] != nil {
				return fmt.Errorf("unexpected/duplicate Go function %s", match[2])
			}
			size, err := strconv.Atoi(match[3])
			if err != nil || size < 56 || size > 1<<20 || size%16 != 0 {
				return fmt.Errorf("unexpected object size for %s", match[2])
			}
			current = &arm64RawFrameListingFunction{symbol: match[1], size: size}
			observed[match[2]] = current
			continue
		}
		if current == nil {
			return fmt.Errorf("Go output outside an expected STEXT: %q", line)
		}
		if match := row.FindStringSubmatch(line); match != nil {
			pc, pcErr := strconv.ParseUint(match[1], 16, 32)
			decimalPC, decimalErr := strconv.ParseUint(match[2], 10, 32)
			sourceLine, lineErr := strconv.Atoi(match[4])
			if pcErr != nil || decimalErr != nil || pc != decimalPC || lineErr != nil || match[3] != sourcePath {
				return fmt.Errorf("Go instruction has mismatched original location/PC: %q", line)
			}
			text := strings.Join(strings.Fields(match[5]), " ")
			name := strings.TrimPrefix(strings.TrimPrefix(current.symbol, "main."), `"".`)
			original := wanted[name]
			if strings.HasPrefix(text, "TEXT ") {
				if current.text || pc != 0 || sourceLine != original.line || len(current.rows) != 0 || text != "TEXT "+current.symbol+"(SB), NOSPLIT|LEAF, $144-16" {
					return fmt.Errorf("unexpected generated TEXT for %s", name)
				}
				current.text = true
				continue
			}
			if strings.HasPrefix(text, "FUNCDATA ") {
				if !current.text || sourceLine != original.line || pc != 12 || len(current.rows) != 3 ||
					(text != "FUNCDATA $5, "+current.symbol+".arginfo0(SB)" && text != "FUNCDATA $0, "+current.symbol+".args_stackmap(SB)") {
					return fmt.Errorf("unexpected generated metadata for %s", name)
				}
				bit := uint8(1)
				if strings.HasPrefix(text, "FUNCDATA $0,") {
					bit = 2
				}
				if current.meta&bit != 0 {
					return fmt.Errorf("duplicate generated metadata for %s", name)
				}
				current.meta |= bit
				continue
			}
			if !current.text || len(current.bytes) != 0 || int(pc) != 4*len(current.rows) {
				return fmt.Errorf("noncontiguous Go instruction rows for %s", name)
			}
			current.rows = append(current.rows, arm64RawFrameListingRow{int(pc), sourceLine, text})
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 17 || !strings.HasPrefix(fields[0], "0x") {
			return fmt.Errorf("unexpected Go listing syntax: %q", line)
		}
		offset, err := strconv.ParseUint(fields[0][2:], 16, 32)
		if err != nil || int(offset) != len(current.bytes) || len(current.bytes)+16 > current.size {
			return fmt.Errorf("noncontiguous/overlong Go object dump for %s", current.symbol)
		}
		for _, token := range fields[1:17] {
			b, err := strconv.ParseUint(token, 16, 8)
			if err != nil || len(token) != 2 {
				return fmt.Errorf("invalid Go object byte %q", token)
			}
			current.bytes = append(current.bytes, byte(b))
		}
	}
	if len(observed) != len(wanted) {
		return fmt.Errorf("Go listing omits original functions: %d != %d", len(observed), len(wanted))
	}
	for name, original := range wanted {
		if err := checkARM64RawFrameFunction(original, observed[name]); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func checkARM64RawFrameFunction(source *arm64RawFrameSourceFunction, object *arm64RawFrameListingFunction) error {
	if len(source.body) < 8 || source.body[0].text != "MOVD in+0(FP),R0" ||
		source.body[1].text != "MOVD out+8(FP),R1" ||
		source.body[2].text != "WORD $0xa9ba6ffc" || source.body[3].text != "WORD $0xa9057bfd" ||
		source.body[4].text != "WORD $0x910143fd" {
		return fmt.Errorf("original framed leaf prefix changed")
	}
	n := len(source.body)
	if source.body[n-3].text != "WORD $0xa9457bfd" || source.body[n-2].text != "WORD $0xa8c66ffc" || source.body[n-1].text != "RET" {
		return fmt.Errorf("original LR/SP restore and RET changed")
	}
	if object == nil || !object.text || object.meta != 3 || len(object.rows) < 11 || len(object.bytes) != object.size || 4*len(object.rows) > object.size {
		return fmt.Errorf("partial original Go object/listing")
	}
	check := func(index, line int, text string, word uint32) bool {
		r := object.rows[index]
		return r.line == line && r.text == text && binary.LittleEndian.Uint32(object.bytes[r.pc:r.pc+4]) == word
	}
	if !check(0, source.line, "MOVD.W R30, -144(RSP)", 0xf8170ffe) ||
		!check(1, source.line, "MOVD R29, -8(RSP)", 0xf81f83fd) ||
		!check(2, source.line, "SUB $8, RSP, R29", 0xd10023fd) {
		return fmt.Errorf("original Go prologue bytes/source contract changed")
	}
	// Every source WORD must have exactly one matching original line and byte
	// sequence; a correct spill in another function cannot discharge this one.
	words := make(map[int]uint32)
	for _, line := range source.body[:n-1] {
		if line.text == "RET" {
			return fmt.Errorf("unexpected original RET")
		}
		if strings.HasPrefix(line.text, "WORD ") {
			value, err := strconv.ParseUint(strings.TrimPrefix(line.text, "WORD $"), 0, 32)
			if err != nil {
				return fmt.Errorf("invalid original WORD")
			}
			words[line.line] = uint32(value)
		}
	}
	end := len(object.rows) - 3
	for _, r := range object.rows[3:end] {
		if r.line <= source.line || r.line >= source.body[n-1].line {
			return fmt.Errorf("body row outside original function")
		}
		if strings.HasPrefix(r.text, "WORD ") {
			word, ok := words[r.line]
			if !ok || r.text != fmt.Sprintf("WORD $%d", word) || binary.LittleEndian.Uint32(object.bytes[r.pc:r.pc+4]) != word {
				return fmt.Errorf("original WORD line/bytes changed")
			}
			delete(words, r.line)
		}
	}
	if len(words) != 0 ||
		!check(end-2, source.body[n-3].line, "WORD $2839903229", 0xa9457bfd) ||
		!check(end-1, source.body[n-2].line, "WORD $2831577084", 0xa8c66ffc) {
		return fmt.Errorf("explicit original LR/SP restore missing before epilogue")
	}
	retLine := source.body[n-1].line
	// Both finish at entry SP and entry-SP-8 in R29. Neither reloads R30:
	// restoration of the caller LR must still come from the raw source above.
	old := check(end, retLine, "ADD $144, RSP", 0x910243ff) &&
		check(end+1, retLine, "SUB $8, RSP, R29", 0xd10023fd)
	current := check(end, retLine, "ADD $136, RSP, R29", 0x910223fd) &&
		check(end+1, retLine, "ADD $144, RSP", 0x910243ff)
	if (!old && !current) || !check(end+2, retLine, "RET (R30)", 0xd65f03c0) {
		return fmt.Errorf("original Go epilogue order/SP/FP/LR/bytes changed")
	}
	for _, b := range object.bytes[4*len(object.rows):] {
		if b != 0 {
			return fmt.Errorf("unexpected code after original RET")
		}
	}
	return nil
}

// The source positions and machine words are from the two independently
// assembled Go1.20/Go1.27 probe objects, not from the listing checker.
func arm64RawFrameListingFixture(styles ...bool) (sourcePath, source, listing string) {
	sourcePath = "/fixture/oracle_arm64.s"
	var src, out strings.Builder
	for index, current := range styles {
		name := fmt.Sprintf("rawFrame_%d", index)
		prefix := `"".`
		if current {
			prefix = "main."
		}
		symbol := prefix + name
		fmt.Fprintf(&src, `TEXT ·%s(SB),4,$120-16
MOVD in+0(FP),R0
MOVD out+8(FP),R1
WORD $0xa9ba6ffc
WORD $0xa9057bfd
WORD $0x910143fd
MOVD R0,(R1)
WORD $0xa9457bfd
WORD $0xa8c66ffc
RET
`, name)
		attributes := "args=0x10 locals=0x88 funcid=0x0 align=0x0"
		if current {
			attributes = "align=0x0 args=0x10 locals=0x88 funcid=0x0"
		}
		fmt.Fprintf(&out, "%s STEXT nosplit asm size=64 %s leaf\n", symbol, attributes)
		line := index*10 + 1
		row := func(pc, sourceLine int, op string) {
			fmt.Fprintf(&out, "\t0x%04x %05d (%s:%d)\t%s\n", pc, pc, sourcePath, sourceLine, op)
		}
		row(0, line, "TEXT\t"+symbol+"(SB), NOSPLIT|LEAF, $144-16")
		row(0, line, "MOVD.W\tR30, -144(RSP)")
		row(4, line, "MOVD\tR29, -8(RSP)")
		row(8, line, "SUB\t$8, RSP, R29")
		row(12, line, "FUNCDATA\t$5, "+symbol+".arginfo0(SB)")
		row(12, line, "FUNCDATA\t$0, "+symbol+".args_stackmap(SB)")
		row(12, line+1, "MOVD\tin(FP), R0")
		row(16, line+2, "MOVD\tout+8(FP), R1")
		row(20, line+3, "WORD\t$2847567868")
		row(24, line+4, "WORD\t$2835708925")
		row(28, line+5, "WORD\t$2432779261")
		row(32, line+6, "MOVD\tR0, (R1)")
		row(36, line+7, "WORD\t$2839903229")
		row(40, line+8, "WORD\t$2831577084")
		epilogue := []uint32{0x910243ff, 0xd10023fd, 0xd65f03c0}
		if current {
			row(44, line+9, "ADD\t$136, RSP, R29")
			row(48, line+9, "ADD\t$144, RSP")
			epilogue = []uint32{0x910223fd, 0x910243ff, 0xd65f03c0}
		} else {
			row(44, line+9, "ADD\t$144, RSP")
			row(48, line+9, "SUB\t$8, RSP, R29")
		}
		row(52, line+9, "RET\t(R30)")
		words := []uint32{
			0xf8170ffe, 0xf81f83fd, 0xd10023fd, 0xf9404fe0,
			0xf94053e1, 0xa9ba6ffc, 0xa9057bfd, 0x910143fd,
			0xf9000020, 0xa9457bfd, 0xa8c66ffc,
		}
		words = append(words, epilogue...)
		words = append(words, 0, 0)
		bytes := make([]byte, 4*len(words))
		for i, word := range words {
			binary.LittleEndian.PutUint32(bytes[4*i:], word)
		}
		for offset := 0; offset < len(bytes); offset += 16 {
			fmt.Fprintf(&out, "\t0x%04x", offset)
			for _, b := range bytes[offset : offset+16] {
				fmt.Fprintf(&out, " %02x", b)
			}
			out.WriteString("  ................\n")
		}
	}
	return sourcePath, src.String(), out.String()
}

func TestARM64RawPrivateFrameGoEpiloguePerFunction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		styles []bool
	}{
		{"go120", []bool{false}},
		{"go127", []bool{true}},
		{"both_independent", []bool{false, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, source, listing := arm64RawFrameListingFixture(tc.styles...)
			if err := checkARM64RawPrivateFrameGoListing(path, source, listing); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestARM64RawPrivateFrameGoEpilogueRejectsBrokenIdentity(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sourceOld  string
		sourceNew  string
		listingOld string
		listingNew string
	}{
		{name: "missing_old_sp", listingOld: "ADD\t$144, RSP", listingNew: "NOP"},
		{name: "reversed_old_sp_fp", listingOld: "ADD\t$144, RSP", listingNew: "SUB\t$8, RSP, R29"},
		{name: "wrong_sp_delta", listingOld: "ADD\t$144, RSP", listingNew: "ADD\t$143, RSP"},
		{name: "wrong_old_fp", listingOld: "0x0030 00048 (/fixture/oracle_arm64.s:10)\tSUB\t$8, RSP, R29", listingNew: "0x0030 00048 (/fixture/oracle_arm64.s:10)\tSUB\t$16, RSP, R29"},
		{name: "wrong_current_fp", listingOld: "ADD\t$136, RSP, R29", listingNew: "ADD\t$128, RSP, R29"},
		{name: "wrong_sp_register", listingOld: "ADD\t$144, RSP", listingNew: "ADD\t$144, R28"},
		{name: "wrong_lr_ret", listingOld: "RET\t(R30)", listingNew: "RET\t(R29)"},
		{name: "missing_raw_lr_restore", listingOld: "WORD\t$2839903229", listingNew: "WORD\t$2839903228"},
		{name: "missing_raw_sp_restore", listingOld: "WORD\t$2831577084", listingNew: "WORD\t$2831577085"},
		{name: "wrong_prologue_lr", listingOld: "MOVD.W\tR30, -144(RSP)", listingNew: "MOVD.W\tR29, -144(RSP)"},
		{name: "wrong_prologue_frame", listingOld: "MOVD.W\tR30, -144(RSP)", listingNew: "MOVD.W\tR30, -128(RSP)"},
		{name: "wrong_listing_frame", listingOld: "$144-16", listingNew: "$128-16"},
		{name: "wrong_listing_locals", listingOld: "locals=0x88", listingNew: "locals=0x90"},
		{name: "wrong_source_frame", sourceOld: "$120-16", sourceNew: "$128-16"},
		{name: "wrong_original_lr", sourceOld: "WORD $0xa9457bfd", sourceNew: "WORD $0xa9457bfc"},
		{name: "wrong_original_ret", sourceOld: "\nRET\n", sourceNew: "\nWORD $0xd65f03c0\n"},
		{name: "foreign_path", listingOld: "/fixture/oracle_arm64.s:8", listingNew: "/foreign/oracle_arm64.s:8"},
		{name: "foreign_line", listingOld: "/fixture/oracle_arm64.s:8", listingNew: "/fixture/oracle_arm64.s:9"},
		{name: "wrong_decimal_pc", listingOld: "0x002c 00044", listingNew: "0x002c 00040"},
		{name: "wrong_prologue_bytes", listingOld: "fe 0f 17 f8", listingNew: "ff 0f 17 f8"},
		{name: "wrong_ret_bytes", listingOld: "c0 03 5f d6", listingNew: "a0 03 5f d6"},
		{name: "nonzero_ret_padding", listingOld: "c0 03 5f d6 00 00 00 00", listingNew: "c0 03 5f d6 01 00 00 00"},
		{name: "missing_text", listingOld: "TEXT\t\"\".rawFrame_0(SB), NOSPLIT|LEAF, $144-16", listingNew: "FUNCDATA\t$5, \"\".rawFrame_0.arginfo0(SB)"},
		{name: "duplicate_metadata", listingOld: "FUNCDATA\t$0, \"\".rawFrame_0.args_stackmap(SB)", listingNew: "FUNCDATA\t$5, \"\".rawFrame_0.arginfo0(SB)"},
		{name: "borrowed_function", listingOld: `"".rawFrame_0 STEXT`, listingNew: `"".rawFrame_other STEXT`},
		{name: "duplicate_function", listingOld: "main.rawFrame_1", listingNew: `"".rawFrame_0`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, source, listing := arm64RawFrameListingFixture(false, true)
			if tc.sourceOld != "" {
				source = strings.Replace(source, tc.sourceOld, tc.sourceNew, 1)
			}
			if tc.listingOld != "" {
				listing = strings.Replace(listing, tc.listingOld, tc.listingNew, 1)
			}
			if err := checkARM64RawPrivateFrameGoListing(path, source, listing); err == nil {
				t.Fatal("broken per-function source/epilogue/object contract accepted")
			}
		})
	}
	path, source, listing := arm64RawFrameListingFixture(false, true)
	for _, tc := range []struct{ name, listing string }{
		{"missing_function", strings.Split(listing, "main.rawFrame_1 STEXT")[0]},
		{"missing_dump", strings.Split(listing, "\t0x0030 fd 23 00 d1")[0]},
		{"missing_epilogue_row", strings.Replace(listing, "\t0x002c 00044 (/fixture/oracle_arm64.s:10)\tADD\t$144, RSP\n", "", 1)},
		{"duplicate_text_row", strings.Replace(listing, "\t0x0000 00000 (/fixture/oracle_arm64.s:1)\tTEXT", "\t0x0000 00000 (/fixture/oracle_arm64.s:1)\tTEXT\t\"\".rawFrame_0(SB), NOSPLIT|LEAF, $144-16\n\t0x0000 00000 (/fixture/oracle_arm64.s:1)\tTEXT", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkARM64RawPrivateFrameGoListing(path, source, tc.listing); err == nil {
				t.Fatal("incomplete/duplicate per-function source/object contract accepted")
			}
		})
	}
}
