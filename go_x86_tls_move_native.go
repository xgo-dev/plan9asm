package plan9asm

import (
	"bufio"
	"bytes"
	"reflect"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// File/line auxiliaries legitimately differ between the original source and
// the owned expanded source. Preserve both whole objects, while independently
// joining every physical TEXT identity, byte and ordered relocation.
func x86TLSOriginalExpandedObjects(original, expanded []gostaticstorage.TextRecord) error {
	if len(original) == 0 || len(original) != len(expanded) {
		return x86TLSMoveContext("complete original/expanded TEXT inventories differ")
	}
	for index, first := range original {
		second := expanded[index]
		if first.Name != second.Name || first.ABI != second.ABI || first.Kind != second.Kind ||
			first.Flags != second.Flags || first.Flags2 != second.Flags2 || first.Size != second.Size ||
			!bytes.Equal(first.Code, second.Code) || !reflect.DeepEqual(first.Relocations, second.Relocations) {
			return x86TLSMoveContext("original expansion changed native TEXT bytes, identity or relocations")
		}
	}
	return nil
}

type x86TLSListingRow struct {
	pc        int64
	file      string
	line      int
	operation string
}

func x86TLSListingTextHeaders(listing []byte) []string {
	var result []string
	for _, line := range strings.Split(string(listing), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "STEXT" {
			result = append(result, strings.Join(fields, " "))
		}
	}
	return result
}

func x86TLSObservedNoops(expanded string, file *File, texts []gostaticstorage.TextRecord, listing []byte,
	packagePath, expandedPath, arch string,
) ([]x86TLSNoopSite, error) {
	if len(file.Funcs) != len(texts) {
		return nil, x86TLSMoveContext("source/object TEXT inventories differ")
	}
	rows := make(map[string][]x86TLSListingRow)
	var symbol string
	scanner := bufio.NewScanner(bytes.NewReader(listing))
	scanner.Buffer(nil, 4<<20)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "STEXT" {
			symbol = fields[0]
			if _, duplicate := rows[symbol]; duplicate {
				return nil, x86TLSMoveContext("duplicate native listing TEXT")
			}
			rows[symbol] = nil
			continue
		}
		if row := goAMD64FrameRow.FindStringSubmatch(line); row != nil {
			pc, err := strconv.ParseInt(row[1], 16, 64)
			separator := strings.LastIndexByte(row[2], ':')
			if err != nil || pc < 0 || symbol == "" || separator < 0 {
				return nil, x86TLSMoveContext("unbound native listing source position")
			}
			sourceLine, err := strconv.Atoi(row[2][separator+1:])
			if err != nil || sourceLine <= 0 {
				return nil, x86TLSMoveContext("invalid native listing source line")
			}
			rows[symbol] = append(rows[symbol], x86TLSListingRow{pc, row[2][:separator], sourceLine, strings.TrimSpace(row[3])})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(rows) != len(texts) {
		return nil, x86TLSMoveContext("complete listing/object TEXT inventories differ")
	}
	lines := strings.Split(expanded, "\n")
	lineCursor := 0
	var sites []x86TLSNoopSite
	for functionIndex, function := range file.Funcs {
		name := numericalNativeName(function.Sym, packagePath)
		text := texts[functionIndex]
		if name != text.Name || text.ABI != 0 {
			return nil, x86TLSMoveContext("source/object TEXT symbol or ABI differs")
		}
		observed, present := rows[name]
		if !present {
			return nil, x86TLSMoveContext("listing lacks exact source TEXT")
		}
		for index, row := range observed {
			physical, valid := originalGoObjectSourcePath(row.file, "")
			if !valid || physical != expandedPath || row.line > len(lines) || row.pc > text.Size ||
				index != 0 && row.pc < observed[index-1].pc {
				return nil, x86TLSMoveContext("native listing PC/file extent differs")
			}
		}
		for instructionIndex, instruction := range function.Instrs {
			// DATA/GLOBL declarations are not function instructions. The complete
			// object equality still checks their effect on every native body.
			for lineCursor < len(lines) && strings.TrimSpace(lines[lineCursor]) != instruction.Raw {
				lineCursor++
			}
			if lineCursor >= len(lines) {
				return nil, x86TLSMoveContext("parsed instruction lacks its exact expanded statement")
			}
			line := lineCursor + 1
			lineCursor++
			form, known, err := x86TLSMoveProperties(instruction, arch)
			if err != nil {
				return nil, err
			}
			if !known || form.memory >= 0 {
				continue
			}
			var matching []int
			for index, row := range observed {
				if row.line == line {
					matching = append(matching, index)
				}
			}
			// Initial-exec and runtime-indirection rows remain observed source,
			// but never become a NOP certificate. No OS-name decision is used.
			if len(matching) != 1 || observed[matching[0]].operation != "NOP" {
				continue
			}
			index := matching[0]
			end := text.Size
			if index+1 < len(observed) {
				end = observed[index+1].pc
			}
			if observed[index].pc != end {
				return nil, x86TLSMoveContext("source NOP has an unexpected native byte extent")
			}
			for _, relocation := range text.Relocations {
				if relocation.Size != 0 && relocation.Offset < end && relocation.Offset+relocation.Size > observed[index].pc {
					return nil, x86TLSMoveContext("source NOP intersects a native relocation")
				}
			}
			sites = append(sites, x86TLSNoopSite{functionIndex, instructionIndex, line, observed[index].pc})
		}
	}
	return sites, nil
}
