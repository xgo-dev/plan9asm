package goasmrules

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
)

// X86SourceRelocation is an instruction-relative source encoding requirement.
// It supplies no symbol address, caller, stack or native execution permission.
type X86SourceRelocation struct {
	Offset, Size int
	Kind, Symbol string
	Add          int64
}

// Canonical witnesses retain the last explicit syntax carrier in Destination.
// Stack, implicit outputs and control-flow effects remain separate contracts.
type X86StackControlWitness struct {
	X86ScalarRMWWitness
	// Origin distinguishes source syntax from direct backend candidates.
	// Neither spelling nor candidate bytes establish an actual observation.
	Origin      string
	Relocations []X86SourceRelocation
	// Local branch witnesses use an independent fixture envelope: this many
	// one-byte padding instructions precede their next RET target.
	BranchPadding int `json:",omitempty"`
}

type X86StackControlRow struct {
	ID, Opcode, ModeFiltered string
	Witnesses                []X86StackControlWitness
}

// X86StackControlSource owns exact original member metadata and optional
// original DUFF frame transport. Its private fields cannot alias callers.
type X86StackControlSource struct {
	members               []byte
	duffBefore, duffAfter []byte
}

func LoadX86StackControlSource(goroot string) (X86StackControlSource, error) {
	var source X86StackControlSource
	catalog, err := LoadX86LegacyRules(goroot)
	if err != nil {
		return source, err
	}
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(goroot, "src/cmd/internal/obj/x86/asm6.go"), nil, 0)
	if err != nil {
		return source, err
	}
	variables, err := x86TableVariables(file)
	if err != nil {
		return source, err
	}
	transport := map[string][]byte{}
	for _, name := range []string{"bpduff1", "bpduff2"} {
		literal := variables[name]
		if literal == nil {
			continue
		}
		if expression(literal.Type) != "[]byte" || len(literal.Elts) == 0 {
			return source, fmt.Errorf("invalid original DUFF frame literal")
		}
		for _, atom := range literal.Elts {
			value, err := strconv.ParseUint(expression(atom), 0, 8)
			if err != nil {
				return source, fmt.Errorf("non-byte original DUFF frame literal")
			}
			// Unlike fixed opBytes literals, these slices include zero bytes.
			transport[name] = append(transport[name], byte(value))
		}
	}
	uses := map[string]int{}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "doasm" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Put" {
				return true
			}
			receiver, valid := selector.X.(*ast.Ident)
			argument, named := call.Args[0].(*ast.Ident)
			if valid && named && receiver.Name == "ab" && (argument.Name == "bpduff1" || argument.Name == "bpduff2") {
				uses[argument.Name]++
			}
			return true
		})
	}
	if len(transport) != 0 || len(uses) != 0 {
		if len(transport) != 2 || len(uses) != 2 || uses["bpduff1"] != 1 || uses["bpduff2"] != 1 {
			return source, fmt.Errorf("incomplete original DUFF frame transport")
		}
	}
	source.duffBefore, source.duffAfter = transport["bpduff1"], transport["bpduff2"]
	source.members, err = x86LegacySourceMembers(catalog, x86StackControlSchema)
	return source, err
}

func x86StackControlSchema(table string) []string {
	switch table {
	case "ycall":
		return []string{"Zcallindreg/0/Yml", "Zcallindreg/2/Yrx,Yrx", "Zcallind/2/Yindir", "Zcall/0/Ybr", "Zcallcon/1/Yi32"}
	case "yloop":
		return []string{"Zloop/1/Ybr"}
	case "yjmp":
		return []string{"Zo_m64/2/Yml", "Zjmp/0/Ybr", "Zjmpcon/1/Yi32"}
	case "ypopl":
		return []string{"Z_rp/1/Yrl", "Zo_m/2/Ym"}
	case "ypushl":
		return []string{"Zrp_/1/Yrl", "Zm_o/2/Ym", "Zib_/1/Yi8", "Zil_/1/Yi32"}
	case "yret":
		return []string{"Zo_iw/1/", "Zo_iw/1/Yi32"}
	case "yduff":
		return []string{"Zcallduff/1/Yi32"}
	}
	return nil
}

func X86StackControlRows(catalog X86LegacyCatalog, source X86StackControlSource, arch string) ([]X86StackControlRow, error) {
	if arch != "amd64" && arch != "386" || len(source.members) == 0 {
		return nil, fmt.Errorf("stack/control source requires an original source and x86 mode")
	}
	members, err := x86LegacySourceMembers(catalog, x86StackControlSchema)
	if err != nil || !bytes.Equal(members, source.members) {
		return nil, fmt.Errorf("stack/control members differ from the captured Go source")
	}
	var result []X86StackControlRow
	names, counts := map[string]bool{}, map[string]int{}
	for index, entry := range catalog.Optab {
		if x86StackControlSchema(entry.Ytab) == nil {
			continue
		}
		if entry.TableIndex != index || names[entry.Opcode] {
			return nil, fmt.Errorf("original stack/control index or member duplicated")
		}
		names[entry.Opcode] = true
		for _, operand := range entry.Rows {
			witnesses, err := x86StackControlWitnesses(entry, operand, source, arch, catalog.OpBytesSize)
			if err != nil {
				return nil, fmt.Errorf("%s/%d: %w", entry.Opcode, operand.RowIndex, err)
			}
			row := X86StackControlRow{ID: fmt.Sprintf("optab/%d/%s/%s/%d", index, entry.Opcode, entry.Ytab, operand.RowIndex), Opcode: entry.Opcode, Witnesses: witnesses}
			if entry.Prefix == "P32" && arch == "amd64" || (entry.Prefix == "Py" || entry.Prefix == "Pw") && arch == "386" {
				row.ModeFiltered, row.Witnesses = "original Go "+entry.Prefix+" rejects this source mode", nil
			}
			result = append(result, row)
			counts[entry.Ytab]++
		}
	}
	want := map[string]int{"ycall": 5, "yloop": 6, "yjmp": 3, "ypopl": 6, "ypushl": 12, "yret": 6, "yduff": 2}
	if len(result) != 40 || len(names) != 19 || len(counts) != len(want) {
		return nil, fmt.Errorf("incomplete original stack/control source cohort")
	}
	for table, count := range want {
		if counts[table] != count {
			return nil, fmt.Errorf("incomplete stack/control source table %s", table)
		}
	}
	return result, nil
}

func x86StackControlWitnesses(entry X86LegacyOpcode, row X86LegacyOperand, source X86StackControlSource, arch string, capacity int) ([]X86StackControlWitness, error) {
	if entry.Kind != "encoding" || entry.Opcode == "" || entry.OpcodeExpression == "" || entry.TableIndex < 0 ||
		capacity <= 0 || len(entry.OpBytes) == 0 || len(entry.OpBytes) > capacity || arch != "amd64" && arch != "386" {
		return nil, fmt.Errorf("invalid captured stack/control entry")
	}
	if err := x86ScalarCompleteOperandSchema(entry, row, x86StackControlSchema(entry.Ytab)); err != nil {
		return nil, err
	}
	var prefix []byte
	switch entry.Prefix {
	case "Px", "P32", "Py":
	case "Pe":
		prefix = []byte{0x66}
	case "Pw":
		prefix = []byte{0x48}
	default:
		return nil, fmt.Errorf("unmodeled stack/control source prefix")
	}
	payload := make([]byte, len(entry.OpBytes))
	for index, atom := range entry.OpBytes {
		value, err := strconv.ParseUint(atom, 0, 8)
		if err != nil {
			return nil, fmt.Errorf("stack/control source contains a non-byte atom")
		}
		payload[index] = byte(value)
	}
	if entry.EscapeAdjustment != 0 || row.UnmatchedOffset >= len(payload) {
		return nil, fmt.Errorf("stack/control source offset or escape changed")
	}
	offset, opcode := row.UnmatchedOffset, payload[row.UnmatchedOffset]
	span := func(length int) bool { return offset+length <= len(payload) }
	var result []X86StackControlWitness
	add := func(arguments string, code []byte, padding int, relocations ...X86SourceRelocation) {
		for index := range relocations {
			// R_CALLIND is a zero-size marker at the instruction's start;
			// encoded displacement fields follow the emitted prefixes.
			if relocations[index].Size != 0 {
				relocations[index].Offset += len(prefix)
			}
		}
		origin := "stock-asm"
		if row.ZCase == "Zcallduff" {
			origin = "stock-backend"
		}
		result = append(result, X86StackControlWitness{
			X86ScalarRMWWitness: X86ScalarRMWWitness{Instruction: strings.TrimSpace(entry.Opcode + " " + arguments),
				Destination: arguments[strings.LastIndex(arguments, ",")+1:], Encoding: append(append([]byte(nil), prefix...), code...)},
			Origin: origin, Relocations: relocations, BranchPadding: padding})
	}
	switch row.ZCase {
	case "Z_rp", "Zrp_":
		add("BX", []byte{opcode + 3}, 0)
	case "Zo_m", "Zm_o", "Zo_m64", "Zcallindreg":
		if !span(2) || payload[offset+1] > 7 {
			return nil, fmt.Errorf("stack/control source lacks a valid group extension")
		}
		operands := []string{"0(SI)"}
		if row.ZCase == "Zo_m64" || row.ZCase == "Zcallindreg" {
			operands = []string{"BX", "0(SI)"}
		}
		if len(row.Classes) == 2 {
			operands = []string{"CX,BX"}
		}
		for _, arguments := range operands {
			modrm := byte(6)
			if strings.HasSuffix(arguments, "BX") {
				modrm = 0xc3
			}
			var relocations []X86SourceRelocation
			if row.ZCase == "Zcallindreg" {
				relocations = []X86SourceRelocation{{Kind: "R_CALLIND"}}
			}
			add(arguments, x86SourceModRMBytes(nil, opcode, modrm|payload[offset+1]<<3), 0, relocations...)
		}
	case "Zib_", "Zil_", "Zo_iw":
		value, width, arguments := 7, 1, "$7"
		if row.ZCase == "Zil_" {
			value, width, arguments = 300, 4, "$300"
			if entry.Prefix == "Pe" {
				width = 2
			}
		} else if row.ZCase == "Zo_iw" {
			value, width, arguments = 37, 2, "$37"
			if len(row.Classes) == 0 {
				width, arguments = 0, ""
			}
		}
		code := []byte{opcode}
		for index := 0; index < width; index++ {
			code = append(code, byte(value>>uint(index*8)))
		}
		add(arguments, code, 0)
	case "Zcall", "Zcallduff":
		arguments, symbol, addend := "·Target+7(SB)", "literal.Target", int64(7)
		code, displacement := []byte{opcode, 0, 0, 0, 0}, 1
		if row.ZCase == "Zcallduff" {
			symbol, addend = "runtime."+strings.ToLower(entry.Opcode), 37
			arguments = "$" + strings.Replace(symbol, ".", "·", 1) + "+37(SB)"
			if arch == "amd64" {
				code = append(append(append([]byte(nil), source.duffBefore...), code...), source.duffAfter...)
				displacement += len(source.duffBefore)
			}
		}
		add(arguments, code, 0, X86SourceRelocation{displacement, 4, "R_CALL", symbol, addend})
	case "Zcallcon", "Zjmpcon":
		if row.ZCase == "Zjmpcon" {
			if !span(2) {
				return nil, fmt.Errorf("constant jump lost its near opcode")
			}
			opcode = payload[offset+1]
		}
		add("$37", []byte{opcode, 0, 0, 0, 0}, 0, X86SourceRelocation{1, 4, "R_PCREL", "", 37})
	case "Zloop", "Zjmp":
		code := []byte{opcode, 1}
		if entry.Opcode == "JCXZL" {
			code = append([]byte{0x67}, code...)
		}
		add("after", code, 1)
		if row.ZCase == "Zjmp" {
			if !span(2) {
				return nil, fmt.Errorf("local jump lost its near opcode")
			}
			add("after", []byte{payload[offset+1], 160, 0, 0, 0}, 160)
			add("·Target(SB)", []byte{payload[offset+1], 0, 0, 0, 0}, 0, X86SourceRelocation{1, 4, "R_CALL", "literal.Target", 0})
		}
	case "Zcallind":
		if !span(2) {
			return nil, fmt.Errorf("symbol-indirect call lost its group encoding")
		}
		kind := "R_PCREL"
		if arch == "386" {
			kind = "R_ADDR"
		}
		add("*·Target(SB)", []byte{opcode, payload[offset+1], 0, 0, 0, 0}, 0, X86SourceRelocation{2, 4, kind, "literal.Target", 0})
	default:
		return nil, fmt.Errorf("unmodeled stack/control encoding group")
	}
	return result, nil
}
