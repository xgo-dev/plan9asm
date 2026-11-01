package gostaticstorage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"text/scanner"
	"unicode"
)

type asmDataLayoutState struct {
	layout     ASMGlobalLayout
	global     bool
	kind       uint8
	actualSize int64
	data       []byte
	addresses  []ASMDataFragment
}

func asmDataProgramFingerprint(source []byte) (string, error) {
	statements, err := asmDataStatements(source)
	if err != nil {
		return "", err
	}
	// Preserve complete statement/token order, not merely DATA values. Raw
	// source hashes remain separate; whitespace/comments do not change grammar.
	type token struct {
		Kind rune
		Text string
	}
	program := make([][]token, len(statements))
	for ordinal, statement := range statements {
		for _, value := range statement {
			program[ordinal] = append(program[ordinal], token{value.kind, value.text})
		}
	}
	encoded, err := json.Marshal(program)
	if err != nil {
		return "", err
	}
	return digest(encoded), nil
}

func joinASMSourceTexts(source []byte, packagePath string, member ASMDataMember) error {
	_, err := ASMSourceTextOrder(source, packagePath, member)
	return err
}

func asmDataStatements(source []byte) ([][]asmDataToken, error) {
	if len(source) == 0 || len(source) > archiveLimit || bytes.IndexByte(source, 0) >= 0 {
		return nil, contextError("DATA source violates its complete byte bound")
	}
	var lexicalError error
	var lexer scanner.Scanner
	lexer.Init(bytes.NewReader(source))
	lexer.Whitespace = 1<<'\t' | 1<<'\r' | 1<<' '
	lexer.Mode = scanner.ScanChars | scanner.ScanFloats | scanner.ScanIdents |
		scanner.ScanInts | scanner.ScanStrings | scanner.ScanComments
	lexer.IsIdentRune = func(ch rune, index int) bool {
		return unicode.IsLetter(ch) || ch == '_' || ch == '·' || ch == '∕' || index > 0 && unicode.IsDigit(ch)
	}
	lexer.Error = func(_ *scanner.Scanner, message string) {
		lexicalError = contextError("invalid DATA source token: " + message)
	}
	var statements [][]asmDataToken
	var statement []asmDataToken
	for {
		kind := lexer.Scan()
		text := lexer.TokenText()
		if lexicalError != nil {
			return nil, lexicalError
		}
		if kind == scanner.Comment {
			continue
		}
		if kind == '#' {
			return nil, contextError("DATA source needs an independent CPP/generated-header observation")
		}
		if kind == '\n' || kind == ';' || kind == scanner.EOF {
			if len(statement) != 0 {
				if len(statements) >= symbolLimit {
					return nil, contextError("DATA source statement inventory exceeds its bound")
				}
				statements = append(statements, statement)
				statement = nil
			}
			if kind == scanner.EOF {
				return statements, nil
			}
			continue
		}
		if (kind == '<' || kind == '>') && lexer.Peek() == kind {
			lexer.Next()
			text += text
			if kind == '<' {
				kind = asmDataLeftShift
			} else {
				kind = asmDataRightShift
			}
		}
		// Go lex.Make normalizes these characters in every token, including
		// string and character literals, not just identifiers.
		text = strings.ReplaceAll(strings.ReplaceAll(text, "·", "."), "∕", "/")
		statement = append(statement, asmDataToken{kind: kind, text: text, line: lexer.Position.Line})
		if len(statement) > symbolLimit {
			return nil, contextError("DATA statement token inventory exceeds its bound")
		}
	}
}

func asmDataOperands(tokens []asmDataToken) [][]asmDataToken {
	var operands [][]asmDataToken
	start, depth := 0, 0
	for index, token := range tokens {
		if token.kind == '(' {
			depth++
		} else if token.kind == ')' {
			depth--
		} else if token.kind == ',' && depth == 0 {
			operands = append(operands, tokens[start:index])
			start = index + 1
		}
	}
	return append(operands, tokens[start:])
}

// Go PathToPrefix escapes bytes, and only escapes periods in the last path
// segment. This is source spelling normalization, not a package authority test.
func asmDataPackagePrefix(path string) string {
	const hex = "0123456789abcdef"
	slash := strings.LastIndexByte(path, '/')
	var prefix strings.Builder
	for index := 0; index < len(path); index++ {
		ch := path[index]
		if ch <= ' ' || ch == '.' && index > slash || ch == '%' || ch == '"' || ch >= 0x7f {
			prefix.WriteByte('%')
			prefix.WriteByte(hex[ch>>4])
			prefix.WriteByte(hex[ch&15])
		} else {
			prefix.WriteByte(ch)
		}
	}
	return prefix.String()
}

func asmDataSymbol(tokens []asmDataToken, packagePath string) (ASMDataAddressValue, error) {
	var symbol ASMDataAddressValue
	if len(tokens) < 4 || tokens[0].kind != scanner.Ident || tokens[len(tokens)-3].kind != '(' ||
		tokens[len(tokens)-2].text != "SB" || tokens[len(tokens)-1].kind != ')' {
		return symbol, contextError("DATA/GLOBL requires an exact symbol(SB) operand")
	}
	symbol.Name = tokens[0].text
	if strings.HasPrefix(symbol.Name, ".") {
		symbol.Name = asmDataPackagePrefix(packagePath) + symbol.Name
	}
	p := &asmDataExpression{tokens: tokens[1 : len(tokens)-3]}
	if p.peek() == '<' {
		p.next()
		if p.peek() == '>' {
			symbol.Static, symbol.ABI = true, 65535
		} else {
			selector := p.next()
			if selector.kind != scanner.Ident || selector.text != "ABI0" && selector.text != "ABIInternal" {
				return symbol, contextError("unknown DATA/GLOBL symbol ABI selector")
			}
			if selector.text == "ABIInternal" {
				symbol.ABI = 1
			}
		}
		if p.next().kind != '>' {
			return symbol, contextError("unclosed DATA/GLOBL symbol attributes")
		}
	}
	if p.peek() == '+' || p.peek() == '-' {
		symbol.Addend = int64(p.integer())
	}
	if p.err != nil || p.pos != len(p.tokens) {
		return symbol, contextError("unconsumed or invalid DATA/GLOBL symbol operand")
	}
	return symbol, nil
}

func asmDataValue(tokens []asmDataToken, width int64, packagePath string, pointerWidth int64) (ASMDataFragment, error) {
	fragment := ASMDataFragment{Width: width}
	if len(tokens) < 2 || tokens[0].kind != '$' || width < 0 || width > archiveLimit {
		return fragment, contextError("DATA requires a bounded immediate value")
	}
	value := tokens[1:]
	if value[0].kind == scanner.String {
		text, err := strconv.Unquote(value[0].text)
		if err != nil || len(value) != 1 || int64(len(text)) > width {
			return fragment, contextError("invalid or oversized DATA string value")
		}
		fragment.Kind, fragment.String = ASMDataString, []byte(text)
		return fragment, nil
	}
	if value[0].kind == scanner.Ident {
		symbol, err := asmDataSymbol(value, packagePath)
		if err != nil || width != pointerWidth {
			return fragment, contextError("DATA address requires an exact pointer-sized symbol value")
		}
		fragment.Kind, fragment.Address = ASMDataAddress, &symbol
		return fragment, nil
	}
	for _, token := range value {
		if token.kind != scanner.Float {
			continue
		}
		if width != 4 && width != 8 {
			return fragment, contextError("DATA float requires width 4 or 8")
		}
		p := &asmDataExpression{tokens: value}
		floatValue := p.floating()
		if p.err != nil || p.pos != len(value) {
			return fragment, contextError("invalid DATA float expression")
		}
		fragment.Kind = ASMDataFloat
		if width == 4 {
			fragment.Bits = uint64(math.Float32bits(float32(floatValue)))
		} else {
			fragment.Bits = math.Float64bits(floatValue)
		}
		return fragment, nil
	}
	if width != 1 && width != 2 && width != 4 && width != 8 {
		return fragment, contextError("DATA integer requires width 1, 2, 4 or 8")
	}
	valueBits, err := asmDataInteger(value)
	if err != nil {
		return fragment, err
	}
	fragment.Kind, fragment.Bits = ASMDataInteger, valueBits
	if width != 8 {
		fragment.Bits &= uint64(1)<<(uint(width)*8) - 1
	}
	return fragment, nil
}

func parseASMDataSource(source []byte, packagePath, target string) ([]asmDataLayoutState, error) {
	statements, err := asmDataStatements(source)
	if err != nil {
		return nil, err
	}
	pointerWidth := int64(8)
	if !X86SDKTarget(target) {
		return nil, contextError("DATA source target has no observed pointer width")
	}
	if strings.HasSuffix(target, "/386") {
		pointerWidth = 4
	}
	states := make(map[string]*asmDataLayoutState)
	lastEnd := make(map[string]int64)
	totalWritten := int64(0)
	var ordered []*asmDataLayoutState
	for ordinal, statement := range statements {
		if statement[0].text != "DATA" && statement[0].text != "GLOBL" {
			continue
		}
		operands := asmDataOperands(statement[1:])
		global := statement[0].text == "GLOBL"
		if !global && len(operands) != 2 || global && len(operands) != 2 && len(operands) != 3 {
			return nil, contextError("invalid DATA/GLOBL operand count")
		}
		nameTokens := operands[0]
		width := int64(0)
		if !global {
			length := len(nameTokens)
			if length < 3 || nameTokens[length-2].kind != '/' || nameTokens[length-1].kind != scanner.Int {
				return nil, contextError("DATA width must be one decimal integer token")
			}
			parsedWidth, err := strconv.ParseInt(nameTokens[length-1].text, 10, 64)
			if err != nil {
				return nil, contextError("invalid DATA width token")
			}
			width, nameTokens = parsedWidth, nameTokens[:length-2]
		}
		symbol, err := asmDataSymbol(nameTokens, packagePath)
		if err != nil || global && symbol.Addend != 0 || !global && (symbol.Addend < 0 || symbol.Addend > archiveLimit-width) {
			return nil, contextError("invalid or unbounded DATA/GLOBL symbol extent")
		}
		key := fmt.Sprintf("%s\x00%d", symbol.Name, symbol.ABI)
		state := states[key]
		if state == nil {
			state = &asmDataLayoutState{layout: ASMGlobalLayout{Name: symbol.Name, Static: symbol.Static, ABI: symbol.ABI}}
			states[key] = state
		}
		if global {
			if state.global {
				return nil, contextError("duplicate source GLOBL declaration")
			}
			flags := uint64(0)
			if len(operands) == 3 {
				flags, err = asmDataInteger(operands[1])
				if err != nil {
					return nil, err
				}
			}
			sizeOperand := operands[len(operands)-1]
			if len(sizeOperand) < 2 || sizeOperand[0].kind != '$' {
				return nil, contextError("GLOBL extent must be an immediate integer")
			}
			size, err := asmDataInteger(sizeOperand[1:])
			if err != nil || int64(size) < 0 || size > archiveLimit {
				return nil, contextError("GLOBL declared extent exceeds its byte bound")
			}
			state.global, state.actualSize = true, int64(size)
			state.layout.Ordinal, state.layout.Line = ordinal, statement[0].line
			state.layout.Flags, state.layout.DeclaredSize = flags, int64(size)
			if state.kind == 0 {
				state.kind = 9 // SBSS.
			}
			switch {
			case flags&8 != 0:
				state.kind = 3 // SRODATA.
			case flags&16 != 0:
				if state.kind == 7 || state.kind == 8 {
					state.kind = 5 // SNOPTRDATA.
				} else {
					state.kind = 10 // SNOPTRBSS.
				}
			case flags&256 != 0:
				state.kind = 11 // STLSBSS.
			}
			ordered = append(ordered, state)
			continue
		}
		if end, present := lastEnd[symbol.Name]; present && symbol.Addend < end {
			return nil, contextError("source DATA entries overlap or are nonmonotonic")
		}
		fragment, err := asmDataValue(operands[1], width, packagePath, pointerWidth)
		if err != nil {
			return nil, err
		}
		fragment.Ordinal, fragment.Line, fragment.Offset = ordinal, statement[0].line, symbol.Addend
		lastEnd[symbol.Name] = symbol.Addend + width
		if state.kind == 11 {
			return nil, contextError("source DATA initializes TLSBSS")
		}
		if state.kind == 0 || state.kind == 9 {
			state.kind = 7 // SDATA.
		} else if state.kind == 10 {
			state.kind = 5 // SNOPTRDATA.
		}
		end := fragment.Offset + fragment.Width
		if end > int64(len(state.data)) {
			totalWritten += end - int64(len(state.data))
			if totalWritten > archiveLimit {
				return nil, contextError("DATA complete written layout inventory exceeds its object byte bound")
			}
			state.data = append(state.data, make([]byte, end-int64(len(state.data)))...)
		}
		if end > state.actualSize {
			state.actualSize = end
		}
		for byteIndex := int64(0); byteIndex < fragment.Width; byteIndex++ {
			switch fragment.Kind {
			case ASMDataInteger, ASMDataFloat:
				state.data[fragment.Offset+byteIndex] = byte(fragment.Bits >> (8 * uint(byteIndex)))
			case ASMDataString:
				if byteIndex < int64(len(fragment.String)) {
					state.data[fragment.Offset+byteIndex] = fragment.String[byteIndex]
				}
			}
		}
		if fragment.Kind == ASMDataAddress {
			state.addresses = append(state.addresses, fragment)
		}
		state.layout.Fragments = append(state.layout.Fragments, fragment)
	}
	if len(ordered) != len(states) {
		return nil, contextError("source DATA lacks its complete GLOBL/object layout")
	}
	result := make([]asmDataLayoutState, len(ordered))
	for index, state := range ordered {
		result[index] = *state
	}
	return result, nil
}
