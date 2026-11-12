package goasmoracle

import (
	"strconv"
	"strings"
	"text/scanner"
	"unicode"
)

type diagnosticToken struct {
	kind         rune
	text         string
	line, column int
}

// These are the actual cmd/asm lexical roles, not supported instruction names.
// Comments are skipped, but physical newlines retain statement boundaries.
func diagnosticTokens(text string) ([]diagnosticToken, bool) {
	var lexer scanner.Scanner
	lexer.Init(strings.NewReader(text))
	lexer.Whitespace = 1<<'\t' | 1<<'\r' | 1<<' '
	lexer.Mode = scanner.ScanChars | scanner.ScanFloats | scanner.ScanIdents |
		scanner.ScanInts | scanner.ScanStrings | scanner.ScanComments | scanner.SkipComments
	lexer.IsIdentRune = func(ch rune, index int) bool {
		return unicode.IsLetter(ch) || ch == '_' || ch == '·' || ch == '∕' ||
			index > 0 && unicode.IsDigit(ch)
	}
	lexer.Error = func(*scanner.Scanner, string) {}
	var tokens []diagnosticToken
	for kind := lexer.Scan(); kind != scanner.EOF; kind = lexer.Scan() {
		tokens = append(tokens, diagnosticToken{kind, lexer.TokenText(), lexer.Position.Line, lexer.Position.Column})
	}
	return tokens, lexer.ErrorCount == 0
}

func tokenTexts(tokens []diagnosticToken) []string {
	texts := make([]string, len(tokens))
	for i, token := range tokens {
		texts[i] = token.text
	}
	return texts
}

// A recognized frontend diagnostic never falls back to an arbitrary message.
func frontendDiagnostic(data []byte, line, column int, message string, wasmWord bool) (known, bound bool) {
	if strings.HasPrefix(message, "unrecognized instruction") {
		return true, unrecognizedInstructionAt(data, line, column, message, wasmWord)
	}
	const expected = "expected identifier, found "
	if strings.HasPrefix(message, "expected identifier") {
		tokens, ok := diagnosticTokens(strings.Split(string(data), "\n")[line-1])
		if !ok {
			return true, false
		}
		for len(tokens) > 0 {
			if tokens[0].kind == ';' || tokens[0].kind == '\n' {
				tokens = tokens[1:]
				continue
			}
			if tokens[0].kind != scanner.Ident {
				// Go stops at the first invalid statement-start token. A
				// later invalid token, or one in an operand, cannot bind it.
				token := tokens[0]
				return true, message == expected+strconv.Quote(token.text) &&
					(column == 0 || column == token.column)
			}
			if len(tokens) >= 2 && tokens[1].kind == ':' {
				tokens = tokens[2:]
				continue
			}
			for len(tokens) > 0 && tokens[0].kind != ';' && tokens[0].kind != '\n' {
				tokens = tokens[1:]
			}
		}
		return true, false
	}
	if strings.HasPrefix(message, "label ") {
		if column != 0 {
			return true, false // cmd/asm errorf reports this role without a column.
		}
		quoted := strings.TrimSuffix(strings.TrimPrefix(message, "label "), " multiply defined")
		name, err := strconv.Unquote(quoted)
		if err != nil || message != "label "+strconv.Quote(name)+" multiply defined" {
			return true, false
		}
		return true, duplicateLabelAt(data, line, name)
	}
	return false, false
}

// Replay only statement-start word/label roles. Go's actual exit and concrete
// message establish rejection separately. Operand, comment and string tokens
// cannot impersonate the frontend's original word. Whole-source lexing retains
// multiline-comment identity and physical token positions.
func unrecognizedInstructionAt(data []byte, line, column int, message string, wasmWord bool) bool {
	all, ok := diagnosticTokens(string(data))
	if !ok {
		return false
	}
	var tokens []diagnosticToken
	for _, token := range all {
		if token.line == line {
			tokens = append(tokens, token)
		}
	}
	for len(tokens) > 0 {
		if tokens[0].kind == ';' || tokens[0].kind == '\n' {
			tokens = tokens[1:]
			continue
		}
		word := tokens[0]
		if word.kind != scanner.Ident {
			return false // The Go frontend stops at an invalid initial token.
		}
		next := 1
		if !wasmWord {
			for next < len(tokens) && tokens[next].kind == '.' {
				next++
				if next == len(tokens) || tokens[next].kind != scanner.Ident {
					return false
				}
				next++
			}
		}
		if next < len(tokens) && tokens[next].kind == ':' {
			tokens = tokens[next+1:]
			continue
		}
		if message == "unrecognized instruction "+strconv.Quote(word.text) &&
			(column == 0 || column == word.column) {
			return true
		}
		for len(tokens) > 0 && tokens[0].kind != ';' && tokens[0].kind != '\n' {
			tokens = tokens[1:]
		}
	}
	return false
}

// Replay label attachment, not instruction validity. Actual exit 1 and Go's
// concrete errorf message remain separately required by CheckOutcome. TEXT
// resets the definition map; pending labels survive an attachment error.
func duplicateLabelAt(data []byte, line int, name string) bool {
	tokens, ok := diagnosticTokens(string(data))
	if !ok {
		return false
	}
	defined := make(map[string]bool)
	var pending []string
	for i := 0; i < len(tokens); {
		if tokens[i].line > line {
			return false
		}
		if tokens[i].kind == '\n' || tokens[i].kind == ';' {
			i++
			continue
		}
		if tokens[i].kind != scanner.Ident {
			return false
		}
		word, position := tokens[i].text, tokens[i].line
		i++
		if i < len(tokens) && tokens[i].kind == ':' {
			pending = append(pending, word)
			i++
			continue
		}
		// Consume the complete original statement, without borrowing labels
		// hidden in operands, strings or comments. Unobserved CPP is unknown.
		for i < len(tokens) && tokens[i].kind != '\n' && tokens[i].kind != ';' {
			if tokens[i].kind == '#' {
				return false
			}
			i++
		}
		if word == "TEXT" {
			defined = make(map[string]bool)
		}
		if word == "DATA" || word == "GLOBL" {
			continue // These pseudo-ops do not append a Prog.
		}
		duplicate := ""
		for _, label := range pending {
			if defined[label] {
				duplicate = label
				break
			}
			defined[label] = true
		}
		if position == line && duplicate != "" {
			// Several attachment statements may share a physical line.
			// errorf reports only its first error, not a later duplicate.
			return duplicate == name
		}
		if duplicate == "" {
			pending = nil
		}
	}
	return false
}
