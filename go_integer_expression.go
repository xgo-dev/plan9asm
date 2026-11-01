package plan9asm

import (
	"strconv"
	"strings"
	"text/scanner"
	"unicode/utf8"
)

const (
	goIntegerExpressionMaxBytes  = 64 << 10
	goIntegerExpressionMaxTokens = 4096
	goIntegerExpressionMaxDepth  = 128
)

// Integer immediates use cmd/asm's expr/term/factor grammar, not Go's AST
// grammar. In particular, SHR consumes a term, whereas SHL consumes a factor
// and finishes its term. The caller must consume the complete expression.
func parseImmExpr(text string) (uint64, bool) {
	if len(text) > goIntegerExpressionMaxBytes {
		return 0, false
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, false
	}
	if value, err := strconv.ParseUint(text, 0, 64); err == nil {
		return value, true
	}
	parser := goIntegerExpression{reader: newPPGoReader("<integer-expression>", text), valid: true}
	parser.next()
	value := parser.expression()
	return value.bits, parser.valid && parser.token.kind == scanner.EOF && value.known
}

// A generated-header expression can be syntactically complete without a
// numerical value. This query uses the same bounded assembler grammar, but
// never exposes its placeholder arithmetic as a resolved immediate.
func goIntegerExpressionNeedsContext(text string) bool {
	if len(text) > goIntegerExpressionMaxBytes {
		return false
	}
	parser := goIntegerExpression{reader: newPPGoReader("<symbolic-expression>", text),
		valid: true, allowUnknown: true}
	parser.next()
	value := parser.expression()
	return parser.valid && parser.token.kind == scanner.EOF && !value.known
}

type goIntegerValue struct {
	bits  uint64
	known bool
}

type goIntegerExpression struct {
	reader       *ppGoReader
	token        ppGoToken
	tokens       int
	depth        int
	valid        bool
	allowUnknown bool
}

func (parser *goIntegerExpression) next() {
	if !parser.valid {
		return
	}
	parser.tokens++
	if parser.tokens > goIntegerExpressionMaxTokens {
		parser.valid = false
		return
	}
	token, err := parser.reader.next()
	parser.token = token
	parser.valid = err == nil
}

func (parser *goIntegerExpression) enter() bool {
	if !parser.valid || parser.depth >= goIntegerExpressionMaxDepth {
		parser.valid = false
		return false
	}
	parser.depth++
	return true
}

func (parser *goIntegerExpression) expression() goIntegerValue {
	value := parser.term()
	for parser.valid {
		switch parser.token.text {
		case "+", "-", "|", "^":
			operator := parser.token.text
			parser.next()
			right := parser.term()
			value.known = value.known && right.known
			switch operator {
			case "+":
				value.bits += right.bits
			case "-":
				value.bits -= right.bits
			case "|":
				value.bits |= right.bits
			case "^":
				value.bits ^= right.bits
			}
		default:
			return value
		}
	}
	return goIntegerValue{}
}

func (parser *goIntegerExpression) term() goIntegerValue {
	if !parser.enter() {
		return goIntegerValue{}
	}
	defer func() { parser.depth-- }()
	value := parser.factor()
	for parser.valid {
		operator := parser.token.text
		switch operator {
		case "*", "/", "%", "&":
			parser.next()
			right := parser.factor()
			switch operator {
			case "*":
				value.bits *= right.bits
			case "/", "%":
				if value.known && int64(value.bits) < 0 || right.known && right.bits == 0 {
					parser.valid = false
					return goIntegerValue{}
				}
				if !value.known || !right.known {
					value.bits = 0
				} else if operator == "/" {
					value.bits /= right.bits
				} else {
					value.bits %= right.bits
				}
			case "&":
				value.bits &= right.bits
			}
			value.known = value.known && right.known
		case "<<", ">>":
			parser.next()
			var shift goIntegerValue
			if operator == "<<" {
				shift = parser.factor()
			} else {
				shift = parser.term()
			}
			if !parser.valid || shift.known && int64(shift.bits) < 0 ||
				operator == ">>" && value.known && int64(value.bits) < 0 {
				parser.valid = false
				return goIntegerValue{}
			}
			value.known = value.known && shift.known
			if operator == "<<" {
				value.bits <<= shift.bits
				return value
			}
			value.bits >>= shift.bits
		default:
			return value
		}
	}
	return goIntegerValue{}
}

func (parser *goIntegerExpression) factor() goIntegerValue {
	if !parser.enter() {
		return goIntegerValue{}
	}
	defer func() { parser.depth-- }()
	token := parser.token
	parser.next()
	switch token.kind {
	case scanner.Ident:
		_, register := parseReg(token.text)
		if parser.allowUnknown && !register && token.text != "g" {
			return goIntegerValue{} // Unknown, never a resolved numerical zero.
		}
		parser.valid = false
		return goIntegerValue{}
	case scanner.Int:
		value, err := strconv.ParseUint(token.text, 0, 64)
		parser.valid = parser.valid && err == nil
		return goIntegerValue{bits: value, known: true}
	case scanner.Char:
		text, err := strconv.Unquote(token.text)
		value, width := utf8.DecodeRuneInString(text)
		parser.valid = parser.valid && err == nil && text != "" && width == len(text) &&
			!(value == utf8.RuneError && width == 1)
		return goIntegerValue{bits: uint64(value), known: true}
	case '+':
		return parser.factor()
	case '-':
		value := parser.factor()
		value.bits = -value.bits
		return value
	case '~':
		value := parser.factor()
		value.bits = ^value.bits
		return value
	case '(':
		value := parser.expression()
		if parser.token.kind != ')' {
			parser.valid = false
			return goIntegerValue{}
		}
		parser.next()
		return value
	default:
		parser.valid = false
		return goIntegerValue{}
	}
}
