package gostaticstorage

import (
	"strconv"
	"text/scanner"
	"unicode/utf8"
)

const (
	asmDataLeftShift  rune = -1000
	asmDataRightShift rune = -1001
)

type asmDataToken struct {
	kind rune
	text string
	line int
}

type asmDataExpression struct {
	tokens []asmDataToken
	pos    int
	err    error
	depth  int
}

func (p *asmDataExpression) peek() rune {
	if p.pos >= len(p.tokens) {
		return scanner.EOF
	}
	return p.tokens[p.pos].kind
}

func (p *asmDataExpression) next() asmDataToken {
	if p.pos >= len(p.tokens) {
		return asmDataToken{kind: scanner.EOF}
	}
	token := p.tokens[p.pos]
	p.pos++
	return token
}

func (p *asmDataExpression) fail(message string) {
	if p.err == nil {
		p.err = contextError(message)
	}
}

func (p *asmDataExpression) enter() bool {
	p.depth++
	if p.depth > 256 {
		p.fail("DATA expression nesting exceeds its observation bound")
		return false
	}
	return true
}

// These are Go assembler uint64 expression rules, not Go constant folding.
// In particular left shift consumes one factor and returns its term, whereas
// right shift consumes a term on the right. Preserve those actual parser rules.
func (p *asmDataExpression) integer() uint64 {
	value := p.term()
	for p.err == nil {
		switch p.peek() {
		case '+':
			p.next()
			value += p.term()
		case '-':
			p.next()
			value -= p.term()
		case '|':
			p.next()
			value |= p.term()
		case '^':
			p.next()
			value ^= p.term()
		default:
			return value
		}
	}
	return 0
}

func (p *asmDataExpression) term() uint64 {
	if !p.enter() {
		return 0
	}
	defer func() { p.depth-- }()
	value := p.factor()
	for p.err == nil {
		switch p.peek() {
		case '*':
			p.next()
			value *= p.factor()
		case '/', '%':
			operator := p.next().kind
			divisor := p.factor()
			if int64(value) < 0 || divisor == 0 {
				p.fail("DATA division/modulo has a high-bit dividend or zero divisor")
				return 0
			}
			if operator == '/' {
				value /= divisor
			} else {
				value %= divisor
			}
		case asmDataLeftShift:
			p.next()
			shift := p.factor()
			if int64(shift) < 0 {
				p.fail("DATA left shift has a negative count")
				return 0
			}
			return value << shift
		case asmDataRightShift:
			p.next()
			shift := p.term()
			if int64(shift) < 0 || int64(value) < 0 {
				p.fail("DATA right shift has a negative count or high-bit value")
				return 0
			}
			value >>= shift
		case '&':
			p.next()
			value &= p.factor()
		default:
			return value
		}
	}
	return 0
}

func (p *asmDataExpression) factor() uint64 {
	if !p.enter() {
		return 0
	}
	defer func() { p.depth-- }()
	token := p.next()
	switch token.kind {
	case scanner.Int:
		value, err := strconv.ParseUint(token.text, 0, 64)
		if err != nil {
			p.fail("invalid DATA integer token")
		}
		return value
	case scanner.Char:
		text, err := strconv.Unquote(token.text)
		value, size := utf8.DecodeRuneInString(text)
		if err != nil || size == 1 && value == utf8.RuneError {
			p.fail("invalid DATA character token")
		}
		return uint64(value)
	case '+':
		return p.factor()
	case '-':
		return -p.factor()
	case '~':
		return ^p.factor()
	case '(':
		value := p.integer()
		if p.next().kind != ')' {
			p.fail("unclosed DATA integer expression")
		}
		return value
	default:
		p.fail("DATA value is not an integer expression")
		return 0
	}
}

func (p *asmDataExpression) floating() float64 {
	if !p.enter() {
		return 0
	}
	defer func() { p.depth-- }()
	token := p.next()
	switch token.kind {
	case scanner.Float:
		value, err := strconv.ParseFloat(token.text, 64)
		if err != nil {
			p.fail("invalid or out-of-range DATA float token")
		}
		return value
	case '+':
		return p.floating()
	case '-':
		return -p.floating()
	case '(':
		value := p.floating()
		if p.next().kind != ')' {
			p.fail("unclosed DATA float expression")
		}
		return value
	default:
		p.fail("DATA float grammar admits only a float token, signs and parentheses")
		return 0
	}
}

func asmDataInteger(tokens []asmDataToken) (uint64, error) {
	p := &asmDataExpression{tokens: tokens}
	value := p.integer()
	if p.pos != len(tokens) {
		p.fail("unconsumed DATA integer expression")
	}
	return value, p.err
}
