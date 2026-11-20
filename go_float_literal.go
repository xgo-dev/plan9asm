package plan9asm

import (
	"strconv"
	"strings"
	"text/scanner"
)

// cmd/asm floatExpr is a FLOAT leaf wrapped in unary +/- or parentheses,
// not the wider binary constant-expression grammar accepted by our parser.
func parseGoFloatLiteral(text string) (float64, bool) {
	var lexer scanner.Scanner
	lexer.Init(strings.NewReader(text))
	lexer.Mode = scanner.ScanInts | scanner.ScanFloats
	valid := true
	lexer.Error = func(*scanner.Scanner, string) { valid = false }
	negative, depth := false, 0
	for next := lexer.Scan(); ; next = lexer.Scan() {
		switch next {
		case '+':
		case '-':
			negative = !negative
		case '(':
			depth++
		case scanner.Float:
			value, err := strconv.ParseFloat(lexer.TokenText(), 64)
			if err != nil {
				return 0, false
			}
			for depth > 0 {
				if lexer.Scan() != ')' {
					return 0, false
				}
				depth--
			}
			if negative {
				value = -value
			}
			return value, valid && lexer.Scan() == scanner.EOF
		default:
			return 0, false
		}
	}
}
