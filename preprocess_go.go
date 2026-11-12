package plan9asm

import (
	"fmt"
	"strings"
	"text/scanner"
)

func preprocessGoAssembly(src string, options AssemblyPreprocessOptions) (string, error) {
	return preprocessGoAssemblyObserved(src, options, nil)
}

func preprocessGoAssemblyObserved(src string, options AssemblyPreprocessOptions, observer *ppGoObservation) (string, error) {
	file := options.FileName
	if file == "" {
		file = "<assembly>"
	}
	input := ppGoInput{
		options: options, readers: []*ppGoReader{newPPGoReader(file, src)},
		macros: make(map[string]ppGoMacro), bol: true, observer: observer,
	}
	if observer != nil && observer.positions != nil {
		input.readers[0].positionBase = newSDKCPPFileBase(file)
		input.readers[0].positionLine = 1
	}
	if observer != nil {
		if err := observer.source(file, src); err != nil {
			return "", err
		}
	}
	for _, definition := range options.Defines {
		name, value, assigned := strings.Cut(definition, "=")
		if !assigned {
			value = "1"
		}
		if !validPPIdentifier(name) {
			return "", fmt.Errorf("invalid predefined CPP macro %q", name)
		}
		reader := newPPGoReader("<predefined>", value)
		macro := ppGoMacro{}
		for {
			token, err := reader.next()
			if err != nil {
				return "", err
			}
			if token.kind == scanner.EOF {
				break
			}
			macro.body = append(macro.body, ppGoRecordedToken(token))
		}
		if observer != nil {
			index, err := input.beginObservation("predefine", ppGoToken{file: "<predefined>", line: 1})
			if err != nil {
				return "", err
			}
			event := input.observedEvent()
			event.Name, event.Executed = name, true
			for _, token := range macro.body {
				if err := observer.capture(token); err != nil {
					return "", err
				}
			}
			macro.definition = index + 1
			input.finishObservation(index)
		}
		input.macros[name] = macro
	}
	var output strings.Builder
	var previous ppGoToken
	statementTokens := 0
	parserPositionInitialized := false
	for {
		token, err := input.next()
		if err != nil {
			return "", err
		}
		if token.kind == scanner.EOF {
			if statementTokens != 0 {
				return "", input.errorf("unexpected instruction EOF: missing newline or semicolon")
			}
			break
		}
		if token.kind == '#' {
			// Preserve Input.Next's control-wisp boundary before asking for
			// another token; cached function-macro lookahead may follow it.
			continue
		}
		if token.kind == ppGoMacroName {
			// A bare function-like macro is a private Go token, not an
			// identifier. Relexing its spelling would accept invalid opcodes
			// and operands which the original assembler rejects.
			return "", input.errorf("function-like macro %q requires arguments", token.text)
		}
		if token.kind == ppGoBuildComment {
			// Before the parser observes its first non-control token, Go's
			// diagnostic line is still zero and its errorf suppresses that
			// first-line CPP/build-comment diagnostic. Preserve this observed
			// acceptance instead of rejecting every comment after a control.
			if input.sawCode && parserPositionInitialized {
				return "", input.errorf("misplaced //go:build comment")
			}
			continue
		}
		parserPositionInitialized = true
		if observer != nil && observer.positions != nil {
			if err := observer.emitSDKPosition(token, input.readers[len(input.readers)-1].positionBase); err != nil {
				return "", err
			}
		}
		if token.kind != '\n' {
			input.sawCode = true
		}
		if token.kind == '\n' {
			start := output.Len()
			if statementTokens != 0 {
				output.WriteByte('\n')
			}
			if observer != nil {
				if err := observer.emitOutput(token, start, output.Len()); err != nil {
					return "", err
				}
			}
			previous, statementTokens = ppGoToken{}, 0
			continue
		}
		if statementTokens != 0 && (ppGoTokenNeedsSpace(previous, token) ||
			statementTokens == 1 && previous.kind == scanner.Ident && token.kind != ':') {
			output.WriteByte(' ')
		}
		start := output.Len()
		output.WriteString(token.text)
		if observer != nil {
			if err := observer.emitOutput(token, start, output.Len()); err != nil {
				return "", err
			}
		}
		previous = token
		statementTokens++
		if token.kind == ';' || token.kind == ':' {
			statementTokens = 0
		}
	}
	return output.String(), nil
}

func ppGoTokenNeedsSpace(left, right ppGoToken) bool {
	word := func(kind rune) bool {
		return kind == scanner.Ident || kind == scanner.Int || kind == scanner.Float
	}
	if word(left.kind) && word(right.kind) {
		return true
	}
	if left.text == "/" && (right.text == "*" || right.text == "/") {
		return true
	}
	// Removing whitespace must not turn separate source tokens into one
	// shift, rotate, arrow or numeric token on the second lexical pass.
	if (left.text == "<" && right.text == "<") || (left.text == ">" && right.text == ">") ||
		(left.text == "-" || left.text == "@") && right.text == ">" {
		return true
	}
	return (left.kind == scanner.Int || left.kind == scanner.Float) && right.text == "." ||
		left.text == "." && (right.kind == scanner.Int || right.kind == scanner.Float)
}
