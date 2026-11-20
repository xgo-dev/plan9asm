package plan9asm

import (
	"fmt"
	"text/scanner"
)

// AssemblyCPPToken describes a physical token, not an expanded or accepted
// assembly instruction. RecordedValue uses the strict preprocessor's recording
// projection; it is not an independently selected SDK encoder certificate.
type AssemblyCPPToken struct {
	Kind          string
	Text          string
	RecordedValue string
	Start         int
	End           int
	Line          int
	Column        int
	EndColumn     int
}

// AssemblyCPPMacroDefinition retains lexical definition identity. Parameters
// is nil for an object macro and non-nil for a function macro, including F().
type AssemblyCPPMacroDefinition struct {
	Name        string
	Function    bool
	Parameters  []string
	Replacement []AssemblyCPPToken
}

// AssemblyCPPSourceRecord is an original physical span. It does not say that
// a directive or candidate invocation is active, defined or syntactically valid
// as a translation unit. Text retains comments, adjacency and continuations.
type AssemblyCPPSourceRecord struct {
	Kind       string
	Start      int
	End        int
	Line       int
	EndLine    int
	Text       string
	Tokens     []AssemblyCPPToken
	Definition *AssemblyCPPMacroDefinition
}

type AssemblyCPPSourceInventory struct {
	File         string
	ByteLength   int
	FinalNewline bool
	EOF          AssemblyCPPToken
	Records      []AssemblyCPPSourceRecord
}

// InspectAssemblyCPPSource is query-only. It neither executes CPP nor grants
// source, include, frame, ABI or instruction permission. Names select potential
// physical invocations, including occurrences before a later definition.
func InspectAssemblyCPPSource(source, file string, invocationNames []string) (AssemblyCPPSourceInventory, error) {
	result := AssemblyCPPSourceInventory{
		File: file, ByteLength: len(source), FinalNewline: len(source) != 0 && source[len(source)-1] == '\n',
		Records: []AssemblyCPPSourceRecord{},
	}
	if file == "" || len(source) > 64<<20 || len(invocationNames) > 4096 {
		return result, fmt.Errorf("physical CPP query requires bounded named source and invocation names")
	}
	names := make(map[string]bool, len(invocationNames))
	for _, name := range invocationNames {
		if !validPPIdentifier(name) || names[name] {
			return result, fmt.Errorf("physical CPP query has an invalid or duplicate invocation name")
		}
		names[name] = true
	}

	reader := newPPGoReader(file, source)
	readLine := func() ([]AssemblyCPPToken, error) {
		var tokens []AssemblyCPPToken
		for {
			physical, err := reader.next()
			if err != nil {
				return nil, err
			}
			if len(tokens) >= 1<<20 {
				return nil, fmt.Errorf("physical CPP statement exceeds its token bound")
			}
			token := assemblyCPPPhysicalToken(reader, physical)
			tokens = append(tokens, token)
			if token.Kind == "newline" || token.Kind == "eof" {
				return tokens, nil
			}
		}
	}
	retainedTokens := 0
	for {
		tokens, err := readLine()
		if err != nil {
			return result, err
		}
		directive := len(tokens) > 1 && tokens[0].Text == "#"
		definition := directive && tokens[1].Kind == "identifier" && tokens[1].Text == "define"
		for definition && assemblyCPPContinuedLine(tokens) {
			continued, err := readLine()
			if err != nil {
				return result, err
			}
			if len(continued) > 1<<20-len(tokens) {
				return result, fmt.Errorf("physical CPP definition exceeds its token bound")
			}
			tokens = append(tokens, continued...)
		}
		last := tokens[len(tokens)-1]
		if last.Kind == "eof" {
			result.EOF = last
		}
		kind := ""
		if directive {
			kind = "directive"
		} else {
			for _, token := range tokens {
				if token.Kind == "build_comment" || token.Text == "#" {
					kind = "lexical_control"
					break
				}
				if token.Kind == "identifier" && names[token.Text] {
					kind = "candidate"
				}
			}
		}
		if kind != "" {
			if len(result.Records) >= 4096 || retainedTokens+len(tokens) > 1<<20 {
				return result, fmt.Errorf("physical CPP inventory exceeds its record/token bound")
			}
			first := tokens[0]
			record := AssemblyCPPSourceRecord{
				Kind: kind, Start: first.Start, End: last.End, Line: first.Line,
				EndLine: last.Line, Text: source[first.Start:last.End], Tokens: tokens,
			}
			if definition {
				record.Definition, err = assemblyCPPPhysicalDefinition(tokens)
				if err != nil {
					return result, fmt.Errorf("%s:%d: %w", file, first.Line, err)
				}
			}
			result.Records = append(result.Records, record)
			retainedTokens += len(tokens)
		}
		if last.Kind == "eof" {
			return result, nil
		}
	}
}

func assemblyCPPPhysicalToken(reader *ppGoReader, physical ppGoToken) AssemblyCPPToken {
	kind := string(physical.kind)
	switch physical.kind {
	case scanner.EOF:
		kind = "eof"
	case scanner.Ident:
		kind = "identifier"
	case scanner.Int:
		kind = "integer"
	case scanner.Float:
		kind = "float"
	case scanner.Char:
		kind = "character"
	case scanner.String:
		kind = "string"
	case scanner.RawString:
		kind = "raw_string"
	case ppGoBuildComment:
		kind = "build_comment"
	case '\n':
		kind = "newline"
	}
	return AssemblyCPPToken{
		Kind: kind, Text: physical.text, RecordedValue: ppGoRecordedToken(physical).value,
		Start: reader.scanner.Position.Offset, End: reader.scanner.Pos().Offset,
		Line: physical.line, Column: reader.scanner.Position.Column, EndColumn: physical.endCol,
	}
}

func assemblyCPPContinuedLine(tokens []AssemblyCPPToken) bool {
	if tokens[len(tokens)-1].Kind != "newline" {
		return false
	}
	backslashes := 0
	for index := len(tokens) - 2; index >= 0 && tokens[index].Kind == "\\"; index-- {
		backslashes++
	}
	return backslashes%2 != 0
}

// This reads definition shape only. Replacement escapes and token execution
// belong to ppGoInput.define; the original complete token span is kept here.
func assemblyCPPPhysicalDefinition(tokens []AssemblyCPPToken) (*AssemblyCPPMacroDefinition, error) {
	if len(tokens) < 4 || tokens[2].Kind != "identifier" {
		return nil, fmt.Errorf("physical define has no literal macro name")
	}
	macro := &AssemblyCPPMacroDefinition{Name: tokens[2].Text}
	index := 3
	if tokens[index].Kind == "(" && tokens[index].Column == tokens[2].EndColumn {
		macro.Function = true
		macro.Parameters = []string{}
		index++
		expectName := true
		for index < len(tokens) && tokens[index].Kind != ")" {
			token := tokens[index]
			if expectName && token.Kind == "identifier" {
				if containsPPGoParameter(macro.Parameters, token.Text) {
					return nil, fmt.Errorf("physical define repeats a formal parameter")
				}
				macro.Parameters = append(macro.Parameters, token.Text)
				expectName = false
			} else if !expectName && token.Kind == "," {
				expectName = true
			} else {
				return nil, fmt.Errorf("physical define has an unregistered formal shape")
			}
			index++
		}
		if index == len(tokens) || tokens[index].Kind != ")" {
			return nil, fmt.Errorf("physical define has an incomplete formal list")
		}
		index++
	}
	end := len(tokens) - 1 // The terminating physical newline/EOF is separate.
	macro.Replacement = append([]AssemblyCPPToken(nil), tokens[index:end]...)
	return macro, nil
}
