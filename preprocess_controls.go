package plan9asm

import (
	"fmt"
	"strconv"
	"text/scanner"
)

// The Go assembly frontend has exactly these eight controls. Generated and
// physical controls use the same dispatcher and the same live macro state.
func (input *ppGoInput) control(origin ppGoToken) (bool, error) {
	index, err := input.beginObservation("control", origin)
	if err != nil {
		return false, err
	}
	defer input.finishObservation(index)
	return input.executeControl(origin)
}

func (input *ppGoInput) executeControl(origin ppGoToken) (bool, error) {
	token, err := input.raw()
	if err != nil {
		return false, err
	}
	if token.kind != scanner.Ident {
		return false, input.errorf("invalid preprocessor directive after '#'")
	}
	directive := token.value
	if event := input.observedEvent(); event != nil {
		event.Directive = directive
	}
	if !input.enabled() && directive != "else" && directive != "endif" &&
		directive != "ifdef" && directive != "ifndef" && directive != "line" {
		// Go skips only the control's name here. Macro tokens in the remaining
		// disabled input still go through Next, including nested controls.
		return false, nil
	}
	if event := input.observedEvent(); event != nil {
		event.Executed = true
	}
	switch directive {
	case "define":
		return true, input.define()
	case "undef":
		name, err := input.name()
		if err != nil {
			return false, err
		}
		if _, found := input.macros[name]; !found {
			return false, input.errorf("#undef for undefined macro: %s", name)
		}
		if err := input.newline(directive); err != nil {
			return false, err
		}
		delete(input.macros, name)
	case "ifdef", "ifndef":
		name, err := input.name()
		if err != nil {
			return false, err
		}
		if err := input.newline(directive); err != nil {
			return false, err
		}
		if len(input.conditions) >= 32 {
			return false, input.errorf("CPP conditional nesting exceeds the explicit 32-level bound")
		}
		_, present := input.macros[name]
		branch := present == (directive == "ifdef")
		input.conditions = append(input.conditions, input.enabled() && branch)
	case "else":
		if err := input.newline(directive); err != nil {
			return false, err
		}
		last := len(input.conditions) - 1
		if last < 0 {
			return false, input.errorf("unmatched #else")
		}
		if last == 0 || input.conditions[last-1] {
			input.conditions[last] = !input.conditions[last]
		}
	case "endif":
		if err := input.newline(directive); err != nil {
			return false, err
		}
		if len(input.conditions) == 0 {
			return false, input.errorf("unmatched #endif")
		}
		input.conditions = input.conditions[:len(input.conditions)-1]
	case "include":
		return true, input.include(origin)
	case "line":
		if err := input.line(); err != nil {
			return false, err
		}
	default:
		return false, input.errorf("unsupported Go assembly directive #%s", directive)
	}
	return true, nil
}

func (input *ppGoInput) define() error {
	name, err := input.name()
	if err != nil {
		return err
	}
	previousColumn := input.last.endCol
	token, err := input.raw()
	if err != nil {
		return err
	}
	macro := ppGoMacro{}
	if token.kind != '\n' && token.kind != scanner.EOF {
		if token.kind == '(' && token.endCol == previousColumn+1 {
			macro.parameters = []string{}
			parameterExpected := true
			for {
				token, err = input.raw()
				if err != nil {
					return err
				}
				if token.kind == ')' {
					token, err = input.raw()
					if err != nil {
						return err
					}
					break
				}
				switch token.kind {
				case ',':
					if parameterExpected {
						return input.errorf("bad syntax in macro definition: %s", name)
					}
					parameterExpected = true
				case scanner.Ident:
					if !parameterExpected || containsPPGoParameter(macro.parameters, token.value) {
						return input.errorf("bad or duplicate argument in macro definition: %s", name)
					}
					macro.parameters = append(macro.parameters, token.value)
					parameterExpected = false
				default:
					return input.errorf("bad definition for macro: %s", name)
				}
			}
		}
		for token.kind != '\n' {
			if token.kind == scanner.EOF {
				return input.errorf("missing newline in definition for macro: %s", name)
			}
			if token.kind == '\\' {
				token, err = input.raw()
				if err != nil {
					return err
				}
				if token.kind != '\n' && token.kind != '\\' {
					return input.errorf("macro replacement can only escape a backslash or newline: %s", name)
				}
			}
			macro.body = append(macro.body, ppGoRecordedToken(token))
			token, err = input.raw()
			if err != nil {
				return err
			}
		}
	}
	if _, exists := input.macros[name]; exists {
		return input.errorf("redefinition of macro: %s", name)
	}
	if event := input.observedEvent(); event != nil {
		event.Function = macro.parameters != nil
		event.Parameters = ppGoCopyParameters(macro.parameters)
		macro.definition = event.Ordinal
	}
	input.macros[name] = macro
	return nil
}

func containsPPGoParameter(parameters []string, name string) bool {
	for _, parameter := range parameters {
		if parameter == name {
			return true
		}
	}
	return false
}

func (input *ppGoInput) include(origin ppGoToken) error {
	token, err := input.raw()
	if err != nil {
		return err
	}
	if token.kind != scanner.String {
		return input.errorf("invalid #include: expected literal string")
	}
	name, err := strconv.Unquote(token.value)
	if err != nil {
		return input.errorf("invalid #include: %v", err)
	}
	if err := input.newline("include"); err != nil {
		return err
	}
	if input.options.ReadInclude == nil {
		return input.errorf("active #include %q requires a resolver", name)
	}
	if input.includes >= 32 {
		return input.errorf("include cycle/depth exceeds the explicit 32-level bound")
	}
	file, source, err := input.options.ReadInclude(origin.file, name)
	if err != nil {
		return fmt.Errorf("%s:%d: #include %q: %w", origin.file, origin.line, name, err)
	}
	if file == "" {
		return input.errorf("active #include %q has no source identity", name)
	}
	// Hash and tokenize the same immutable snapshot of the resolver's bytes.
	sourceText := string(source)
	if input.observer != nil {
		if err := input.observer.source(file, sourceText); err != nil {
			return err
		}
	}
	reader := newPPGoReader(file, sourceText)
	if input.observer != nil && input.observer.positions != nil {
		reader.positionBase = newSDKCPPFileBase(name)
		reader.positionLine = 1
	}
	reader.include = true
	if event := input.observedEvent(); event != nil {
		event.Included = file
		reader.includeEvent = event.Ordinal
	}
	if err := input.push(reader); err != nil {
		return err
	}
	input.includes++
	return nil
}

func (input *ppGoInput) line() error {
	number, err := input.raw()
	if err != nil {
		return err
	}
	if number.kind != scanner.Int {
		return input.errorf("invalid #line number")
	}
	if _, err := strconv.Atoi(number.value); err != nil {
		return input.errorf("invalid #line number: %v", err)
	}
	file, err := input.raw()
	if err != nil {
		return err
	}
	if file.kind != scanner.String {
		return input.errorf("invalid #line filename")
	}
	if _, err := strconv.Unquote(file.value); err != nil {
		return input.errorf("invalid #line filename: %v", err)
	}
	// The API emits normalized machine source, not diagnostic line metadata.
	// Keep physical origins for includes instead of trusting logical filenames.
	if err := input.newline("line"); err != nil {
		return err
	}
	if input.observer != nil && input.observer.positions != nil {
		reader := input.readers[len(input.readers)-1]
		logical, _ := strconv.Unquote(file.value)
		line, _ := strconv.Atoi(number.value)
		reader.positionBase = &sdkCPPPositionBase{
			File: logical, Anchor: sdkCPPClampLine(reader.positionLine + 1), Line: uint(line),
		}
	}
	return nil
}
