package plan9asm

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/scanner"
	"unicode"
)

type ppMacro struct {
	body   string
	params []string
}

// Recognize comments in lexical order: // hides any later /*, and quoted
// constants hide both. A block comment is whitespace, not token concatenation.
func stripAssemblyComments(line string, inBlock *bool) string {
	if !*inBlock && !strings.Contains(line, "/") {
		return line
	}
	var out strings.Builder
	var quote byte
	for i := 0; i < len(line); {
		if *inBlock {
			end := strings.Index(line[i:], "*/")
			if end < 0 {
				break
			}
			i += end + 2
			*inBlock = false
			continue
		}
		ch := line[i]
		if quote != 0 {
			out.WriteByte(ch)
			i++
			if ch == '\\' && quote != '`' && i < len(line) {
				out.WriteByte(line[i])
				i++
			} else if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '/' && i+1 < len(line) {
			if line[i+1] == '/' {
				break
			}
			if line[i+1] == '*' {
				out.WriteByte(' ')
				*inBlock = true
				i += 2
				continue
			}
		}
		if ch == '"' || ch == '\'' || ch == '`' {
			quote = ch
		}
		out.WriteByte(ch)
		i++
	}
	return out.String()
}

// preprocess applies a very small preprocessor needed for some stdlib asm:
//   - strips // comments
//   - ignores #include
//   - supports #define NAME <body> with optional single-line continuation via '\'
//   - expands macros only when a statement is exactly NAME
func preprocess(src string) (string, error) {
	return preprocessWithDefines(src, nil)
}

// GoAssemblerDefines returns the predefined symbols cmd/go passes to cmd/asm.
// The feature values come from the same GO* environment variables used to
// select files and configure the assembler invocation.
func GoAssemblerDefines(goos, goarch string) []string {
	return GoAssemblerDefinesWithEnv(goos, goarch, nil)
}

// GoAssemblerDefinesWithEnv uses explicit target feature values when env is
// non-nil. This lets a compiler pass its resolved configuration without
// mutating the process environment; omitted entries use Go's baseline defaults.
func GoAssemblerDefinesWithEnv(goos, goarch string, env map[string]string) []string {
	getenv := os.Getenv
	if env != nil {
		getenv = func(name string) string { return env[name] }
	}
	defines := []string{}
	if goos != "" {
		defines = append(defines, "GOOS_"+goos)
	}
	if goarch != "" {
		defines = append(defines, "GOARCH_"+goarch)
	}
	switch goarch {
	case "386":
		value := getenv("GO386")
		if value == "" {
			value = "sse2"
		}
		defines = append(defines, "GO386_"+value)
	case "amd64":
		value := getenv("GOAMD64")
		if value == "" {
			value = "v1"
		}
		defines = append(defines, "GOAMD64_"+value)
	case "arm":
		value := getenv("GOARM")
		if value == "" {
			value = "7"
		}
		if strings.Contains(value, "7") {
			defines = append(defines, "GOARM_7")
		}
		if strings.Contains(value, "6") || strings.Contains(value, "7") {
			defines = append(defines, "GOARM_6")
		}
		defines = append(defines, "GOARM_5")
	case "arm64":
		if lse, err := goARM64ProfileLSE(getenv("GOARM64")); err == nil && lse {
			defines = append(defines, "GOARM64_LSE")
		}
	}
	return defines
}

// AssemblyPreprocessOptions supplies the real source inputs for preprocessing.
// ReadInclude resolves an active quoted include using the caller's bounded
// package/toolchain search. It returns a stable source identity and its bytes;
// identities are used to diagnose include recursion. An inactive include never
// calls the resolver, including when its operand is malformed or missing.
// The API bounds include depth (32); the caller must bound individual/aggregate
// input bytes and emitted output for its own source inventory/resource budget.
type AssemblyPreprocessOptions struct {
	FileName    string
	Defines     []string
	ReadInclude func(parent, name string) (fileName string, source []byte, err error)
}

// PreprocessAssemblySource expands Go assembly macros and active includes with
// one source-order macro/conditional environment. Unlike the historical Parse
// path, an unresolved active include is an error, never silently discarded.
func PreprocessAssemblySource(src string, opt AssemblyPreprocessOptions) (string, error) {
	return preprocessGoAssembly(src, opt)
}

func preprocessWithDefines(src string, defines []string) (string, error) {
	return preprocessAssembly(src, defines, nil)
}

func preprocessAssembly(src string, defines []string, opt *AssemblyPreprocessOptions) (string, error) {
	macros := map[string]ppMacro{}
	for _, name := range defines {
		name = strings.TrimSpace(name)
		if name != "" {
			macros[name] = ppMacro{body: "1"}
		}
	}
	macroNames := []string{}
	refreshMacroNames := func() {
		macroNames = macroNames[:0]
		for name := range macros {
			macroNames = append(macroNames, name)
		}
		// Try longer names first to avoid prefix shadowing.
		sort.Slice(macroNames, func(i, j int) bool {
			return len(macroNames[i]) > len(macroNames[j])
		})
	}
	refreshMacroNames()

	type ifState struct {
		outerActive bool
		cond        bool
		inElse      bool
	}
	isDefined := func(name string) bool {
		_, ok := macros[name]
		return ok
	}
	evalIfExpr := func(expr string) bool {
		e := strings.TrimSpace(expr)
		if e == "" {
			return false
		}
		neg := false
		for strings.HasPrefix(e, "!") {
			neg = !neg
			e = strings.TrimSpace(strings.TrimPrefix(e, "!"))
		}
		val := false
		switch {
		case strings.HasPrefix(e, "defined(") && strings.HasSuffix(e, ")"):
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(e, "defined("), ")"))
			val = isDefined(name)
		case strings.HasPrefix(e, "defined ") || strings.HasPrefix(e, "defined\t"):
			name := strings.TrimSpace(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(e, "defined "), "defined\t")))
			val = isDefined(name)
		default:
			// Bare identifier in #if.
			val = isDefined(e)
		}
		if neg {
			return !val
		}
		return val
	}

	// Expand each instruction while its source-order macro environment is live.
	// Delaying expansion until EOF would apply later #undef/#define changes to
	// earlier functions, changing both Go's accepted forms and their semantics.
	lines := []string{}
	// Conditional directives emitted by a macro must also use the definitions
	// in force at its invocation, not the final map after the whole source.
	expandedConditions := map[int]bool{}
	appendExpanded := func(line string) {
		for _, expanded := range expandPPLine(line, macros, macroNames, 0) {
			trim := strings.TrimSpace(expanded)
			switch {
			case strings.HasPrefix(trim, "#ifdef"):
				name := strings.TrimSpace(strings.TrimPrefix(trim, "#ifdef"))
				expandedConditions[len(lines)] = isDefined(name)
			case strings.HasPrefix(trim, "#ifndef"):
				name := strings.TrimSpace(strings.TrimPrefix(trim, "#ifndef"))
				expandedConditions[len(lines)] = !isDefined(name)
			case strings.HasPrefix(trim, "#if"):
				expr := strings.TrimSpace(strings.TrimPrefix(trim, "#if"))
				expandedConditions[len(lines)] = evalIfExpr(expr)
			case strings.HasPrefix(trim, "#elif"):
				expr := strings.TrimSpace(strings.TrimPrefix(trim, "#elif"))
				expandedConditions[len(lines)] = evalIfExpr(expr)
			}
			lines = append(lines, expanded)
		}
	}

	newScanner := func(source string) *bufio.Scanner {
		sc := bufio.NewScanner(strings.NewReader(source))
		// An in-memory source bounds a physical line, unlike Scanner's 64 KiB
		// default (Go assembly has no such line-length cap).
		sc.Buffer(nil, len(source)+1)
		if opt != nil {
			// Keep real newline tokens. ScanLines would silently turn a final
			// unterminated directive into a terminated one.
			sc.Split(func(data []byte, atEOF bool) (int, []byte, error) {
				if end := bytes.IndexByte(data, '\n'); end >= 0 {
					return end + 1, data[:end+1], nil
				}
				if atEOF && len(data) > 0 {
					return len(data), data, nil
				}
				return 0, nil, nil
			})
		}
		return sc
	}
	sc := newScanner(src)
	fileName := "<assembly>"
	if opt != nil && opt.FileName != "" {
		fileName = opt.FileName
	}
	type inputState struct {
		scanner *bufio.Scanner
		file    string
		line    int
	}
	inputs := []inputState{}
	activeFiles := map[string]bool{fileName: true}
	inBlockComment := false
	var defName string
	var defParams []string
	var defBody strings.Builder
	defCont := false
	active := true
	ifStack := []ifState{}
	flushDefine := func() error {
		if !defCont {
			return nil
		}
		name := strings.TrimSpace(defName)
		body := strings.TrimSpace(defBody.String())
		if name == "" {
			return fmt.Errorf("invalid #define with empty name")
		}
		if opt != nil {
			if _, exists := macros[name]; exists {
				return fmt.Errorf("redefinition of macro %s", name)
			}
			var err error
			body, err = normalizePPMacroEscapes(body)
			if err != nil {
				return err
			}
		}
		macros[name] = ppMacro{body: body, params: defParams}
		refreshMacroNames()
		defName = ""
		defParams = nil
		defBody.Reset()
		defCont = false
		return nil
	}

	lineno := 0
	for {
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				return "", fmt.Errorf("%s: %w", fileName, err)
			}
			if opt != nil && (defCont || inBlockComment) {
				return "", fmt.Errorf("%s:%d: unterminated macro continuation or comment", fileName, lineno)
			}
			if len(inputs) == 0 {
				break
			}
			delete(activeFiles, fileName)
			parent := inputs[len(inputs)-1]
			inputs = inputs[:len(inputs)-1]
			sc, fileName, lineno = parent.scanner, parent.file, parent.line
			continue
		}
		lineno++
		statementFile, statementLine := fileName, lineno
		rawLine := sc.Text()
		terminated := opt == nil || strings.HasSuffix(rawLine, "\n")
		rawLine = strings.TrimSuffix(rawLine, "\n")
		// C-style preprocessing splices a physical backslash-newline before
		// removing comments. Record it before the comment pass below can erase
		// the slash from a continued multi-line #define.
		physicalContinuation := strings.HasSuffix(strings.TrimRight(rawLine, " \t\r"), "\\")
		line := stripAssemblyComments(rawLine, &inBlockComment)
		line = strings.TrimRight(line, " \t")
		if opt != nil && !terminated && (strings.HasPrefix(strings.TrimSpace(line), "#") || defCont) {
			// Go's lex.Stack discards an exhausted included tokenizer, not a
			// newline. Read the parent tokens until a real newline is found.
			// Tokenizers stay separate: comments cannot cross file boundaries
			// and identifiers cannot concatenate across those boundaries.
			for !terminated && len(inputs) > 0 {
				if inBlockComment {
					return "", fmt.Errorf("%s:%d: unterminated comment", fileName, lineno)
				}
				delete(activeFiles, fileName)
				parent := inputs[len(inputs)-1]
				inputs = inputs[:len(inputs)-1]
				sc, fileName, lineno = parent.scanner, parent.file, parent.line
				if !sc.Scan() {
					if err := sc.Err(); err != nil {
						return "", fmt.Errorf("%s: %w", fileName, err)
					}
					continue
				}
				lineno++
				next := sc.Text()
				terminated = strings.HasSuffix(next, "\n")
				next = strings.TrimSuffix(next, "\n")
				line += " " + stripAssemblyComments(next, &inBlockComment)
			}
		}
		// cmd/asm also accepts historical assembly that places a // comment
		// after the continuation slash. In that spelling the slash only becomes
		// the last token after comment removal (for example "MOVQ ... \\ // why").
		physicalContinuation = physicalContinuation || strings.HasSuffix(line, "\\")
		if opt != nil {
			// At file EOF a following parent token can complete a backslash
			// pair rather than an escaped newline. Decide from the merged
			// token line, not the exhausted header's last byte alone.
			physicalContinuation = hasPPContinuation(line)
		}
		// A newline within a block comment is not the end of a macro body.
		// cmd/asm removes the entire comment before parsing #define lines, so
		// only the newline after the closing */ can terminate the definition.
		if defCont && inBlockComment {
			physicalContinuation = true
		}
		if defCont {
			// Continue a definition body on the following line(s).
			if !active {
				// Discard bodies from inactive blocks.
				if physicalContinuation {
					continue
				}
				if err := flushDefine(); err != nil {
					return "", fmt.Errorf("line %d: %v", lineno, err)
				}
				continue
			}
			cont := strings.TrimSpace(line)
			if physicalContinuation {
				// Comment removal may already have removed the slash.
				cont = strings.TrimSpace(strings.TrimSuffix(cont, "\\"))
				defBody.WriteString("\n")
				defBody.WriteString(cont)
				continue
			}
			defBody.WriteString("\n")
			defBody.WriteString(cont)
			if err := flushDefine(); err != nil {
				return "", fmt.Errorf("line %d: %v", lineno, err)
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}

		trim := strings.TrimSpace(line)
		if opt != nil && strings.HasPrefix(trim, "#") {
			// Tabs are token whitespace as well; do not recognize a directive
			// by a substring prefix (#includeExtra is not #include).
			fields := strings.Fields(strings.TrimSpace(trim[1:]))
			if len(fields) == 0 {
				return "", fmt.Errorf("%s:%d: invalid preprocessor directive", fileName, lineno)
			}
			directive := fields[0]
			rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(trim[1:]), directive))
			if !active && directive != "ifdef" && directive != "ifndef" && directive != "else" && directive != "endif" && directive != "line" {
				continue
			}
			if !terminated {
				// cmd/asm alone permits EOF directly after an object-like macro
				// name. Function-like definitions and nonempty bodies require
				// an actual newline, as do all other active controls.
				_, params, body, err := parseMacroDefine(rest)
				if directive != "define" || err != nil || params != nil || body != "" {
					return "", fmt.Errorf("%s:%d: #%s requires a terminating newline", statementFile, statementLine, directive)
				}
			}
			switch directive {
			case "include", "define", "undef":
			case "ifdef", "ifndef":
				if !validPPIdentifier(rest) {
					return "", fmt.Errorf("%s:%d: invalid #%s", fileName, lineno, directive)
				}
			case "else", "endif":
				if rest != "" {
					return "", fmt.Errorf("%s:%d: unexpected tokens after #%s", fileName, lineno, directive)
				}
			case "line":
				if err := validatePPLine(rest); err != nil {
					return "", fmt.Errorf("%s:%d: %w", fileName, lineno, err)
				}
				continue // source-position metadata, not a machine instruction
			default:
				return "", fmt.Errorf("%s:%d: unsupported Go assembly directive #%s", fileName, lineno, directive)
			}
			trim = "#" + directive
			if rest != "" {
				trim += " " + rest
			}
		}
		if strings.HasPrefix(trim, "#include") {
			if opt == nil {
				// Preserve the historical parser behavior. Actual source readers
				// opt into the strict API rather than inventing missing headers.
				continue
			}
			if !active {
				continue
			}
			rest := strings.TrimSpace(strings.TrimPrefix(trim, "#include"))
			name, err := strconv.Unquote(rest)
			if err != nil || !strings.HasPrefix(rest, "\"") {
				return "", fmt.Errorf("%s:%d: invalid #include: %q", fileName, lineno, line)
			}
			if opt.ReadInclude == nil {
				return "", fmt.Errorf("%s:%d: active #include %q requires a resolver", fileName, lineno, name)
			}
			includedName, includedSource, err := opt.ReadInclude(statementFile, name)
			if err != nil {
				return "", fmt.Errorf("%s:%d: #include %q: %w", fileName, lineno, name, err)
			}
			if includedName == "" {
				return "", fmt.Errorf("%s:%d: #include %q has no source identity", fileName, lineno, name)
			}
			if activeFiles[includedName] || len(inputs) >= 32 {
				return "", fmt.Errorf("%s:%d: include cycle/depth at %s", fileName, lineno, includedName)
			}
			inputs = append(inputs, inputState{sc, fileName, lineno})
			sc, fileName, lineno = newScanner(string(includedSource)), includedName, 0
			activeFiles[fileName] = true
			continue
		}
		if strings.HasPrefix(trim, "#undef") {
			if active {
				name := strings.TrimSpace(strings.TrimPrefix(trim, "#undef"))
				if name == "" || strings.ContainsAny(name, " \t") {
					return "", fmt.Errorf("line %d: invalid #undef: %q", lineno, line)
				}
				if opt != nil {
					if _, exists := macros[name]; !exists || !validPPIdentifier(name) {
						return "", fmt.Errorf("%s:%d: #undef for undefined macro %s", fileName, lineno, name)
					}
				}
				delete(macros, name)
				refreshMacroNames()
			}
			continue
		}
		if strings.HasPrefix(trim, "#ifdef") {
			name := strings.TrimSpace(strings.TrimPrefix(trim, "#ifdef"))
			if name == "" {
				return "", fmt.Errorf("line %d: invalid #ifdef: %q", lineno, line)
			}
			st := ifState{outerActive: active, cond: isDefined(name)}
			ifStack = append(ifStack, st)
			active = active && st.cond
			continue
		}
		if strings.HasPrefix(trim, "#ifndef") {
			name := strings.TrimSpace(strings.TrimPrefix(trim, "#ifndef"))
			if name == "" {
				return "", fmt.Errorf("line %d: invalid #ifndef: %q", lineno, line)
			}
			st := ifState{outerActive: active, cond: !isDefined(name)}
			ifStack = append(ifStack, st)
			active = active && st.cond
			continue
		}
		if strings.HasPrefix(trim, "#if") {
			expr := strings.TrimSpace(strings.TrimPrefix(trim, "#if"))
			st := ifState{outerActive: active, cond: evalIfExpr(expr)}
			ifStack = append(ifStack, st)
			active = active && st.cond
			continue
		}
		if strings.HasPrefix(trim, "#elif") {
			if len(ifStack) == 0 {
				return "", fmt.Errorf("line %d: stray #elif", lineno)
			}
			top := ifStack[len(ifStack)-1]
			if top.inElse {
				return "", fmt.Errorf("line %d: #elif after #else", lineno)
			}
			// Only first satisfied branch stays active.
			if top.cond {
				active = false
				continue
			}
			expr := strings.TrimSpace(strings.TrimPrefix(trim, "#elif"))
			top.cond = evalIfExpr(expr)
			ifStack[len(ifStack)-1] = top
			active = top.outerActive && top.cond
			continue
		}
		if strings.HasPrefix(trim, "#else") {
			if len(ifStack) == 0 {
				return "", fmt.Errorf("line %d: stray #else", lineno)
			}
			top := ifStack[len(ifStack)-1]
			if top.inElse {
				return "", fmt.Errorf("line %d: duplicate #else", lineno)
			}
			top.inElse = true
			ifStack[len(ifStack)-1] = top
			active = top.outerActive && !top.cond
			continue
		}
		if strings.HasPrefix(trim, "#endif") {
			if len(ifStack) == 0 {
				return "", fmt.Errorf("line %d: stray #endif", lineno)
			}
			top := ifStack[len(ifStack)-1]
			ifStack = ifStack[:len(ifStack)-1]
			active = top.outerActive
			continue
		}
		if strings.HasPrefix(trim, "#define") {
			if !active {
				continue
			}
			rest := strings.TrimSpace(strings.TrimPrefix(trim, "#define"))
			name, params, afterName, err := parseMacroDefine(rest)
			if err != nil {
				return "", fmt.Errorf("line %d: invalid #define: %q", lineno, line)
			}
			defName = name
			defParams = params
			if physicalContinuation {
				afterName = strings.TrimSpace(strings.TrimSuffix(afterName, "\\"))
				defBody.WriteString(afterName)
				defCont = true
				continue
			}
			defBody.WriteString(afterName)
			defCont = true
			if err := flushDefine(); err != nil {
				return "", fmt.Errorf("line %d: %v", lineno, err)
			}
			continue
		}

		if !active {
			continue
		}
		appendExpanded(strings.TrimSpace(line))
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if defCont {
		if err := flushDefine(); err != nil {
			return "", err
		}
	}
	if len(ifStack) != 0 {
		return "", fmt.Errorf("unterminated #if block")
	}

	// Some Go assembly deliberately places conditionals inside a continued
	// macro body (runtime's ARM64 BREAK macro is the canonical example). Those
	// directives become visible only after macro expansion, so evaluate a
	// second conditional pass instead of leaking them into the instruction
	// stream.
	active = true
	ifStack = nil
	expandedOpen := []string{}
	var out strings.Builder
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if opt != nil && strings.HasPrefix(trim, "#") {
			fields := strings.Fields(strings.TrimPrefix(trim, "#"))
			if len(fields) == 0 {
				return "", fmt.Errorf("invalid macro-expanded preprocessor directive: %s", trim)
			}
			conditional := fields[0] == "ifdef" || fields[0] == "ifndef" || fields[0] == "else" || fields[0] == "endif"
			if !active && !conditional {
				continue // cmd/asm does not parse inactive include/define operands
			}
			if !conditional {
				return "", fmt.Errorf("unsupported macro-expanded preprocessor directive: %s", trim)
			}
			if fields[0] == "ifdef" || fields[0] == "ifndef" {
				if len(fields) != 2 || !validPPIdentifier(fields[1]) {
					return "", fmt.Errorf("invalid macro-expanded #%s: %s", fields[0], trim)
				}
			} else if len(fields) != 1 {
				return "", fmt.Errorf("unexpected tokens in macro-expanded #%s: %s", fields[0], trim)
			}
		}
		switch {
		case strings.HasPrefix(trim, "#ifdef"):
			name := strings.TrimSpace(strings.TrimPrefix(trim, "#ifdef"))
			if name == "" {
				return "", fmt.Errorf("expanded line %d: invalid #ifdef: %q", i+1, line)
			}
			st := ifState{outerActive: active, cond: expandedConditions[i]}
			ifStack = append(ifStack, st)
			expandedOpen = append(expandedOpen, trim)
			active = active && st.cond
			continue
		case strings.HasPrefix(trim, "#ifndef"):
			name := strings.TrimSpace(strings.TrimPrefix(trim, "#ifndef"))
			if name == "" {
				return "", fmt.Errorf("expanded line %d: invalid #ifndef: %q", i+1, line)
			}
			st := ifState{outerActive: active, cond: expandedConditions[i]}
			ifStack = append(ifStack, st)
			expandedOpen = append(expandedOpen, trim)
			active = active && st.cond
			continue
		case strings.HasPrefix(trim, "#if"):
			st := ifState{outerActive: active, cond: expandedConditions[i]}
			ifStack = append(ifStack, st)
			expandedOpen = append(expandedOpen, trim)
			active = active && st.cond
			continue
		case strings.HasPrefix(trim, "#elif"):
			if len(ifStack) == 0 {
				return "", fmt.Errorf("expanded line %d: stray #elif", i+1)
			}
			top := ifStack[len(ifStack)-1]
			if top.inElse {
				return "", fmt.Errorf("expanded line %d: #elif after #else", i+1)
			}
			if top.cond {
				active = false
				continue
			}
			top.cond = expandedConditions[i]
			ifStack[len(ifStack)-1] = top
			active = top.outerActive && top.cond
			continue
		case strings.HasPrefix(trim, "#else"):
			if len(ifStack) == 0 {
				return "", fmt.Errorf("expanded line %d: stray #else", i+1)
			}
			top := ifStack[len(ifStack)-1]
			if top.inElse {
				return "", fmt.Errorf("expanded line %d: duplicate #else", i+1)
			}
			top.inElse = true
			ifStack[len(ifStack)-1] = top
			active = top.outerActive && !top.cond
			continue
		case strings.HasPrefix(trim, "#endif"):
			if len(ifStack) == 0 {
				return "", fmt.Errorf("expanded line %d: stray #endif", i+1)
			}
			top := ifStack[len(ifStack)-1]
			ifStack = ifStack[:len(ifStack)-1]
			expandedOpen = expandedOpen[:len(expandedOpen)-1]
			active = top.outerActive
			continue
		}
		if active {
			if opt != nil && strings.HasPrefix(trim, "#") {
				// The legacy emitter supports conditional directives in macro
				// bodies. Other generated controls need token-stack processing;
				// reject them rather than emitting an unconsumed include/define.
				return "", fmt.Errorf("unsupported macro-expanded preprocessor directive: %s", trim)
			}
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	if len(ifStack) != 0 {
		return "", fmt.Errorf("unterminated expanded #if block: %s", strings.Join(expandedOpen, ", "))
	}
	return out.String(), nil
}

func validPPIdentifier(name string) bool {
	var s scanner.Scanner
	s.Init(strings.NewReader(name))
	s.Mode = scanner.ScanIdents
	s.IsIdentRune = ppIdentRune
	s.Error = func(*scanner.Scanner, string) {}
	return s.Scan() == scanner.Ident && s.TokenText() == name && s.Scan() == scanner.EOF && s.ErrorCount == 0
}

func hasPPContinuation(line string) bool {
	line = strings.TrimRight(line, " \t\r")
	backslashes := 0
	for i := len(line) - 1; i >= 0 && line[i] == '\\'; i-- {
		backslashes++
	}
	return backslashes%2 != 0
}

// cmd/asm escapes only a newline or another backslash in macro replacement
// tokens. Strings/chars remain scanner tokens, so their internal escapes must
// not be interpreted as preprocessor escapes.
func normalizePPMacroEscapes(body string) (string, error) {
	var s scanner.Scanner
	s.Init(strings.NewReader(body))
	s.Mode = scanner.ScanChars | scanner.ScanFloats | scanner.ScanIdents | scanner.ScanInts | scanner.ScanStrings
	s.Whitespace = 1<<'\t' | 1<<'\r' | 1<<' '
	s.IsIdentRune = ppIdentRune
	var scanErr error
	s.Error = func(_ *scanner.Scanner, message string) {
		scanErr = fmt.Errorf("invalid macro replacement: %s", message)
	}
	var out strings.Builder
	start := 0
	for tok := s.Scan(); tok != scanner.EOF; tok = s.Scan() {
		if tok != '\\' {
			continue
		}
		escape := s.Position.Offset
		next := s.Scan()
		if next != '\\' && next != '\n' {
			return "", fmt.Errorf("macro replacement can only escape a backslash or newline")
		}
		out.WriteString(body[start:escape])
		out.WriteRune(next)
		start = s.Position.Offset + 1
	}
	if scanErr != nil {
		return "", scanErr
	}
	if start == 0 {
		return body, nil
	}
	out.WriteString(body[start:])
	return out.String(), nil
}

func validatePPLine(rest string) error {
	var s scanner.Scanner
	s.Init(strings.NewReader(rest))
	s.Mode = scanner.ScanInts | scanner.ScanStrings
	s.Error = func(*scanner.Scanner, string) {}
	if s.Scan() != scanner.Int {
		return fmt.Errorf("invalid #line number")
	}
	if _, err := strconv.Atoi(s.TokenText()); err != nil {
		return fmt.Errorf("invalid #line number: %w", err)
	}
	if s.Scan() != scanner.String || s.Scan() != scanner.EOF || s.ErrorCount != 0 {
		return fmt.Errorf("invalid #line filename or trailing tokens")
	}
	return nil
}

func expandPPLine(line string, macros map[string]ppMacro, macroNames []string, depth int) []string {
	if depth >= 16 {
		return []string{line}
	}
	if strings.Contains(line, "\n") {
		chunks := strings.Split(line, "\n")
		out := make([]string, 0, len(chunks))
		for _, chunk := range chunks {
			out = append(out, expandPPLine(strings.TrimSpace(chunk), macros, macroNames, depth+1)...)
		}
		return out
	}
	trimLine := strings.TrimSpace(line)
	if trimLine == "" {
		return []string{""}
	}
	// Conditional directives embedded in a continued macro are evaluated by
	// preprocessWithDefines after expansion. Their identifiers are macro names,
	// not replacement tokens; keep the directive text intact for that pass.
	if strings.HasPrefix(trimLine, "#") {
		return []string{trimLine}
	}
	for _, name := range macroNames {
		m := macros[name]
		if m.params == nil {
			continue
		}
		args, ok := parseMacroCall(trimLine, name, len(m.params))
		if !ok {
			continue
		}
		body := replaceMacroParams(m.body, m.params, args)
		chunks := strings.Split(body, "\n")
		out := make([]string, 0, len(chunks))
		for _, ch := range chunks {
			out = append(out, expandPPLine(strings.TrimSpace(ch), macros, macroNames, depth+1)...)
		}
		return out
	}
	if m, ok := macros[trimLine]; ok && m.params == nil {
		chunks := strings.Split(m.body, "\n")
		out := make([]string, 0, len(chunks))
		for _, ch := range chunks {
			out = append(out, expandPPLine(strings.TrimSpace(ch), macros, macroNames, depth+1)...)
		}
		return out
	}
	// Expand function-like macro calls that appear inline within a statement,
	// e.g. "...; ROL16(X12, X15); ...".
	inlineChanged := false
	for _, name := range macroNames {
		m := macros[name]
		if m.params == nil {
			continue
		}
		nl, changed := expandInlineMacroCalls(line, name, m)
		if changed {
			line = nl
			inlineChanged = true
		}
	}
	if inlineChanged {
		return expandPPLine(line, macros, macroNames, depth+1)
	}
	// Expand object-like macro identifiers inline (e.g. "MOVD NR, R0").
	if nl, changed := expandIdentMacros(line, macros); changed {
		return expandPPLine(nl, macros, macroNames, depth+1)
	}
	// Immediate expressions use the same identifier tokens as ordinary
	// operands. A second substring pass would expand buf again inside buffer.
	return []string{line}
}

func ppIsIdentChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '_' || ch >= 0x80
}

func expandIdentMacros(line string, macros map[string]ppMacro) (string, bool) {
	var tokens scanner.Scanner
	tokens.Init(strings.NewReader(line))
	tokens.Mode = scanner.ScanIdents | scanner.ScanInts | scanner.ScanFloats |
		scanner.ScanChars | scanner.ScanStrings | scanner.ScanRawStrings
	tokens.IsIdentRune = ppIdentRune
	// Malformed literals are diagnosed by the parser; do not print an unrelated
	// scanner diagnostic or transform a partially recognized token sequence.
	tokens.Error = func(*scanner.Scanner, string) {}

	var out strings.Builder
	last := 0
	for token := tokens.Scan(); token != scanner.EOF; token = tokens.Scan() {
		if token != scanner.Ident {
			continue
		}
		name := tokens.TokenText()
		macro, ok := macros[name]
		body := strings.TrimSpace(macro.body)
		if !ok || macro.params != nil || body == "" || body == name {
			continue
		}
		start := tokens.Position.Offset
		out.WriteString(line[last:start])
		out.WriteString(body)
		last = start + len(name)
	}
	if last == 0 || tokens.ErrorCount != 0 {
		return line, false
	}
	out.WriteString(line[last:])
	return out.String(), true
}

// cmd/asm's identifier grammar is not Go's: assembly identifiers also allow
// the middle dot and division slash, including as their first rune.
func ppIdentRune(ch rune, index int) bool {
	return unicode.IsLetter(ch) || ch == '_' || ch == '·' || ch == '∕' ||
		index > 0 && unicode.IsDigit(ch)
}

func isIdentStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' || ch >= 0x80
}

func isIdentPart(ch byte) bool {
	return isIdentStart(ch) || (ch >= '0' && ch <= '9')
}

func parseMacroDefine(rest string) (name string, params []string, body string, err error) {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", nil, "", fmt.Errorf("empty define")
	}
	i := 0
	for i < len(rest) && isIdentPart(rest[i]) {
		i++
	}
	if i == 0 || !isIdentStart(rest[0]) {
		return "", nil, "", fmt.Errorf("invalid define name")
	}
	name = rest[:i]
	if i < len(rest) && rest[i] == '(' {
		// Keep an empty non-nil slice for function-like macros with no
		// parameters. A nil slice identifies object-like macros.
		params = []string{}
		j := i + 1
		depth := 1
		for ; j < len(rest); j++ {
			switch rest[j] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					goto done
				}
			}
		}
		return "", nil, "", fmt.Errorf("unterminated macro params")
	done:
		paramText := strings.TrimSpace(rest[i+1 : j])
		if paramText != "" {
			for _, p := range strings.Split(paramText, ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					return "", nil, "", fmt.Errorf("empty macro param")
				}
				params = append(params, p)
			}
		}
		body = strings.TrimSpace(rest[j+1:])
		return name, params, body, nil
	}
	body = strings.TrimSpace(rest[i:])
	return name, nil, body, nil
}

func parseMacroCall(line, name string, wantArgs int) ([]string, bool) {
	if !strings.HasPrefix(line, name) {
		return nil, false
	}
	start := len(name)
	for start < len(line) && (line[start] == ' ' || line[start] == '	') {
		start++
	}
	if start >= len(line) || line[start] != '(' {
		return nil, false
	}
	j := start
	depth := 0
	for ; j < len(line); j++ {
		switch line[j] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				goto closeFound
			}
		}
	}
	return nil, false
closeFound:
	tail := strings.TrimSpace(line[j+1:])
	if tail != "" && tail != ";" {
		return nil, false
	}
	argText := strings.TrimSpace(line[start+1 : j])
	if argText == "" {
		if wantArgs == 0 {
			return nil, true
		}
		return nil, false
	}
	parts := splitTopLevelCSV(argText)
	if len(parts) != wantArgs {
		return nil, false
	}
	args := make([]string, 0, len(parts))
	for _, p := range parts {
		args = append(args, strings.TrimSpace(p))
	}
	return args, true
}

func expandInlineMacroCalls(line, name string, m ppMacro) (string, bool) {
	if m.params == nil || line == "" {
		return line, false
	}
	var out strings.Builder
	changed := false
	i := 0
	for i < len(line) {
		j := strings.Index(line[i:], name)
		if j < 0 {
			out.WriteString(line[i:])
			break
		}
		j += i
		// Identifier boundary check on the left side.
		// Go assembler symbols commonly prefix package-local names with the
		// UTF-8 middle dot. Treat non-ASCII bytes as identifier bytes here so a
		// macro named g expands in g(CX), but not inside TEXT ·g(SB).
		if j > 0 && ppIsIdentChar(line[j-1]) {
			out.WriteString(line[i : j+1])
			i = j + 1
			continue
		}
		open := j + len(name)
		for open < len(line) && (line[open] == ' ' || line[open] == '	') {
			open++
		}
		if open >= len(line) || line[open] != '(' {
			out.WriteString(line[i : j+1])
			i = j + 1
			continue
		}
		depth := 0
		k := open
		for ; k < len(line); k++ {
			switch line[k] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					goto callFound
				}
			}
		}
		// Unterminated call; keep tail as-is.
		out.WriteString(line[i:])
		return out.String(), changed

	callFound:
		argText := strings.TrimSpace(line[open+1 : k])
		args := []string{}
		if argText != "" {
			parts := splitTopLevelCSV(argText)
			args = make([]string, 0, len(parts))
			for _, p := range parts {
				args = append(args, strings.TrimSpace(p))
			}
		}
		if len(args) != len(m.params) {
			// Not this macro invocation; keep one byte and continue scanning.
			out.WriteString(line[i : j+1])
			i = j + 1
			continue
		}
		out.WriteString(line[i:j])
		out.WriteString(replaceMacroParams(m.body, m.params, args))
		changed = true
		i = k + 1
	}
	return out.String(), changed
}

func replaceMacroParams(body string, params, args []string) string {
	if len(params) == 0 || len(params) != len(args) {
		return body
	}
	m := make(map[string]string, len(params))
	for i, p := range params {
		m[p] = args[i]
	}
	var out strings.Builder
	for i := 0; i < len(body); {
		ch := body[i]
		if isIdentStart(ch) {
			j := i + 1
			for j < len(body) && isIdentPart(body[j]) {
				j++
			}
			name := body[i:j]
			if rep, ok := m[name]; ok {
				out.WriteString(rep)
			} else {
				out.WriteString(name)
			}
			i = j
			continue
		}
		out.WriteByte(ch)
		i++
	}
	return out.String()
}
