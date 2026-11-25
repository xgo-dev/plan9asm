package asm

import (
	"fmt"
	"sort"
	"strings"
)

// CollectMissingLLVMIntrinsicDecls scans generated LLVM IR function bodies for
// calls to `@llvm.*` intrinsics that are not already declared in prelude and
// returns deterministic `declare ...` lines for them.
//
// This lets declarative instruction tables emit any LLVM generic or target
// intrinsic without bloating preludes or manually syncing declarations.
func CollectMissingLLVMIntrinsicDecls(prelude, body string) string {
	declared := map[string]bool{}
	for _, line := range strings.Split(prelude, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "declare ") {
			continue
		}
		if idx := strings.Index(line, "@llvm."); idx >= 0 {
			rest := line[idx:]
			if end := strings.IndexByte(rest, '('); end > 0 {
				declared[rest[:end]] = true
			}
		}
	}

	needed := map[string]string{}
	for _, rawLine := range strings.Split(body, "\n") {
		line := strings.TrimSpace(rawLine)
		atIdx := strings.Index(line, "@llvm.")
		if atIdx < 0 {
			continue
		}
		callIdx := strings.Index(line[:atIdx], "call ")
		if callIdx < 0 {
			continue
		}
		retTy := strings.TrimSpace(line[callIdx+len("call ") : atIdx])
		// Strip optional fast-math/tail/ret attributes before return type.
		for _, prefix := range []string{"fast ", "ninf ", "nnan ", "nsz ", "arcp ", "contract ", "afn ", "reassoc ", "zeroext ", "signext ", "inreg "} {
			for strings.HasPrefix(retTy, prefix) {
				retTy = strings.TrimSpace(strings.TrimPrefix(retTy, prefix))
			}
		}
		if retTy == "" {
			continue
		}
		rest := line[atIdx:]
		openParen := strings.IndexByte(rest, '(')
		if openParen <= 0 {
			continue
		}
		name := rest[:openParen]
		if declared[name] {
			continue
		}
		if _, exists := needed[name]; exists {
			continue
		}
		closeParen := matchParen(rest, openParen)
		if closeParen <= openParen {
			continue
		}
		argList := rest[openParen+1 : closeParen]
		argTypes, ok := extractLLVMCallArgTypes(argList)
		if !ok {
			continue
		}
		needed[name] = fmt.Sprintf("declare %s %s(%s)", retTy, name, strings.Join(argTypes, ", "))
	}

	if len(needed) == 0 {
		return ""
	}
	names := make([]string, 0, len(needed))
	for name := range needed {
		names = append(names, name)
	}
	sort.Strings(names)
	var out strings.Builder
	for _, name := range names {
		out.WriteString(needed[name])
		out.WriteByte('\n')
	}
	out.WriteByte('\n')
	return out.String()
}

func matchParen(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// extractLLVMCallArgTypes extracts the LLVM type from each typed call argument
// (e.g. `<16 x i8> %t1, i8 3` -> `[]string{"<16 x i8>", "i8"}`).
func extractLLVMCallArgTypes(argList string) ([]string, bool) {
	argList = strings.TrimSpace(argList)
	if argList == "" {
		return nil, true
	}
	parts := splitLLVMArgs(argList)
	types := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, false
		}
		ty := parseLLVMArgType(p)
		if ty == "" {
			return nil, false
		}
		types = append(types, ty)
	}
	return types, true
}

func splitLLVMArgs(s string) []string {
	var parts []string
	depthAngle, depthBrace, depthBracket, depthParen := 0, 0, 0, 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '<':
			depthAngle++
		case '>':
			depthAngle--
		case '{':
			depthBrace++
		case '}':
			depthBrace--
		case '[':
			depthBracket++
		case ']':
			depthBracket--
		case '(':
			depthParen++
		case ')':
			depthParen--
		case ',':
			if depthAngle == 0 && depthBrace == 0 && depthBracket == 0 && depthParen == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func parseLLVMArgType(arg string) string {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return ""
	}
	switch arg[0] {
	case '<':
		if end := strings.IndexByte(arg, '>'); end > 0 {
			return strings.TrimSpace(arg[:end+1])
		}
		return ""
	case '{':
		depth := 0
		for i := 0; i < len(arg); i++ {
			if arg[i] == '{' {
				depth++
			} else if arg[i] == '}' {
				depth--
				if depth == 0 {
					return strings.TrimSpace(arg[:i+1])
				}
			}
		}
		return ""
	case '[':
		depth := 0
		for i := 0; i < len(arg); i++ {
			if arg[i] == '[' {
				depth++
			} else if arg[i] == ']' {
				depth--
				if depth == 0 {
					return strings.TrimSpace(arg[:i+1])
				}
			}
		}
		return ""
	default:
		fields := strings.Fields(arg)
		if len(fields) == 0 {
			return ""
		}
		// Handle `ptr addrspace(N) %x`
		if fields[0] == "ptr" && len(fields) >= 3 && strings.HasPrefix(fields[1], "addrspace(") {
			return fields[0] + " " + fields[1]
		}
		return fields[0]
	}
}
