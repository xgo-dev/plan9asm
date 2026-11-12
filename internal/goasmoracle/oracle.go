// Package goasmoracle validates source-bound observations, not ISA/ABI authority.
package goasmoracle

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/scanner"
)

func CheckOutcome(source, object string, stdout, stderr []byte, commandErr, contextErr error, wantSuccess bool, focus int, additional func(string, string) bool) error {
	if contextErr != nil {
		return fmt.Errorf("Go assembler oracle infrastructure failure: deadline/cancellation: %w", contextErr)
	}
	if commandErr == nil {
		if !wantSuccess {
			return fmt.Errorf("Go assembler accepted a form expected outside the optab")
		}
		info, err := os.Lstat(object)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("Go assembler oracle infrastructure failure: missing/nonregular/empty object: %v", err)
		}
		return nil
	}
	// Cleanup/pipe errors joined to a source exit are still infrastructure
	// failures. A signal, launch error or unknown positive exit is not evidence.
	exit, ok := commandErr.(*exec.ExitError)
	if !ok || exit.ProcessState == nil || !exit.ProcessState.Exited() || exit.ExitCode() != 1 {
		return fmt.Errorf("Go assembler oracle infrastructure failure: unknown process outcome: %w", commandErr)
	}
	streams := []string{string(stdout), string(stderr)}
	for _, marker := range []string{"panic:", "fatal error:", "runtime: failed to", "runtime: out of memory", "signal:", "executable file not found"} {
		for _, text := range streams {
			if strings.Contains(text, marker) {
				return fmt.Errorf("Go assembler oracle infrastructure failure: %s: %w", marker, commandErr)
			}
		}
	}
	// Go prints source positions either directly or in its illegal-combination
	// listing. A footer alone, or a line for another source, cannot reject this
	// exact fixture. Keep positive canonical line/column positions.
	bound := false
	for _, text := range streams {
		bound = bound || SourceDiagnosticLine(source, text, focus) || (additional != nil && additional(source, text))
	}
	if !bound {
		return fmt.Errorf("Go assembler oracle infrastructure failure: no concrete fixture diagnostic: %w", commandErr)
	}
	if wantSuccess {
		return fmt.Errorf("Go assembler rejected accepted forms: %w", commandErr)
	}
	return nil
}

// ReadSource preserves the existing eight-MiB fixture bound. This is an
// independent bounded physical read, not a caller-supplied snapshot/hash.
func ReadSource(source string) ([]byte, bool) {
	before, err := os.Lstat(source)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > 8<<20 {
		return nil, false
	}
	file, err := os.Open(source)
	if err != nil {
		return nil, false
	}
	opened, err := file.Stat()
	if err != nil || !sameInput(before, opened) {
		_ = file.Close()
		return nil, false
	}
	data, readErr := io.ReadAll(io.LimitReader(file, before.Size()+1))
	ended, endErr := file.Stat()
	closeErr := file.Close()
	after, pathErr := os.Lstat(source)
	return data, readErr == nil && endErr == nil && closeErr == nil &&
		pathErr == nil && int64(len(data)) == before.Size() &&
		sameInput(before, ended) && sameInput(before, after)
}

func sameInput(before, after os.FileInfo) bool {
	return os.SameFile(before, after) && before.Mode() == after.Mode() &&
		before.Size() == after.Size() && before.ModTime() == after.ModTime()
}

// The token role is only a diagnostic join. It is not an instruction grammar,
// lowering rule, or permission to execute a source statement.
func statementOpcode(statement string) string {
	opcode, _ := statementRole(statement)
	return opcode
}

func statementRole(statement string) (string, bool) {
	tokens, ok := diagnosticTokens(statement)
	if !ok || len(tokens) == 0 || tokens[0].kind != scanner.Ident {
		return "", false
	}
	opcode, next := tokens[0].text, 1
	for next < len(tokens) && tokens[next].kind == '.' {
		if next+1 >= len(tokens) || tokens[next+1].kind != scanner.Ident {
			return "", false
		}
		opcode += "." + tokens[next+1].text
		next += 2
	}
	if next < len(tokens) && tokens[next].kind == ':' {
		// A label or label prefix is not this isolated statement's opcode.
		return "", false
	}
	return opcode, next == len(tokens)
}

func positivePosition(text string) (int, bool) {
	value, err := strconv.Atoi(text)
	return value, err == nil && value > 0 && strconv.Itoa(value) == text
}

func canonicalPC(pc string) bool {
	address, err := strconv.ParseUint(pc, 10, 64)
	return err == nil && len(pc) >= 5 && fmt.Sprintf("%05d", address) == pc
}

func ListingBindsSource(source, position, pc, instruction string) bool {
	data, ok := ReadSource(source)
	line, valid := positivePosition(position)
	lines := strings.Split(string(data), "\n")
	if !ok || !valid || line > len(lines) || !canonicalPC(strings.TrimSpace(pc)) {
		return false
	}
	fields := strings.Fields(instruction)
	opcode, zeroOperands := statementRole(lines[line-1])
	if len(fields) == 0 || opcode == "" || opcode != fields[0] {
		return false
	}
	// A single listing token is complete only for an original statement with
	// no operand tokens. Truncated operand-bearing listings remain unbound.
	return len(fields) > 1 || zeroOperands
}

func SourceDiagnostic(source, output string) bool {
	return SourceDiagnosticLine(source, output, 0)
}

// Only a real statement in this exact physical fixture can bind a diagnostic.
// A nonzero focus is the script's actual isolated instruction, not its CPP
// header, TEXT setup, RET footer, another source, or an unobserved #line route.
func SourceDiagnosticLine(source, output string, focus int) bool {
	return SourceDiagnosticLineWithListing(source, output, focus, nil)
}

// SourceDiagnosticLineWithListing permits an explicitly selected backend to
// join a complete rewritten listing. The matcher runs only after the same
// physical-source/path/line/focus/canonical-PC checks as the strict default.
// Its lexical inputs are diagnostic observations, not instruction authority.
func SourceDiagnosticLineWithListing(source, output string, focus int, match func(original, listing []string) bool) bool {
	return sourceDiagnosticLine(source, output, focus, match, false)
}

// WasmSourceDiagnosticLine explicitly selects Go's wasm frontend word role.
// Unlike the other supported targets, wasm does not consume opcode suffixes
// before deciding whether the first identifier is a pending label. This is a
// source diagnostic observation, never instruction or execution authority.
func WasmSourceDiagnosticLine(source, output string, focus int) bool {
	return sourceDiagnosticLine(source, output, focus, nil, true)
}

func sourceDiagnosticLine(source, output string, focus int, match func(original, listing []string) bool, wasmWord bool) bool {
	data, ok := ReadSource(source)
	if !ok || focus < 0 {
		return false
	}
	lines := strings.Split(string(data), "\n")
	backendDiagnostic := false
	for _, line := range strings.Split(output, "\n") {
		direct := strings.HasPrefix(line, source+":")
		start, pc := 0, ""
		// cmd/asm's obj.Link diagnostics add this exact backend prefix to
		// source positions. It does not authorize embedded or foreign paths.
		if !direct && strings.HasPrefix(line, "asm: "+source+":") {
			direct, start = true, len("asm: ")
		}
		if !direct {
			marker := strings.Index(line, "("+source+":")
			if marker < 0 {
				if strings.TrimSpace(line) != "" {
					backendDiagnostic = strings.HasPrefix(line, "asm: ") &&
						line != "asm: assembly failed" && line != "asm: "
				}
				continue
			}
			prefix := strings.TrimSpace(line[:marker])
			fields := strings.Fields(prefix)
			if len(fields) == 0 {
				continue
			}
			pc = fields[len(fields)-1]
			if !canonicalPC(pc) {
				continue
			}
			if len(fields) == 1 {
				if !backendDiagnostic {
					continue
				}
			} else if !strings.HasPrefix(prefix, "asm: ") ||
				strings.TrimSpace(strings.TrimSuffix(prefix, pc)) == "asm:" ||
				strings.TrimSpace(strings.TrimSuffix(prefix, pc)) == "asm: assembly failed" {
				continue
			}
			start = marker + 1
		}
		position := line[start+len(source)+1:]
		end := strings.IndexAny(position, ":)")
		if end < 0 {
			continue
		}
		number, valid := positivePosition(position[:end])
		if !valid || number > len(lines) || (focus > 0 && number != focus) {
			continue
		}
		message := strings.TrimSpace(position[end+1:])
		if position[end] == ')' {
			if !direct && ListingBindsSource(source, position[:end], pc, message) {
				return true
			}
			if !direct && match != nil && statementOpcode(lines[number-1]) != "" {
				original, sourceOK := diagnosticTokens(lines[number-1])
				listing, listingOK := diagnosticTokens(message)
				if sourceOK && listingOK && len(listing) > 0 && listing[0].kind == scanner.Ident &&
					match(tokenTexts(original), tokenTexts(listing)) {
					return true
				}
			}
			continue
		}
		if !direct {
			continue
		}
		if column, detail, found := strings.Cut(message, ":"); found &&
			(column == "" || strings.ContainsRune("+-0123456789", rune(column[0]))) {
			if value, valid := positivePosition(column); valid && value <= len([]rune(lines[number-1])) && strings.TrimSpace(detail) != "" {
				if known, bound := frontendDiagnostic(data, number, value, strings.TrimSpace(detail), wasmWord); known {
					if bound {
						return true
					}
				} else if statementOpcode(lines[number-1]) != "" {
					return true
				}
			}
			continue
		}
		if known, bound := frontendDiagnostic(data, number, 0, message, wasmWord); known {
			if bound {
				return true
			}
		} else if message != "" && statementOpcode(lines[number-1]) != "" {
			return true
		}
	}
	return false
}
