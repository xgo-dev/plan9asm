package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

// Bind every parsed instruction ordinal to the sealed SDK lexer tape, not a
// guessed line in a newly flattened file. DATA/GLOBL stay in the authenticated
// complete program but are not TEXT instructions. Labels retain their order.
func numericalSDKLiteralSourcePositions(file *File, output string, observed sdkCPPPositionObservation) ([][]string, error) {
	if file == nil || file.Arch != ArchAMD64 || len(file.UnlinkedPrelude) != 0 {
		return nil, numericalSBContext("mapped numerical source lacks its complete parsed TEXT")
	}
	mapped, err := sdkCPPMappedAssembly(observed.Tokens, ppGoObservationBytes)
	if err != nil || mapped != observed.Mapped {
		return nil, numericalSBContext("mapped numerical source changed its complete SDK position tape")
	}
	replayed, err := preprocessGoAssembly(mapped, AssemblyPreprocessOptions{})
	if err != nil || replayed != output {
		return nil, numericalSBContext("mapped numerical source changed its complete CPP program")
	}
	var statements []numericalListingRow
	var tokens []sdkCPPPositionToken
	for _, token := range observed.Tokens {
		if token.Kind != '\n' {
			tokens = append(tokens, token)
		}
		if token.Kind != '\n' && token.Kind != ';' && token.Kind != ':' || len(tokens) == 0 {
			continue
		}
		var text strings.Builder
		for _, item := range tokens {
			text.WriteString(item.Text)
			text.WriteByte(' ')
		}
		canonical, err := preprocessGoAssembly(text.String()+"\n", AssemblyPreprocessOptions{})
		if err != nil {
			return nil, numericalSBContext("mapped numerical statement cannot be replayed")
		}
		canonical = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(canonical), ";"))
		base := token.Position.FinalBase
		line := sdkCPPClampLine(tokens[0].Position.Line)
		if base.Line == 0 {
			line = 0
		} else {
			line = base.Line + (line - base.Anchor)
		}
		position := fmt.Sprintf("%s:%d", base.File, line)
		statements = append(statements, numericalListingRow{position: position, ins: Instr{Raw: canonical}})
		tokens = nil
	}
	if len(tokens) != 0 {
		return nil, numericalSBContext("mapped numerical source has unterminated tokens")
	}
	var instructions []numericalListingRow
	for _, statement := range statements {
		head, err := parseAssemblyOpcode(ArchAMD64, statement.ins.Raw)
		if err != nil {
			return nil, err
		}
		if head.name != "DATA" && head.name != "GLOBL" {
			instructions = append(instructions, statement)
		}
	}
	positions := make([][]string, len(file.Funcs))
	index := 0
	for f, fn := range file.Funcs {
		positions[f] = make([]string, len(fn.Instrs))
		for ordinal, ins := range fn.Instrs {
			if index >= len(instructions) || instructions[index].ins.Raw != ins.Raw {
				return nil, numericalSBContext("mapped numerical source ordinal differs from complete parsed instructions")
			}
			positions[f][ordinal] = instructions[index].position
			index++
		}
	}
	if index != len(instructions) {
		return nil, numericalSBContext("mapped numerical source omitted parsed instruction ordinals")
	}
	return positions, nil
}

// Repeated macro expansions or semicolon statements can have the same logical
// source position. Their complete source order and actual native PC order must
// agree too; a filename/line or a matching relocation alone is not a join.
func numericalSDKLiteralReadOrdinal(fn Func, ordinal int, positions []string, pc int64, row numericalListingRow,
	rows map[int64][]numericalListingRow, pkg, arch string,
) bool {
	logical, valid := numericalSDKListingLogicalPosition(row.position)
	if !valid || ordinal < 0 || ordinal >= len(fn.Instrs) || len(positions) != len(fn.Instrs) || logical != positions[ordinal] {
		return false
	}
	ins := fn.Instrs[ordinal]
	if !numericalSameInstruction(ins, row.ins, pkg, arch) {
		return false
	}
	sourceRank := 0
	for index, prior := range fn.Instrs[:ordinal] {
		if positions[index] == logical && numericalSameInstruction(ins, prior, pkg, arch) {
			sourceRank++
		}
	}
	nativeRank := 0
	for before, previous := range rows {
		if before >= pc {
			continue
		}
		for _, previous := range previous {
			before, valid := numericalSDKListingLogicalPosition(previous.position)
			if valid && before == logical && numericalSameInstruction(ins, previous.ins, pkg, arch) {
				nativeRank++
			}
		}
	}
	return sourceRank == nativeRank
}

// Go's Pos.Format(true,true) prints a #line position as logical[original].
// Keep the complete listing in the native proof; only the logical projection
// can be compared with Go's binary PC tables and the authenticated lexer tape.
// The bracket annotation is not an authenticated physical-file lookup route.
func numericalSDKListingLogicalPosition(display string) (string, bool) {
	validPosition := func(position string) bool {
		colon := strings.LastIndexByte(position, ':')
		if colon <= 0 || strings.ContainsAny(position, "[]\r\n") {
			return false
		}
		line := position[colon+1:]
		if line == "" {
			return false
		}
		for _, digit := range line {
			if digit < '0' || digit > '9' {
				return false
			}
		}
		_, err := strconv.ParseUint(line, 10, 32)
		return err == nil
	}
	logical := display
	if bracket := strings.IndexByte(display, '['); bracket >= 0 {
		if !strings.HasSuffix(display, "]") || !validPosition(display[bracket+1:len(display)-1]) {
			return "", false
		}
		logical = display[:bracket]
	}
	return logical, validPosition(logical)
}

// Native SDK PC tables use $GOROOT metadata while -S uses absolute names.
// Resolve only against this invocation's captured root and existing exact CPP
// input inventory. A logical name never authorizes opening an arbitrary file.
func (source *GoX86NumericalReadSource) sdkLiteralObjectSource(name string) (string, bool) {
	if source.sdkAssemblyJoin() == nil {
		return "", false
	}
	name, valid := originalGoObjectSourcePath(name, source.guard.env["GOROOT"])
	if !valid {
		return "", false
	}
	digest, captured := source.guard.inputs[name]
	if !captured {
		return "", false
	}
	for _, input := range source.cpp.Sources {
		if input.File == name && input.SHA256 == fmt.Sprintf("%x", digest) {
			return name, true
		}
	}
	return "", false
}
