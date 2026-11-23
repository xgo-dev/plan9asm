package plan9asm

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

// Resolve CALL byte addends against the original Go object layout. A declared
// ordinary TEXT retains its callable entry; only the bound interior edge
// enters the continuation graph.
func (graph *x86DirectTailGraph) bindInteriorCallEntries(triple string) error {
	var targets map[x86SourceBranchTarget]int
	for _, fn := range graph.original.Funcs {
		for _, ins := range fn.Instrs {
			branch, direct := x86DirectSourceBranch(ins, graph.goarch)
			if !direct || ins.Op != OpCALL || branch.addend == 0 {
				continue
			}
			text, found := graph.texts[branch.symbol]
			if !found || branch.addend < 0 || graph.numerical != nil {
				return x86DirectTailContext("unbound CALL byte entry: %s", ins.Raw)
			}
			if !graph.helpers[branch.symbol] {
				name := graph.symbols[branch.symbol]
				sig, declared := graph.signatures[name]
				if !declared || sig.Name != "" && sig.Name != name || sig.Ret != Void ||
					len(sig.Args) != 0 || len(sig.ArgRegs) != 0 || len(sig.Frame.Params) != 0 || len(sig.Frame.Results) != 0 {
					return x86DirectTailContext("CALL byte target needs an ordinary zero-argument, void entry: %s", branch.symbol)
				}
			}
			if targets == nil {
				targets = make(map[x86SourceBranchTarget]int)
			}
			targets[branch] = text
		}
	}
	if len(targets) == 0 {
		return nil
	}

	selected := make(map[int]bool)
	for _, text := range targets {
		selected[text] = true
	}
	const sourceHeader = "#include \"textflag.h\"\n"
	var source strings.Builder
	points := []x86DirectTailPoint{{text: -1}} // The include has no instruction owner.
	source.WriteString(sourceHeader)
	for text, fn := range graph.original.Funcs {
		if !selected[text] {
			continue
		}
		if err := x86InteriorCallText(fn, graph.goarch, false); err != nil {
			return err
		}
		for ordinal, ins := range fn.Instrs {
			if len(points) > 4096 || len(ins.Raw) > 1<<20-source.Len() ||
				strings.ContainsAny(ins.Raw, "\r\n") || strings.HasPrefix(strings.TrimSpace(ins.Raw), "#") {
				return x86DirectTailContext("unbounded or unbound private CALL source")
			}
			source.WriteString(ins.Raw)
			source.WriteByte('\n')
			points = append(points, x86DirectTailPoint{text, ordinal})
		}
	}
	// Bind the exact source handed to cmd/asm to the same parsed instructions
	// that lowering will execute. Handles callers that construct a File by hand.
	replayed, err := parsePreprocessedAssembly(ArchAMD64, strings.TrimPrefix(source.String(), sourceHeader))
	if err != nil || len(replayed.Funcs) != len(selected) {
		return x86DirectTailContext("cannot replay private CALL source: %v", err)
	}
	for _, replay := range replayed.Funcs {
		text, found := graph.texts[replay.Sym]
		if !found || !selected[text] || !x86InteriorCallSameSource(graph.original.Funcs[text], replay, graph.goarch) {
			return x86DirectTailContext("private CALL source replay differs: %s", replay.Sym)
		}
	}
	listing, err := x86InteriorCallGoListing(source.String(), graph.goarch, triple)
	if err != nil {
		return err
	}
	positions := x86InteriorCallPositions(listing, points, graph.original)
	graph.interiorEntries = make(map[x86SourceBranchTarget]x86DirectTailPoint, len(targets))
	for target, text := range targets {
		entries, frameless := positions[text]
		if !frameless {
			return x86DirectTailContext("CALL byte entry lacks a verified frameless Go layout: %s", target.symbol)
		}
		point, found := entries[target.addend]
		if !found {
			return x86DirectTailContext("CALL byte offset %s%+d has no original instruction entry", target.symbol, target.addend)
		}
		graph.interiorEntries[target] = point
	}
	return nil
}

func x86InteriorCallText(fn Func, arch string, requiresExplicitNoFrame bool) error {
	if fn.FrameSize != 0 || fn.ArgSize != 0 || len(fn.Instrs) == 0 || fn.Instrs[0].Op != OpTEXT {
		return x86DirectTailContext("CALL byte entry needs an explicit frameless TEXT: %s", fn.Sym)
	}
	_, header := splitOpcode(fn.Instrs[0].Raw)
	parts := strings.Split(header, ",")
	if len(parts) != 3 {
		return x86DirectTailContext("CALL byte entry needs explicit TEXT flags: %s", fn.Sym)
	}
	flags, err := nativeFlags(parts[1], "NOSPLIT", "NOFRAME", "DUPOK")
	frame, frameErr := parseTEXTFrameSpec(parts)
	if err != nil || frameErr != nil || !flags["NOSPLIT"] ||
		!frame.argsSpecified || frame.frameSize != 0 || frame.argSize != 0 {
		return x86DirectTailContext("CALL byte entry requires NOSPLIT and an explicit zero-size source frame: %s", fn.Sym)
	}
	if requiresExplicitNoFrame && !flags["NOFRAME"] {
		return x86DirectTailContext("native literal CALL requires explicit NOFRAME: %s", fn.Sym)
	}
	// A standalone member preserves local code layout. Go's shared/dynlink
	// modes can change the size of TLS accesses and global/literal loads.
	for _, ins := range fn.Instrs[1:] {
		if _, direct := x86DirectSourceBranch(ins, arch); direct {
			continue
		}
		for _, arg := range ins.Args {
			if arg.Kind == OpSym || arg.Kind == OpImm && arg.ImmIsFloat || arg.Kind == OpReg && arg.Reg == TLS ||
				arg.Kind == OpMem && (arg.Mem.Sym != "" || arg.Mem.Base == TLS || arg.Mem.Index == TLS) {
				return x86DirectTailContext("CALL byte entry needs target-specific relocation layout: %s", ins.Raw)
			}
		}
	}
	return nil
}

func x86InteriorCallSameSource(original, replay Func, arch string) bool {
	if len(original.Instrs) != len(replay.Instrs) || original.FrameSize != replay.FrameSize || original.ArgSize != replay.ArgSize {
		return false
	}
	for ordinal, ins := range original.Instrs {
		actual := replay.Instrs[ordinal]
		if ins.Op != actual.Op || ins.Raw != actual.Raw {
			return false
		}
		if reflect.DeepEqual(ins.Args, actual.Args) {
			continue
		}
		left, leftOK := x86DirectSourceBranch(ins, arch)
		right, rightOK := x86DirectSourceBranch(actual, arch)
		if !leftOK || !rightOK || left != right {
			return false
		}
	}
	return true
}

func x86InteriorCallGoListing(source, arch, triple string) ([]byte, error) {
	goos := "linux"
	for _, component := range strings.Split(strings.ToLower(triple), "-") {
		switch {
		case strings.HasPrefix(component, "darwin"), strings.HasPrefix(component, "macos"):
			goos = "darwin"
		case component == "windows", component == "win32", component == "mingw32":
			goos = "windows"
		case component == "freebsd", component == "netbsd", component == "openbsd", component == "dragonfly",
			component == "solaris", component == "illumos", component == "plan9":
			goos = component
		}
	}
	dir, err := os.MkdirTemp("", "plan9asm-call-entries-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "entries.s"), []byte(source), 0600); err != nil {
		return nil, err
	}
	root := runtime.GOROOT()
	goBinary := filepath.Join(root, "bin", "go")
	if runtime.GOOS == "windows" {
		goBinary += ".exe"
	}
	env := append(os.Environ(), "GOENV=off", "GOWORK=off", "GOFLAGS=", "GOTOOLCHAIN=local",
		"GOROOT="+root, "GOOS="+goos, "GOARCH="+arch)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return goasmcmd.Run(ctx, dir, env, goBinary, "tool", "asm", "-S", "-p", "plan9asmentries",
		"-I", filepath.Join(root, "pkg", "include"), "-o", "entries.o", "entries.s")
}

var x86InteriorCallLine = regexp.MustCompile(`^\s+0x([0-9a-f]+)\s+\d+\s+\((?:.*[/\\])?entries[.]s:(\d+)\)\s+([A-Z][A-Z0-9.]*)\b`)

func x86InteriorCallPositions(listing []byte, points []x86DirectTailPoint, file *File) map[int]map[int64]x86DirectTailPoint {
	positions := make(map[int]map[int64]x86DirectTailPoint)
	seen := make(map[x86DirectTailPoint]bool)
	text := -1
	for _, line := range strings.Split(string(listing), "\n") {
		match := x86InteriorCallLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		pc, pcErr := strconv.ParseInt(match[1], 16, 64)
		lineNumber, lineErr := strconv.Atoi(match[2])
		if pcErr != nil || lineErr != nil || lineNumber < 2 || lineNumber > len(points) {
			continue
		}
		point := points[lineNumber-1]
		op := file.Funcs[point.text].Instrs[point.instruction].Op
		switch match[3] {
		case "TEXT":
			text = -1
			// The assembler can add a frame even for source TEXT $0-0.
			// Older SDK listings may leave NOFRAME implicit for a leaf.
			frame, err := parseTEXTFrameSpec(strings.Split(line[len(match[0]):], ","))
			if op == OpTEXT && pc == 0 && err == nil && frame.argsSpecified &&
				frame.frameSize == 0 && frame.argSize == 0 {
				text = point.text
				positions[text] = make(map[int64]x86DirectTailPoint)
			}
			continue
		case "PCDATA", "FUNCDATA", "PCALIGN", "PCALIGNMAX":
			continue
		}
		if point.text != text || op == OpLABEL || seen[point] {
			continue
		}
		if op == OpTEXT {
			// Code attributed to the TEXT header is assembler-generated.
			delete(positions, text)
			text = -1
			continue
		}
		seen[point] = true // Expanded instructions can only be entered at their first byte.
		if _, found := positions[text][pc]; !found {
			positions[text][pc] = point
		}
	}
	return positions
}
