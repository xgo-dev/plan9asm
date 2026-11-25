package plan9asm

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// GoSourceSelection supplies the complete selected Go source inventory used by
// the type checker for ARM64 ABI0 private tail declaration binding.
type GoSourceSelection struct {
	Fset            *token.FileSet
	TypesInfo       *types.Info
	Sizes           types.Sizes
	SelectedGoFiles []string
	GoSources       map[string][]byte
}

// GoARM64ABI0TailDeclarationBindingNeeded reports whether file contains an
// ARM64 ABI0 entry that branches to a file-local helper<> without its own
// frame arguments (or performs a candidate trailing result store) and therefore
// requires binding to the selected bodyless Go declarations.
func GoARM64ABI0TailDeclarationBindingNeeded(file *File) bool {
	if file == nil || file.Arch != ArchARM64 {
		return false
	}
	for _, fn := range file.Funcs {
		if strings.Contains(fn.Sym, "<") {
			continue
		}
		if arm64ABI0TailCandidate(file, fn, nil, nil) {
			return true
		}
	}
	return false
}

func arm64PrivateTailTarget(ins Instr) (string, bool) {
	op := strings.ToUpper(string(ins.Op))
	if (op != "B" && op != "JMP") || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
		return "", false
	}
	sym := strings.TrimSpace(ins.Args[0].Sym)
	if !strings.HasSuffix(sym, "<>(SB)") {
		return "", false
	}
	return strings.TrimSuffix(sym, "(SB)"), true
}

func arm64ABI0TailCandidate(file *File, root Func, resolve func(string) string, sigs map[string]FuncSig) bool {
	for _, ins := range root.Instrs {
		name, ok := arm64PrivateTailTarget(ins)
		if !ok {
			continue
		}
		for _, helper := range file.Funcs {
			if helper.Sym != name || helper.ArgSize != 0 {
				continue
			}
			if resolve != nil && sigs != nil {
				if _, bound := sigs[resolve(goTextSymbolForResolution(helper.Sym))]; bound {
					continue
				}
			}
			return true
		}
	}
	return false
}

// BindGoARM64ABI0TailDeclarations validates pkg.SourceSelection for every
// ARM64 ABI0 entry that tail-branches to an unbound file-local helper<> and
// derives the helper's register-passing signature from the caller's live setup.
func BindGoARM64ABI0TailDeclarations(pkg GoPackage, file *File, resolve func(string) string, sigs map[string]FuncSig) (map[string]FuncSig, error) {
	result := make(map[string]FuncSig, len(sigs))
	for k, v := range sigs {
		result[k] = v
	}
	if file == nil || file.Arch != ArchARM64 {
		return result, nil
	}
	helpersBySym := make(map[string]Func, len(file.Funcs))
	for _, fn := range file.Funcs {
		helpersBySym[fn.Sym] = fn
	}

	for _, root := range file.Funcs {
		if strings.Contains(root.Sym, "<") || !arm64ABI0TailCandidate(file, root, resolve, result) {
			continue
		}
		if resolve == nil || !strings.HasPrefix(root.Sym, "·") || strings.ContainsAny(strings.TrimPrefix(root.Sym, "·"), "·<>") {
			return nil, fmt.Errorf("%w: ARM64 ABI0 tail needs an exact local declaration namespace", ErrProbeNeedsContext)
		}
		rootResolved := resolve(goTextSymbolForResolution(root.Sym))
		declName := strings.TrimPrefix(root.Sym, "·")
		if err := validateARM64ABI0SourceSelection(pkg, declName, rootResolved); err != nil {
			return nil, err
		}
		// Derive the helper<> signature from registers written in root before B helper<>(SB)
		// and read by helper<>.
		for _, ins := range root.Instrs {
			targetSym, ok := arm64PrivateTailTarget(ins)
			if !ok {
				continue
			}
			helper, exists := helpersBySym[targetSym]
			if !exists {
				continue
			}
			helperResolved := resolve(goTextSymbolForResolution(helper.Sym))
			if _, already := result[helperResolved]; already {
				continue
			}
			helperSig := deriveARM64TailHelperSig(root, helper, helperResolved)
			result[helperResolved] = helperSig
		}
	}
	return result, nil
}

func validateARM64ABI0SourceSelection(pkg GoPackage, funcName, resolvedSym string) error {
	if pkg.Types == nil || pkg.Types.Scope() == nil {
		return fmt.Errorf("%w: ARM64 ABI0 tail lacks package types", ErrProbeNeedsContext)
	}
	// Check namespace identity: regular package matches pkg.Types.Path(),
	// while executable main packages may link under "main".
	namespaceOK := pkg.Path == pkg.Types.Path() ||
		(pkg.Path == "main" && pkg.Types.Name() == "main" && resolvedSym == "main."+funcName)
	if !namespaceOK {
		return fmt.Errorf("%w: ARM64 ABI0 tail package namespace mismatch (%q vs %q)", ErrProbeNeedsContext, pkg.Path, pkg.Types.Path())
	}
	decl, ok := pkg.Types.Scope().Lookup(funcName).(*types.Func)
	if !ok || decl == nil {
		return fmt.Errorf("%w: ARM64 ABI0 tail missing Go declaration %q", ErrProbeNeedsContext, funcName)
	}
	sel := pkg.SourceSelection
	if sel == nil || sel.Fset == nil || sel.TypesInfo == nil || sel.Sizes == nil ||
		len(sel.SelectedGoFiles) == 0 || len(sel.SelectedGoFiles) > 256 ||
		len(sel.GoSources) != len(sel.SelectedGoFiles) || len(pkg.Syntax) != len(sel.SelectedGoFiles) {
		return fmt.Errorf("%w: ARM64 ABI0 tail lacks complete selected Go source inventory", ErrProbeNeedsContext)
	}

	var matchedDecl *ast.Ident
	total := 0
	seen := make(map[string]bool, len(sel.SelectedGoFiles))
	for i, filename := range sel.SelectedGoFiles {
		if seen[filename] {
			return fmt.Errorf("%w: ARM64 ABI0 tail duplicate selected file %q", ErrProbeNeedsContext, filename)
		}
		seen[filename] = true
		src, present := sel.GoSources[filename]
		total += len(src)
		if !present || len(src) == 0 || total > 16<<20 {
			return fmt.Errorf("%w: ARM64 ABI0 tail incomplete or oversized Go source %q", ErrProbeNeedsContext, filename)
		}
		parsedFset := token.NewFileSet()
		parsed, err := parser.ParseFile(parsedFset, filename, src, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("%w: ARM64 ABI0 tail selected Go source parse error: %v", ErrProbeNeedsContext, err)
		}
		actualText, err := formatASTFile(pkg.Syntax[i], sel.Fset)
		parsedText, perr := formatASTFile(parsed, parsedFset)
		if err != nil || perr != nil || actualText != parsedText || pkg.Syntax[i].Name.Name != pkg.Types.Name() {
			return fmt.Errorf("%w: ARM64 ABI0 tail syntax differs from selected bytes for %q", ErrProbeNeedsContext, filename)
		}
		for _, d := range pkg.Syntax[i].Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Name.Name != funcName {
				continue
			}
			if matchedDecl != nil || fn.Recv != nil || fn.Body != nil ||
				sel.TypesInfo.Defs[fn.Name] != decl || fn.Name.Pos() != decl.Pos() ||
				sel.Fset.Position(fn.Name.Pos()).Filename != filename {
				return fmt.Errorf("%w: ARM64 ABI0 tail declaration %q is not a unique bodyless declaration", ErrProbeNeedsContext, funcName)
			}
			matchedDecl = fn.Name
		}
	}
	if matchedDecl == nil {
		return fmt.Errorf("%w: ARM64 ABI0 tail declaration %q not found in selected sources", ErrProbeNeedsContext, funcName)
	}
	return nil
}

func formatASTFile(file *ast.File, fset *token.FileSet) (string, error) {
	if file == nil || file.Name == nil || fset == nil {
		return "", fmt.Errorf("incomplete Go AST")
	}
	var out bytes.Buffer
	if err := format.Node(&out, fset, file); err != nil {
		return "", err
	}
	return out.String(), nil
}

func deriveARM64TailHelperSig(root, helper Func, helperResolved string) FuncSig {
	// Collect GP registers written in root (distinguishing FP-address Ptr slots)
	// and intersect with GP registers read in helper.
	writtenInRoot := map[Reg]LLVMType{}
	for _, ins := range root.Instrs {
		if len(ins.Args) < 2 {
			continue
		}
		dst := ins.Args[len(ins.Args)-1]
		if dst.Kind != OpReg {
			continue
		}
		ty := I64
		if ins.Args[0].Kind == OpFPAddr {
			ty = Ptr
		}
		writtenInRoot[dst.Reg] = ty
	}
	readInHelper := map[Reg]bool{}
	for _, ins := range helper.Instrs {
		for i, arg := range ins.Args {
			switch arg.Kind {
			case OpReg:
				// For non-store instructions, the last operand is usually dst.
				if i < len(ins.Args)-1 || strings.HasPrefix(strings.ToUpper(string(ins.Op)), "CMP") || strings.HasPrefix(strings.ToUpper(string(ins.Op)), "CB") {
					readInHelper[arg.Reg] = true
				}
			case OpMem:
				if arg.Mem.Base != "" {
					readInHelper[arg.Mem.Base] = true
				}
				if arg.Mem.Index != "" {
					readInHelper[arg.Mem.Index] = true
				}
			}
		}
	}
	var regs []Reg
	for r := range writtenInRoot {
		if readInHelper[r] {
			regs = append(regs, r)
		}
	}
	sort.Slice(regs, func(i, j int) bool { return regs[i] < regs[j] })
	args := make([]LLVMType, len(regs))
	for i, r := range regs {
		args[i] = writtenInRoot[r]
	}
	return FuncSig{
		Name:    helperResolved,
		Args:    args,
		Ret:     Void,
		ArgRegs: regs,
	}
}

// hasARM64PrivateTailBranch reports whether file has an ARM64 private tail call.
func isARM64HelperSym(sym string) bool {
	return strings.HasSuffix(sym, "<>") && !strings.Contains(strings.TrimSuffix(sym, "<>"), "<")
}

// Keep unused asm import referenced cleanly if needed.
var _ = asm.ArchARM64
