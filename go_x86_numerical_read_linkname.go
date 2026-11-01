package plan9asm

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gosym"
)

// Candidates are source spellings, not compiler or entry authority. A foreign
// mapping is usable only with the existing live factory's compiler witness.
type numericalGoLinknames struct {
	localToNative map[string]string
	nativeToLocal map[string]string
	standard      map[string]bool
	functions     map[string]bool
}

func numericalGoDeclarationLinknames(syntax []*ast.File, typed *types.Package) (numericalGoLinknames, error) {
	if typed == nil || typed.Scope() == nil {
		return numericalGoLinknames{}, numericalSBContext("linkname candidate lacks its actual Go package")
	}
	names, err := numericalGoLinknameSpellings(syntax, typed.Path())
	if err != nil {
		return names, err
	}
	names.functions = make(map[string]bool)
	for local := range names.localToNative {
		switch object := typed.Scope().Lookup(local).(type) {
		case *types.Func:
			if object.Pkg() != typed {
				return names, numericalSBContext("linkname function has a foreign Go owner")
			}
			names.functions[local] = true
		case *types.Var:
			if object.Pkg() != typed {
				return names, numericalSBContext("linkname variable has a foreign Go owner")
			}
		default:
			return names, numericalSBContext("linkname candidate lacks its actual declaration")
		}
	}
	prefix := gosym.PackagePrefix(typed.Path()) + "."
	for native, local := range names.nativeToLocal {
		if strings.HasPrefix(native, prefix) {
			ordinary := strings.TrimPrefix(native, prefix)
			if ordinary != local && typed.Scope().Lookup(ordinary) != nil {
				names.nativeToLocal[native] = "" // An alias cannot shadow an independent ordinary declaration.
			}
		}
	}
	return names, nil
}

// The spelling pass is also a cost query at capture time. Its output is not
// a declaration or compiler witness; the typed pass above remains mandatory.
func numericalGoLinknameSpellings(syntax []*ast.File, pkg string) (numericalGoLinknames, error) {
	names := numericalGoLinknames{localToNative: make(map[string]string),
		nativeToLocal: make(map[string]string), standard: make(map[string]bool)}
	for _, file := range syntax {
		if file == nil {
			return names, numericalSBContext("linkname candidate omitted an original Go file")
		}
		unsafeImported := false
		for _, spec := range file.Imports {
			if spec == nil || spec.Path == nil {
				return names, numericalSBContext("linkname candidate has incomplete import syntax")
			}
			path, err := strconv.Unquote(spec.Path.Value)
			unsafeImported = unsafeImported || err == nil && path == "unsafe"
		}
		for _, group := range file.Comments {
			if group == nil {
				return names, numericalSBContext("linkname candidate has incomplete comment syntax")
			}
			for _, comment := range group.List {
				if comment == nil {
					return names, numericalSBContext("linkname candidate omitted a directive")
				}
				text := strings.TrimPrefix(comment.Text, "//")
				if !strings.HasPrefix(text, "go:linkname ") && !strings.HasPrefix(text, "go:linknamestd ") {
					continue
				}
				fields := strings.Fields(text)
				if !unsafeImported || len(fields) < 2 || len(fields) > 3 || !token.IsIdentifier(fields[1]) {
					return names, numericalSBContext("linkname candidate lacks exact fields/file unsafe import")
				}
				local := fields[1]
				if _, duplicate := names.localToNative[local]; duplicate {
					return names, numericalSBContext("linkname repeats its local declaration")
				}
				remote := gosym.PackagePrefix(pkg) + "." + local
				if len(fields) == 3 {
					remote = fields[2]
				}
				if strings.Contains(remote, "[") && strings.Contains(remote, "]") {
					return names, numericalSBContext("linkname instantiation needs a separate compiler role")
				}
				names.localToNative[local], names.standard[local] = remote, fields[0] == "go:linknamestd"
				if _, exists := names.nativeToLocal[remote]; exists {
					names.nativeToLocal[remote] = ""
				} else {
					names.nativeToLocal[remote] = local
				}
			}
		}
	}
	return names, nil
}

type numericalSourceDeclaration struct {
	local string
	abi   uint16
	entry bool
}

type numericalCompilerAliasWitness struct {
	ABI      uint16
	Standard bool
}

func (names numericalGoLinknames) declaration(native, pkg string, abi uint16, aliases map[string]numericalCompilerAliasWitness) (string, bool) {
	if local, found := names.nativeToLocal[native]; found {
		if local == "" || !names.functions[local] {
			return "", false
		}
		if native != gosym.PackagePrefix(pkg)+"."+local {
			witness, observed := aliases[native]
			return local, observed && witness.ABI == abi && witness.Standard == names.standard[local]
		}
		return local, true
	}
	if !strings.HasPrefix(native, gosym.PackagePrefix(pkg)+".") {
		return "", false
	}
	local := strings.TrimPrefix(native, gosym.PackagePrefix(pkg)+".")
	if remote, renamed := names.localToNative[local]; renamed && remote != native {
		return "", false
	}
	return local, true
}

func numericalTypedSourceDeclarations(file *File, pkg, arch string, role numericalSBSourceRole,
	names numericalGoLinknames, aliases map[string]numericalCompilerAliasWitness,
) (map[string]numericalSourceDeclaration, map[string]numericalSourceDeclaration, error) {
	controls, err := numericalDirectTailRoles(file)
	if err != nil {
		return nil, nil, err
	}
	entries, terminals := make(map[string]numericalSourceDeclaration), make(map[string]numericalSourceDeclaration)
	add := func(symbol string, terminal bool) error {
		native, abi, valid := numericalFunctionSourceIdentity(symbol, pkg, arch, role)
		local, declared := names.declaration(native, pkg, abi, aliases)
		if !valid || !declared {
			return numericalSBContext("numerical source lacks its exact Go declaration/compiler/native association")
		}
		declaration := numericalSourceDeclaration{local: local, abi: abi, entry: !terminal}
		if prior, exists := entries[native]; exists {
			if !terminal || prior.local != local || prior.abi != abi {
				return numericalSBContext("numerical source repeats or changes its native declaration")
			}
			declaration.entry = prior.entry
		}
		if terminal {
			terminals[native] = declaration
		}
		entries[native] = declaration
		return nil
	}
	for _, fn := range file.Funcs {
		if strings.HasSuffix(fn.Sym, "<>") && len(controls) != 0 {
			continue
		}
		if err := add(fn.Sym, false); err != nil {
			return nil, nil, err
		}
	}
	for _, symbol := range controls {
		if !strings.HasSuffix(symbol, "<>") {
			if err := add(symbol, true); err != nil {
				return nil, nil, err
			}
		}
	}
	return entries, terminals, nil
}
