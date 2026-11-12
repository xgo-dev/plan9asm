package sdkfrontend

import (
	"context"
	"errors"
	"go/types"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

type OwnerRequest struct {
	PackagePath string
	CPU         bool
	Variables   []plan9asm.GoNumericalStorageReference
}

// OwnerRequests is a cost query over actual typed package scopes. It has no
// numerical type/storage/read grammar: the separate SDK producer authenticates
// the complete original Go definition, pointer-free type and compiler record.
// Private assembly data and functions never become Go-defined variables here.
func OwnerRequests(pkg *Package, file *plan9asm.File, target string) []OwnerRequest {
	if pkg == nil || pkg.Module || file == nil || file.Arch != plan9asm.ArchAMD64 ||
		!gostaticstorage.X86SDKTarget(target) {
		return nil
	}
	packages := make(map[string]*Package)
	var visit func(*Package)
	visit = func(current *Package) {
		if current == nil || current.Module || len(packages) >= 256 || packages[current.Path] != nil {
			return
		}
		packages[current.Path] = current
		for _, dependency := range current.Imports {
			visit(dependency)
		}
	}
	visit(pkg)
	requests := make(map[string]*OwnerRequest)
	variables := make(map[string]bool)
	for _, fn := range file.Funcs {
		for _, instruction := range fn.Instrs {
			for _, operand := range instruction.Args {
				if operand.Kind != plan9asm.OpSym || !strings.HasSuffix(operand.Sym, "(SB)") {
					continue
				}
				name := strings.TrimSuffix(operand.Sym, "(SB)")
				if offset := strings.IndexAny(name, "+-"); offset >= 0 {
					name = name[:offset]
				}
				name = Resolve(pkg.Path, name)
				if strings.ContainsAny(name, "<>") || variables[name] {
					continue
				}
				dot := strings.LastIndexByte(name, '.')
				if dot < 1 || dot == len(name)-1 {
					continue
				}
				path, symbol := name[:dot], name[dot+1:]
				cpu := name == "internal/cpu.X86"
				if !cpu {
					owner := packages[path]
					if owner == nil || owner.Types == nil || owner.Types.Path() != path || owner.Types.Scope() == nil {
						continue
					}
					variable, valid := owner.Types.Scope().Lookup(symbol).(*types.Var)
					if !valid || variable.IsField() || variable.Pkg() != owner.Types {
						continue
					}
				}
				key := path
				if cpu {
					key += "/cpu"
				}
				if requests[key] == nil {
					requests[key] = &OwnerRequest{PackagePath: path, CPU: cpu}
				}
				requests[key].Variables = append(requests[key].Variables,
					plan9asm.GoNumericalStorageReference{PackagePath: path, Name: symbol})
				variables[name] = true
			}
		}
	}
	keys := make([]string, 0, len(requests))
	for key := range requests {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]OwnerRequest, 0, len(keys))
	for _, key := range keys {
		request := requests[key]
		sort.Slice(request.Variables, func(i, j int) bool { return request.Variables[i].Name < request.Variables[j].Name })
		result = append(result, *request)
	}
	return result
}

func NumericalOwnerRequested(pkg *Package, file *plan9asm.File, target string) bool {
	return len(OwnerRequests(pkg, file, target)) != 0
}

func captureOwners(ctx context.Context, request CaptureRequest, file *plan9asm.File) (_ []*plan9asm.GoNumericalStorageOwner, _ func() error, result error) {
	queries := OwnerRequests(request.Package, file, request.Target)
	if len(queries) == 0 || len(queries) > 8 {
		return nil, nil, contextError("source lacks a bounded typed SDK variable query")
	}
	var owners []*plan9asm.GoNumericalStorageOwner
	close := func() error {
		for index := len(owners) - 1; index >= 0; index-- {
			owners[index].Close()
		}
		owners = nil
		return nil
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, close())
		}
	}()
	for _, query := range queries {
		owner, err := plan9asm.CaptureGoNumericalStorageOwner(ctx, plan9asm.GoNumericalStorageCaptureRequest{
			GoBinary: request.GoBinary, Directory: filepath.Join(request.Root, "src", filepath.FromSlash(query.PackagePath)),
			PackagePath: query.PackagePath, Target: request.Target, Environment: request.Environment,
			Variables: query.Variables, SDKCPU: query.CPU, SDKGlobals: !query.CPU,
		})
		if err != nil {
			return nil, nil, err
		}
		owners = append(owners, owner)
	}
	return owners, close, nil
}
