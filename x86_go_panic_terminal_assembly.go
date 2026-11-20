package plan9asm

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/gosym"
)

// An association query result is not a terminal capability. The ordinal is in
// the complete original function, before any translator control-flow rewrite.
type x86GoPanicTerminalAssemblyCall struct {
	file, function, target string
	ordinal                int
	instruction            Instr
	relocation             gostaticstorage.TextRelocation
}

func x86GoPanicTerminalAssemblyCalls(pkg GoPackage, bodies []x86GoPanicTerminalCompilerBody,
	objects *gostaticstorage.SDKASMDataObservation, cpp []AssemblyCPPObservation, positions []sdkCPPPositionObservation,
	root string, budget *x86ResultFlowBudget,
) ([]x86GoPanicTerminalAssemblyCall, error) {
	fail := func(reason string) ([]x86GoPanicTerminalAssemblyCall, error) {
		return nil, sdkASMDataContext("panic CALL association: %s", reason)
	}
	if budget == nil || budget.visits >= 16384 || budget.bytes >= 64<<20 || objects == nil || pkg.SourceSelection == nil ||
		objects.Protocol != gostaticstorage.ASMDataCPPProtocol || objects.Target != "linux/386" || objects.PackagePath != pkg.Path ||
		len(objects.Sources) == 0 || len(objects.Sources) != len(cpp) || len(cpp) != len(positions) ||
		len(objects.Members) != len(cpp)+2 || len(pkg.SourceSelection.SelectedAssemblyFiles) != len(cpp) || len(pkg.SourceSelection.Assembly) != len(cpp) {
		return fail("missing complete source/member/compiler/shared-budget identity")
	}
	declarations, err := x86GoPanicTerminalDeclarations(pkg)
	if err != nil {
		return nil, err
	}
	declared := make(map[string]x86GoPanicTerminalDeclaration)
	for _, declaration := range declarations {
		declared[declaration.nativeName] = declaration
	}
	callees := make(map[string]bool)
	for _, body := range bodies {
		name := body.declaration.nativeName
		if body.assemblyABI != 0 || body.text.ABI != 1 || body.text.Name != name || callees[name] || declared[name] != body.declaration {
			return fail("compiler body differs from its exact selected Go declaration")
		}
		matches := 0
		for _, text := range objects.Members[1].Texts {
			if text.Name == name && reflect.DeepEqual(text, body.text) {
				matches++
			}
		}
		if matches != 1 {
			return fail("compiler body differs from its actual complete archive member")
		}
		callees[name] = true
	}
	var result []x86GoPanicTerminalAssemblyCall
	for sourceOrdinal, source := range objects.Sources {
		filename := pkg.SourceSelection.SelectedAssemblyFiles[sourceOrdinal]
		file := pkg.SourceSelection.Assembly[filename]
		if !filepath.IsAbs(filename) || filepath.Clean(filename) != filename || filepath.Base(filename) != source.Name || file == nil {
			return fail("source route differs from its complete selected assembly")
		}
		reparsed, err := Parse(ArchAMD64, cpp[sourceOrdinal].Output)
		if err != nil || !reflect.DeepEqual(reparsed, file) {
			return fail("complete original instruction tuple differs from its parsed CPP")
		}
		programBytes := len(cpp[sourceOrdinal].Output) + len(positions[sourceOrdinal].Mapped)
		// This noniterative query charges actual retained source bytes. The
		// CFG's separate eight-copy initial-state reservation is not a byte
		// multiplier here; subsequent flow replay shares the same64MiB cap.
		if programBytes > (64<<20)-budget.bytes {
			return fail("combined source-graph byte budget exhausted")
		}
		budget.bytes += programBytes
		mapped, err := numericalSDKLiteralSourcePositions(file, cpp[sourceOrdinal].Output, positions[sourceOrdinal])
		if err != nil {
			return nil, err
		}
		if !reflect.DeepEqual(source.Original.Texts, source.Expanded.Texts) || !reflect.DeepEqual(source.Original.Texts, objects.Members[sourceOrdinal+2].Texts) {
			return fail("original/mapped/archive complete native TEXT records differ")
		}
		order, err := gostaticstorage.ASMSourceTextOrder([]byte(cpp[sourceOrdinal].Output), pkg.Path, source.Original)
		if err != nil || len(order) != len(file.Funcs) || !reflect.DeepEqual(order, source.TextOrder) {
			return fail("source TEXT order differs from the actual complete object namespace")
		}
		for functionOrdinal, fn := range file.Funcs {
			if len(fn.Instrs) > 16384-budget.visits {
				return fail("combined source-graph visit budget exhausted")
			}
			budget.visits += len(fn.Instrs)
			var calls []int
			candidate := false
			for ordinal, ins := range fn.Instrs {
				if ins.Op != "CALL" {
					continue
				}
				calls = append(calls, ordinal)
				if name, valid := x86GoPanicTerminalCallTarget(ins, pkg.Path); valid && callees[name] {
					candidate = true
				}
			}
			if !candidate {
				continue // No facts are granted for ordinary unrelated functions.
			}
			association := order[functionOrdinal]
			text := source.Original.Texts[association.ObjectOrdinal]
			if text.ABI != 0 || text.Size != int64(len(text.Code)) || len(text.Code) == 0 {
				return fail("original caller lacks its exact ABI0 code extent")
			}
			var relocations []gostaticstorage.TextRelocation
			for _, relocation := range text.Relocations {
				if relocation.Type == 7 { // The selected source pins R_CALL independently.
					relocations = append(relocations, relocation)
				}
			}
			if len(relocations) != len(calls) {
				return fail("complete source/native CALL inventories differ")
			}
			lastPC := int64(-1)
			for callOrdinal, ordinal := range calls {
				ins, relocation := fn.Instrs[ordinal], relocations[callOrdinal]
				target, valid := x86GoPanicTerminalCallTarget(ins, pkg.Path)
				pc := relocation.Offset - 1
				if !valid || !relocation.Target.ABIKnown || relocation.Target.ABI != 0 || relocation.Target.Name != target ||
					relocation.Size != 4 || relocation.Add != 0 || pc < 0 || pc <= lastPC || pc > text.Size-5 || text.Code[pc] != 0xe8 {
					return fail("source CALL target/ABI/order differs from its original E8 relocation")
				}
				for _, other := range text.Relocations {
					if other != relocation && other.Size != 0 && other.Offset < pc+5 && other.Offset+other.Size > pc {
						return fail("original CALL overlaps another native relocation")
					}
				}
				matchedPosition := false
				for _, position := range text.Positions {
					if position.Start <= pc && position.End >= pc+5 {
						physical, known := originalGoObjectSourcePath(position.File, root)
						matchedPosition = known && fmt.Sprintf("%s:%d", physical, position.Line) == mapped[functionOrdinal][ordinal]
						break
					}
				}
				if !matchedPosition {
					return fail("original native CALL does not cover its exact source node position")
				}
				lastPC = pc
				if callees[target] {
					ins.Args = append([]Operand(nil), ins.Args...)
					result = append(result, x86GoPanicTerminalAssemblyCall{file: filename, function: fn.Sym, target: target,
						ordinal: ordinal, instruction: ins, relocation: relocation})
				}
			}
		}
	}
	return result, nil
}

func x86GoPanicTerminalCallTarget(ins Instr, pkg string) (string, bool) {
	if ins.Op != "CALL" || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym || !strings.HasSuffix(ins.Args[0].Sym, "(SB)") {
		return "", false
	}
	name, offset := splitSymPlusOff(strings.TrimSuffix(ins.Args[0].Sym, "(SB)"))
	if offset != 0 {
		return "", false
	}
	native, abi, valid := numericalFunctionSourceIdentity(name, gosym.PackagePrefix(pkg), "386", numericalSBSDKSource)
	return native, valid && abi == 0
}
