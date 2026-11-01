package plan9asm

import (
	"bytes"
	"fmt"
	"go/types"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// This classifies original source nodes, not callable ABIs or initialized
// inputs. A leaf cannot observe its physical frame or CALL's stack change.
// A nonzero frame's automatic BP/FLAGS effects are checked independently.
func goAMD64FramePrivateLeaves(file *File, pkg GoPackage) (map[string]bool, error) {
	if file == nil || pkg.Types == nil {
		return nil, goAMD64FrameContext("private source roles need complete parsed source and actual types")
	}
	leaves := make(map[string]bool)
	for _, fn := range file.Funcs {
		if _, declared := pkg.Types.Scope().Lookup(strings.TrimPrefix(fn.Sym, "·")).(*types.Func); declared {
			continue
		}
		name := strings.TrimSuffix(fn.Sym, "<>")
		if name == "" || strings.ContainsAny(name, "·./<>") || fn.FrameSize < 0 || fn.FrameSize > 64<<10 ||
			fn.FrameSize%8 != 0 || fn.ArgSize != 0 || len(fn.Instrs) == 0 {
			return nil, goAMD64FrameContext("undeclared TEXT is not a bounded same-source leaf: %s", fn.Sym)
		}
		_, header := splitOpcode(fn.Instrs[0].Raw)
		parts := strings.Split(header, ",")
		if len(parts) != 3 {
			return nil, goAMD64FrameContext("private leaf needs explicit original NOSPLIT flags")
		}
		flags, err := nativeFlags(parts[1], "NOSPLIT", "NOFRAME")
		if err != nil || !flags["NOSPLIT"] {
			return nil, goAMD64FrameContext("private leaf has an unclosed original prologue")
		}
		for _, ins := range fn.Instrs {
			if ins.Op == OpCALL || isX86RawDirective(ins) {
				return nil, goAMD64FrameContext("private leaf has raw or non-leaf effects")
			}
			if _, stack, _ := x86StackWidthProperties(ins, "amd64"); stack {
				return nil, goAMD64FrameContext("private leaf observes implicit stack storage")
			}
			for _, operand := range ins.Args {
				if operand.Kind == OpFP || operand.Kind == OpFPAddr || operand.Kind == OpReg && operand.Reg == SP ||
					operand.Kind == OpMem && (operand.Mem.Base == SP || operand.Mem.Index == SP) {
					return nil, goAMD64FrameContext("private leaf observes its incoming physical frame")
				}
			}
		}
		leaves[fn.Sym] = true
	}
	graph := &x86DirectTailGraph{original: file, helpers: leaves}
	if err := graph.auditReferences(); err != nil {
		return nil, err
	}
	reached := make(map[string]bool)
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			if ins.Op != OpCALL && ins.Op != OpJMP || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
				continue
			}
			name, offset, valid := parseSBRef(ins.Args[0].Sym)
			if valid && offset == 0 && leaves[name] {
				if ins.Op != OpCALL {
					return nil, goAMD64FrameContext("framed root cannot tail-enter a private leaf")
				}
				reached[name] = true
			}
		}
	}
	for name := range leaves {
		if !reached[name] {
			return nil, goAMD64FrameContext("private leaf lacks a same-source declared caller: %s", name)
		}
	}
	return leaves, nil
}

// Reuse the independent complete source/object association. Go orders static
// and nonstatic symbols in separate banks; listings retain source order.
func goAMD64FrameSourceTexts(listing []byte, data *gostaticstorage.AMD64AssemblyData) ([]gostaticstorage.TextRecord, error) {
	if _, err := sdkAMD64FrameNativeRecordsForSource(listing, data.Member.Texts, data.TextOrder); err != nil {
		return nil, err
	}
	texts := make([]gostaticstorage.TextRecord, len(data.TextOrder))
	for index, association := range data.TextOrder {
		texts[index] = data.Member.Texts[association.ObjectOrdinal]
	}
	return texts, nil
}

func goAMD64FrameLocalCallTarget(r gostaticstorage.TextRelocation, texts []gostaticstorage.TextRecord) bool {
	if r.Type != 7 || r.Size != 4 || r.Add != 0 || !r.Target.ABIKnown {
		return false
	}
	for _, text := range texts {
		bank := uint32(2147483647) // PkgIdxNone: non-package definitions.
		if text.Namespace == gostaticstorage.TextSymbolSelf {
			bank = 2147483643
		} else if text.Namespace != gostaticstorage.TextSymbolNonpkgDefinition {
			continue
		}
		if r.Target.Name == text.Name && r.Target.ABI == text.ABI &&
			r.Target.PackageIndex == bank && r.Target.SymbolIndex == text.Relative {
			return true
		}
	}
	return false
}

// Machine CALL fields must match the complete original source call order and
// exact local object target. Generated split calls are outside this projection.
func goAMD64FramePrivateCallPCs(fn goAMD64FrameFunction, original Func, text gostaticstorage.TextRecord,
	leaves map[string]bool, names map[string]string) (map[int]bool, error) {
	var targets []string
	for _, ins := range original.Instrs {
		if ins.Op != OpCALL {
			continue
		}
		if len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
			return nil, goAMD64FrameContext("original CALL lacks a direct leaf target")
		}
		name, offset, valid := parseSBRef(ins.Args[0].Sym)
		if !valid || offset != 0 || !leaves[name] || names[name] == "" {
			return nil, goAMD64FrameContext("original CALL target has no complete private leaf role")
		}
		targets = append(targets, names[name])
	}
	calls := make(map[int]bool)
	for _, relocation := range text.Relocations {
		pc := int(relocation.Offset) - fn.prologue - 1
		if relocation.Type != 7 || pc < 0 || pc >= len(fn.code) {
			continue
		}
		if len(calls) >= len(targets) || relocation.Target.Name != targets[len(calls)] ||
			relocation.Size != 4 || relocation.Add != 0 || pc+5 > len(fn.code) ||
			fn.code[pc] != 0xe8 || !bytes.Equal(fn.code[pc+1:pc+5], []byte{0, 0, 0, 0}) ||
			!strings.Contains(fn.positions[pc], "\tCALL\t") || calls[pc] {
			return nil, goAMD64FrameContext("original source CALL and exact machine relocation differ")
		}
		calls[pc] = true
	}
	if len(calls) != len(targets) {
		return nil, goAMD64FrameContext("original source CALL inventory is incomplete")
	}
	return calls, nil
}

func goAMD64FramePrivateCallRelocation(r gostaticstorage.TextRelocation, data *gostaticstorage.AMD64AssemblyData) string {
	if goAMD64FrameLocalCallTarget(r, data.Member.Texts) {
		return fmt.Sprintf("rel %d+4 t=R_CALL %s+0", r.Offset, r.Target.Name)
	}
	return ""
}
