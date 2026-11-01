package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func (source *GoARM64ByteCarrierSource) bindNative(ctx context.Context, environment map[string]string) error {
	guard := source.guard
	// This is an observation of the actual ordinary driver namespace, not a
	// request-controlled alias or an entry capability. Both tools use pkgPath.
	driver, err := guard.read(filepath.Join(guard.env["GOROOT"], "src/cmd/go/internal/work/gc.go"))
	if err != nil {
		return err
	}
	const ordinaryPackageRule = `func pkgPath(a *Action) string {
	p := a.Package
	ppath := p.ImportPath
	if cfg.BuildBuildmode == "plugin" {
		ppath = pluginPath(a)
	} else if p.Name == "main" && !p.Internal.ForceLibrary {
		ppath = "main"
	}
	return ppath
}`
	if !bytes.Contains(driver, []byte(ordinaryPackageRule)) ||
		!bytes.Contains(driver, []byte("defaultGcFlags := []string{\"-p\", pkgpath}")) ||
		!bytes.Contains(driver, []byte("base.Tool(\"asm\"), \"-p\", pkgpath")) {
		return arm64ByteCarrierContext("ordinary compiler/assembler package namespace rule differs")
	}
	nativePackage := source.request.PackagePath
	if guard.selection.Name == "main" {
		nativePackage = "main"
	}
	source.report.NativePackagePath = nativePackage
	builtins, err := guard.read(filepath.Join(guard.env["GOROOT"], "src/cmd/internal/goobj/builtinlist.go"))
	if err != nil {
		return err
	}
	source.report.OriginalArchive, err = guard.read(guard.selection.Export)
	if err != nil {
		return err
	}
	source.report.Archive, err = gostaticstorage.ObserveARM64AssemblyArchive(source.report.OriginalArchive, builtins, source.request.Target, guard.selection.SFiles)
	if err != nil {
		return arm64ByteCarrierContext("complete actual compiler/archive role: %v", err)
	}
	goos, _, _ := strings.Cut(source.request.Target, "/")
	output := filepath.Join(guard.owned, "original.o")
	arguments := []string{"tool", "asm", "-S", "-p", nativePackage,
		"-I", source.request.Directory, "-I", filepath.Join(guard.env["GOROOT"], "pkg/include")}
	for _, define := range GoAssemblerDefinesWithEnv(goos, "arm64", environment) {
		arguments = append(arguments, "-D", define)
	}
	arguments = append(arguments, "-o", output, filepath.Join(source.request.Directory, source.request.AssemblyFile))
	source.report.OriginalListing, err = guard.run(ctx, arguments...)
	if err != nil {
		return arm64ByteCarrierContext("actual original assembler command: %v", err)
	}
	source.record(source.report.OriginalListing, arguments...)
	source.report.OriginalObject, err = guard.read(output)
	if err != nil {
		return err
	}
	source.report.Standalone, err = gostaticstorage.ObserveARM64AssemblyText(source.report.OriginalObject, builtins, source.request.Target)
	if err != nil || len(source.report.Standalone) != len(source.file.Funcs) {
		return arm64ByteCarrierContext("complete original TEXT source inventory differs: %v", err)
	}
	archived := source.report.Archive[2].Texts
	if len(archived) != len(source.report.Standalone) {
		return arm64ByteCarrierContext("archive/standalone TEXT inventory differs")
	}
	texts := make(map[string]gostaticstorage.TextRecord)
	functions := make(map[string]Func)
	for ordinal, fn := range source.file.Funcs {
		text, prior := source.report.Standalone[ordinal], archived[ordinal]
		name := numericalNativeName(fn.Sym, nativePackage)
		if text.Name != name || text.ABI != 0 || text.Name != prior.Name || text.ABI != prior.ABI ||
			text.Size != prior.Size || !bytes.Equal(text.Code, prior.Code) || !numericalRelocationEqual(text.Relocations, prior.Relocations) ||
			len(text.Code)%4 != 0 || len(text.Positions) == 0 || len(prior.Positions) == 0 {
			return arm64ByteCarrierContext("complete original source/standalone/archive instruction join differs")
		}
		texts[name], functions[name] = text, fn
	}
	// Retain every original compiler entry, not just the hand-written callee.
	// Requiring the actual ABIInternal wrapper does not assert that arbitrary
	// future callers or code-address entry paths are supported by LLVM.
	entries := make(map[string]bool)
	for _, text := range source.report.Archive[1].Texts {
		if text.ABI == 1 {
			entries[text.Name] = true
		}
	}
	for name := range source.report.Declarations {
		if !entries[nativePackage+"."+name] {
			return arm64ByteCarrierContext("original complete compiler entry is missing: %s", name)
		}
	}
	for _, fn := range source.file.Funcs {
		callerName := numericalNativeName(fn.Sym, nativePackage)
		caller := texts[callerName]
		var calls []struct {
			ordinal int
			name    string
		}
		for ordinal, instruction := range fn.Instrs {
			if instruction.Op == "TEXT" {
				continue
			}
			if instruction.Op == "CALL" {
				if len(instruction.Args) != 1 || instruction.Args[0].Kind != OpSym {
					return arm64ByteCarrierContext("indirect/native-address call lacks a closed source target")
				}
				base, offset, valid := parseSBRef(instruction.Args[0].Sym)
				name := numericalNativeName(base, nativePackage)
				if !valid || offset != 0 || texts[name].Name == "" {
					return arm64ByteCarrierContext("external/offset call lacks a same-file source target")
				}
				calls = append(calls, struct {
					ordinal int
					name    string
				}{ordinal, name})
				continue
			}
			if instruction.Op != "RET" {
				if bits, _ := arm64ScalarMemoryBits(instruction.Op); bits == 0 {
					return arm64ByteCarrierContext("first observation requires the complete scalar move/call source role: %s", instruction.Op)
				}
			}
			for _, operand := range instruction.Args {
				if operand.Kind == OpSym || operand.Kind == OpFPAddr || operand.Kind == OpImm && (operand.ImmRaw != "" || operand.ImmIsFloat) ||
					operand.Kind == OpMem && (operand.Mem.Sym != "" || operand.Mem.Index != "" || operand.Mem.Base != "RSP") ||
					operand.Kind == OpReg && (operand.Reg == "RSP" || operand.Reg == "R29" || operand.Reg == "R30" || operand.Reg == "g") {
					return arm64ByteCarrierContext("code/storage/frame-address escape requires a separate producer")
				}
			}
		}
		if len(caller.Relocations) != len(calls) {
			return arm64ByteCarrierContext("original call/source relocation inventory differs")
		}
		for ordinal, relocation := range caller.Relocations {
			call := calls[ordinal]
			callee := texts[call.name]
			if relocation.Type != 9 || relocation.Size != 4 || relocation.Add != 0 || relocation.Offset < 0 || relocation.Offset%4 != 0 ||
				relocation.Offset+8 > int64(len(caller.Code)) || relocation.Target.Name != callee.Name ||
				!relocation.Target.ABIKnown || relocation.Target.ABI != 0 ||
				binary.LittleEndian.Uint32(caller.Code[relocation.Offset:])&0xfc000000 != 0x94000000 {
				return arm64ByteCarrierContext("actual original direct-call/ABI/continuation record differs")
			}
			position, err := source.callPosition(caller, relocation.Offset, fn.Instrs[call.ordinal].Raw)
			if err != nil {
				return err
			}
			// The initial native-width result class is a leaf ABI0 callee. Its
			// unchanged SP is the original caller's SP at this exact call. Keep
			// actual memory effects as observations, not allocated padding fields.
			calleeFn := functions[callee.Name]
			if calleeFn.FrameSize != 0 || len(callee.Relocations) != 0 {
				return arm64ByteCarrierContext("callee native frame/calls need a separate SP transition observation")
			}
			reads, writes, err := arm64ByteCarrierLeafMemory(callee)
			if err != nil {
				return err
			}
			declaration := source.declarations[strings.TrimPrefix(callee.Name, nativePackage+".")]
			for _, read := range reads {
				matched := false
				for _, field := range declaration.Frame.Params {
					matched = matched || read.Offset == field.Offset+8 && read.Bytes == frameTypeSize(field.Type, 8)
				}
				if !matched {
					return arm64ByteCarrierContext("native parameter bytes need a separate initialized caller observation")
				}
			}
			for _, write := range writes {
				matched := false
				for _, field := range declaration.Frame.Results {
					matched = matched || write.Offset == field.Offset+8 && write.Bytes >= frameTypeSize(field.Type, 8)
				}
				if !matched {
					return arm64ByteCarrierContext("native store is not the declared-result-start rule class")
				}
			}
			source.report.Calls = append(source.report.Calls, arm64ByteCarrierCall{
				Caller: caller.Name, Callee: callee.Name, SourceInstruction: call.ordinal,
				CallPC: relocation.Offset, ContinuationPC: relocation.Offset + 4,
				CallerCode: sha256.Sum256(caller.Code), CalleeCode: sha256.Sum256(callee.Code),
				OriginalCall: relocation, Position: position, CalleeSPReads: reads, SPWrites: writes,
			})
		}
		physicalCalls := 0
		for pc := 0; pc < len(caller.Code); pc += 4 {
			if binary.LittleEndian.Uint32(caller.Code[pc:])&0xfc000000 == 0x94000000 {
				physicalCalls++
			}
		}
		if physicalCalls != len(calls) {
			return arm64ByteCarrierContext("native direct calls are not exhausted by original source relocations")
		}
	}
	if len(source.report.Calls) == 0 {
		return arm64ByteCarrierContext("source has no actual same-file caller/callee region to observe")
	}
	return nil
}

func (source *GoARM64ByteCarrierSource) callPosition(text gostaticstorage.TextRecord, pc int64, raw string) (gostaticstorage.TextPosition, error) {
	filename := filepath.Join(source.request.Directory, source.request.AssemblyFile)
	lines := strings.Split(string(source.report.Sources[source.request.AssemblyFile]), "\n")
	for _, position := range text.Positions {
		// The original Go object uses slash spelling on Windows. Decode only
		// that spelling, without granting an SDK alias or cleaning source paths.
		physical, valid := originalGoObjectSourcePath(position.File, "")
		if valid && position.Start <= pc && position.End >= pc+4 && physical == filename && position.Line > 0 && int(position.Line) <= len(lines) &&
			strings.TrimSpace(lines[position.Line-1]) == raw {
			return position, nil
		}
	}
	return gostaticstorage.TextPosition{}, arm64ByteCarrierContext("actual call/source ordinal/physical PC mapping differs")
}

func arm64ByteCarrierLeafMemory(text gostaticstorage.TextRecord) (reads, writes []arm64ByteCarrierMemory, result error) {
	returned := false
	for pc := 0; pc < len(text.Code); pc += 4 {
		word := binary.LittleEndian.Uint32(text.Code[pc:])
		if returned && word == 0 {
			continue // retained original alignment bytes, never executable authority
		}
		if word == 0xd65f03c0 && !returned {
			returned = true
			continue
		}
		// Original scalar unsigned-offset loads/stores only. A leaf has no SP
		// adjustment, writeback, aliases, hidden call or arbitrary native entry.
		if returned || word&0x3b000000 != 0x39000000 || word&(1<<26) != 0 || (word>>5)&31 != 31 || (word>>22)&3 > 1 {
			return nil, nil, arm64ByteCarrierContext("native leaf contains an unobserved SP transition/effect")
		}
		width := int64(1) << (word >> 30)
		memory := arm64ByteCarrierMemory{PC: int64(pc), Offset: int64(word>>10&4095) * width, Bytes: width, Instruction: word}
		if word&(1<<22) != 0 {
			reads = append(reads, memory)
		} else {
			writes = append(writes, memory)
		}
	}
	if !returned || len(reads) == 0 || len(writes) == 0 {
		return nil, nil, arm64ByteCarrierContext("native caller region lacks a complete input/store/return observation")
	}
	return reads, writes, nil
}
