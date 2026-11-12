package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"golang.org/x/arch/x86/x86asm"
)

func verifyGoAMD64FrameNumericalRequest(ctx context.Context, pkg GoPackage, request GoAMD64FrameCaptureRequest) error {
	binding := request.NumericalReads
	if err := binding.verify(); err != nil {
		return err
	}
	if ctx != binding.context || request.Target != "linux/amd64" || request.Target != binding.source.request.Target ||
		request.GoBinary != binding.source.request.GoBinary || request.Directory != binding.source.request.Directory ||
		request.AssemblyFile != binding.source.request.AssemblyFile || pkg.Path != binding.packageInput.Path ||
		pkg.Types != binding.originalTypes || pkg.SourceSelection != nil || !numericalSameImports(pkg.Imports, binding.originalImports) {
		return goAMD64FrameContext("numerical frame join has foreign complete source/package/tool/profile/context")
	}
	environment := func(values []string) (map[string]string, bool) {
		result := make(map[string]string, len(values))
		for _, pair := range values {
			key, value, valid := strings.Cut(pair, "=")
			if _, duplicate := result[key]; !valid || key == "" || duplicate {
				return nil, false
			}
			result[key] = value
		}
		return result, true
	}
	provided, valid := environment(request.Environment)
	original, originalValid := environment(binding.source.request.Environment)
	if !valid || !originalValid || !reflect.DeepEqual(provided, original) {
		return goAMD64FrameContext("numerical frame join command environment differs")
	}
	binding.source.mu.Lock()
	err := numericalDeclarationSyntax(binding.source, pkg)
	binding.source.mu.Unlock()
	return err
}

func (source *GoAMD64FrameSource) revokeNumericalFrame() {
	source.mu.Lock()
	source.ready = false
	source.mu.Unlock()
}

// No Frame lock survives an external numerical/owner verification. Close can
// linearize during the independent frame round, but its final guard must fail.
func (source *GoAMD64FrameSource) verifyNumericalFrameInputs(ctx context.Context) error {
	source.mu.Lock()
	request, binding, seal, pkg, ready, origin := source.request, source.numericalBinding, source.numericalSeal, source.numericalPackage, source.ready, source.numericalOrigin
	selection := source.selection
	inputs := make(map[string][32]byte, len(source.inputs))
	for name, sum := range source.inputs {
		inputs[name] = sum
	}
	environment := make(map[string]string, len(source.env))
	for name, value := range source.env {
		environment[name] = value
	}
	source.mu.Unlock()
	if binding == nil && request.NumericalReads == nil && origin == nil {
		return nil // Preserve every existing unbound/default role.
	}
	if ctx == nil {
		return goAMD64FrameContext("numerical frame verification requires a live context")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("verify numerical frame context: %w", err)
	}
	if !ready || origin != source || binding == nil || request.NumericalReads != binding || binding.seal != seal {
		return goAMD64FrameContext("numerical frame generation/token is closed, missing or changed")
	}
	if err := verifyGoAMD64FrameNumericalRequest(binding.context, pkg, request); err != nil {
		return err
	}
	binding.source.mu.Lock()
	actualSelection := binding.source.guard.selection
	actualEnvironment := binding.source.guard.env
	var mismatch bool
	for _, key := range []string{"GOROOT", "GOTOOLDIR", "GOVERSION", "GOOS", "GOARCH", "GOAMD64", "GOFLAGS", "GOEXPERIMENT", "GOCACHE"} {
		mismatch = mismatch || environment[key] != actualEnvironment[key]
	}
	for name, data := range binding.source.native.Sources {
		sum, exists := inputs[name]
		mismatch = mismatch || !exists || sum != sha256.Sum256(data)
	}
	binding.source.mu.Unlock()
	if mismatch || !reflect.DeepEqual(selection, actualSelection) || len(selection.SFiles) != 1 || selection.SFiles[0] != request.AssemblyFile {
		return goAMD64FrameContext("independent complete numerical/frame source selection or tool bytes differ")
	}
	// Catch Close that linearized while the independent owner checks ran.
	source.mu.Lock()
	live := source.ready && source.request.NumericalReads == binding && source.numericalBinding == binding
	source.mu.Unlock()
	if !live {
		return goAMD64FrameContext("numerical frame closed during complete verification")
	}
	return nil
}

func (source *GoAMD64FrameSource) numericalFrameObject(object string, file *File) ([]gostaticstorage.TextRecord, error) {
	data, err := source.read(object)
	if err != nil {
		return nil, err
	}
	builtin, err := source.read(filepath.Join(source.env["GOROOT"], "src/cmd/internal/goobj/builtinlist.go"))
	if err != nil {
		return nil, err
	}
	texts, err := gostaticstorage.ObserveX86AssemblyText(data, builtin, source.request.Target)
	if err != nil {
		return nil, err
	}
	binding := source.numericalBinding
	if err := binding.verify(); err != nil {
		return nil, err
	}
	fingerprint, err := x86CallerSourceFingerprint(file)
	if err != nil || fingerprint != binding.file {
		return nil, goAMD64FrameContext("independent numerical frame parsed source differs")
	}
	if err := goAMD64FrameNumericalObjectJoin(texts, binding.source.native.OriginalText, binding.reads); err != nil {
		return nil, err
	}
	return texts, nil
}

// Both TEXT collections came from independently decoded actual original
// objects. Whole records (including positions and auxiliaries) must agree;
// every relocation must also be exactly one certified scalar read's field.
func goAMD64FrameNumericalObjectJoin(texts, numerical []gostaticstorage.TextRecord, reads []numericalSBReadFact) error {
	if len(texts) == 0 || !reflect.DeepEqual(texts, numerical) {
		return goAMD64FrameContext("independent complete TEXT/code/source/ABI0/relocations differ")
	}
	readIndex := 0
	for _, text := range texts {
		if text.ABI != 0 || text.Size != int64(len(text.Code)) {
			return goAMD64FrameContext("numerical frame has foreign ABI0 or incomplete code")
		}
		lastPC, lastInstruction := int64(-1), -1
		for _, relocation := range text.Relocations {
			if readIndex >= len(reads) {
				return goAMD64FrameContext("missing complete numerical frame read")
			}
			read := reads[readIndex]
			if read.Function != text.Name || !reflect.DeepEqual(read.Relocation, relocation) ||
				read.PC <= lastPC || read.Instruction <= lastInstruction || read.PC >= text.Size ||
				read.Variable.NativeName != relocation.Target.Name {
				return goAMD64FrameContext("foreign, duplicate or reordered numerical frame read/owner")
			}
			native, err := x86asm.Decode(text.Code[read.PC:], 64)
			if err != nil || native.Op == 0 || native.Len <= 0 || read.PC+int64(native.Len) > text.Size ||
				!bytes.Equal(read.Code, text.Code[read.PC:read.PC+int64(native.Len)]) || native.MemBytes != int(read.Width) {
				return goAMD64FrameContext("numerical frame instruction boundary/code/width differs")
			}
			actual, offset, err := numericalInstructionRelocation(text, read.PC, native, "amd64")
			if err != nil || !reflect.DeepEqual(actual, relocation) || offset != read.Offset {
				return goAMD64FrameContext("numerical frame PC displacement/type/target/ABI/addend differs")
			}
			lastPC, lastInstruction = read.PC, read.Instruction
			readIndex++
		}
	}
	if readIndex != len(reads) {
		return goAMD64FrameContext("numerical frame omitted a certified original read")
	}
	return nil
}

func goAMD64FrameNumericalRelocationLine(relocation gostaticstorage.TextRelocation) string {
	if relocation.Type != 14 || relocation.Size != 4 || !relocation.Target.ABIKnown || relocation.Target.ABI != 0 {
		return "" // No other listing relocation has been authorized.
	}
	line := fmt.Sprintf("rel %d+%d t=R_PCREL %s", relocation.Offset, relocation.Size, relocation.Target.Name)
	if relocation.Add != 0 {
		line += fmt.Sprintf("%+d", relocation.Add)
	}
	return line
}
