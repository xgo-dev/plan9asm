package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// The exported fields participate in the numerical source seal. The private
// identities cannot be reconstructed from those diagnostic bytes. This join
// keeps initializer authority separate from the external mutable Go variables.
type numericalSDKLiteralJoin struct {
	Observation     sdkASMDataLiveObservation
	Initializers    sdkReadonlyLiteralDataReport
	SourceOrdinal   int
	owner           *GoX86SDKReadonlyLiteralDataOwner
	source          *GoX86SDKASMDataSource
	ownerGeneration uint64
	ownerSeal       [32]byte
	context         context.Context
	Deadline        time.Time
}

func captureNumericalSDKLiteralJoin(ctx context.Context, request GoX86NumericalReadCaptureRequest, role numericalSBSourceRole) (*numericalSDKLiteralJoin, error) {
	owner := request.ReadonlyLiterals
	if owner == nil {
		return nil, nil
	}
	if role != numericalSBSDKSource || owner.identity != owner {
		return nil, numericalSBContext("literal initializer needs its independent live SDK role")
	}
	if err := owner.Verify(ctx); err != nil {
		return nil, err
	}
	owner.mu.Lock()
	actual, generation, seal := owner.source, owner.generation, owner.seal
	owner.mu.Unlock()
	if actual == nil || actual.identity != actual {
		return nil, numericalSBContext("literal initializer lost its original SDK source")
	}
	profile := actual.request
	if request.GoBinary != profile.GoBinary || request.Directory != profile.Directory ||
		request.PackagePath != profile.PackagePath || request.Target != profile.Target ||
		!reflect.DeepEqual(request.Environment, profile.Environment) {
		return nil, numericalSBContext("literal initializer source/tool/profile differs")
	}
	raw, err := actual.Readback(ctx)
	if err != nil {
		return nil, err
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !reflect.TypeOf(ctx).Comparable() {
		return nil, numericalSBContext("literal numerical join needs one original bounded context")
	}
	joined := &numericalSDKLiteralJoin{owner: owner, source: actual, ownerGeneration: generation, ownerSeal: seal,
		SourceOrdinal: -1, context: ctx, Deadline: deadline}
	if json.Unmarshal(raw, &joined.Observation) != nil || joined.Observation.Objects == nil {
		return nil, numericalSBContext("literal source retained invalid whole observation bytes")
	}
	initializers, err := owner.Readback(ctx)
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(initializers, &joined.Initializers) != nil || sha256.Sum256(initializers) != seal ||
		joined.Initializers.SourceReportSHA256 != sha256.Sum256(raw) ||
		joined.Initializers.Protocol != sdkReadonlyLiteralDataProtocol ||
		joined.Initializers.PackagePath != request.PackagePath || joined.Initializers.Target != request.Target {
		return nil, numericalSBContext("literal initializer differs from its complete live SDK observation")
	}
	for index, selected := range joined.Observation.Objects.Sources {
		if selected.Name == request.AssemblyFile {
			if joined.SourceOrdinal >= 0 {
				return nil, numericalSBContext("literal source repeats its selected assembly identity")
			}
			joined.SourceOrdinal = index
		}
	}
	if joined.SourceOrdinal < 0 || joined.SourceOrdinal >= len(joined.Observation.CPP) ||
		joined.SourceOrdinal >= len(joined.Observation.Positions) ||
		joined.SourceOrdinal >= len(joined.Observation.ObjectInputs.Sources) {
		return nil, numericalSBContext("literal initializer does not own this selected assembly")
	}
	if err := joined.verifyIdentity(request); err != nil {
		return nil, err
	}
	return joined, nil
}

// No context callback or producer operation runs under a numerical source lock.
// This check samples only immutable identities and guarded generation state.
func (joined *numericalSDKLiteralJoin) verifyIdentity(request GoX86NumericalReadCaptureRequest) error {
	if joined == nil || joined.owner == nil || joined.owner.identity != joined.owner ||
		joined.source == nil || joined.source.identity != joined.source || request.ReadonlyLiterals != joined.owner {
		return numericalSBContext("literal owner identity changed")
	}
	owner := joined.owner
	owner.mu.Lock()
	valid := owner.ready && owner.generation == joined.ownerGeneration && owner.seal == joined.ownerSeal &&
		sha256.Sum256(owner.report) == joined.ownerSeal && owner.source == joined.source && owner.originalSource == joined.source
	owner.mu.Unlock()
	if !valid {
		return numericalSBContext("literal initializer generation changed or closed")
	}
	return owner.verifySourceGeneration()
}

func (source *GoX86NumericalReadSource) verifySDKLiteralNumericalSource(ctx context.Context) (result error) {
	joined := source.literals
	if source.identity != source || joined == nil || joined.owner == nil {
		return numericalSBContext("copied or missing joined numerical source")
	}
	defer func() {
		result = errors.Join(result, joined.liveContext(ctx), joined.verifyIdentity(source.request))
		source.mu.Lock()
		ready := source.ready
		source.mu.Unlock()
		if !ready {
			result = errors.Join(result, numericalSBContext("joined numerical source closed during verification"))
		}
		if result != nil {
			source.revokeNumericalSource()
		}
	}()
	if err := joined.verifyIdentity(source.request); err != nil {
		return err
	}
	if err := joined.liveContext(ctx); err != nil {
		return err
	}
	if err := joined.owner.Verify(ctx); err != nil {
		return err
	}
	for _, owner := range source.originalOwners {
		if err := owner.Verify(ctx); err != nil {
			return err
		}
	}
	private, stop, err := joined.privateContext(ctx)
	if err != nil {
		return err
	}
	defer stop()
	if err := joined.verifyIdentity(source.request); err != nil {
		return err
	}
	if err := errors.Join(source.verifyNumericalSource(private), private.Err()); err != nil {
		return err
	}
	for _, owner := range source.originalOwners {
		if err := owner.Verify(ctx); err != nil {
			return err
		}
	}
	return joined.owner.Verify(ctx)
}

func (joined *numericalSDKLiteralJoin) liveContext(ctx context.Context) error {
	if ctx == nil || joined.context == nil || joined.owner == nil {
		return numericalSBContext("joined numerical source lost its original context")
	}
	if err := joined.owner.liveContext(ctx); err != nil {
		return err
	}
	_, err := sampleGoSourceContext(ctx, joined.context,
		goSourceContextLifetime{deadline: joined.Deadline, bounded: true}, false,
		numericalSBContext("joined numerical source original deadline changed or canceled without a cause"))
	return err
}

func (joined *numericalSDKLiteralJoin) privateContext(ctx context.Context) (context.Context, func(), error) {
	if err := joined.liveContext(ctx); err != nil {
		return nil, nil, err
	}
	return sdkASMDataPrivateContext(ctx, joined.context, joined.Deadline)
}

func (source *GoX86NumericalReadSource) numericalDeclarationContext(ctx context.Context) (context.Context, func(), error) {
	if source.literals != nil {
		return source.literals.privateContext(ctx)
	}
	if source.assembly != nil {
		return source.assembly.privateContext(ctx)
	}
	return ctx, func() {}, nil
}

func (source *GoX86NumericalReadSource) bindSDKLiteralSymbols(file *File, options Options, symbols map[string]string) error {
	if err := source.literals.verifyFile(file, source.request.PackagePath); err != nil {
		return err
	}
	used := make(map[string]bool)
	for _, name := range symbols {
		used[name] = true
	}
	for _, global := range file.Globl {
		qualified := global.Sym
		if !strings.ContainsAny(qualified, "·/.") {
			qualified = "·" + qualified
		}
		name := options.ResolveSym(qualified)
		if name == "" || name != numericalNativeName(qualified, source.request.PackagePath) || used[name] {
			return numericalSBContext("private literal resolver changed or collapsed its namespace")
		}
		if _, collision := options.Sigs[name]; collision {
			return numericalSBContext("private literal resolver collides with a function declaration")
		}
		used[name] = true
		symbols[qualified], symbols[global.Sym] = name, name
	}
	return nil
}

// This is a bounded access to this translation's own emitted literal, not an
// external Go-variable certificate. The shared complete typed memory shape
// supplies the native width. An observed full-word address or indexed source
// additionally requires the separate complete literal provenance/range proof
// at binding; this role query alone supplies neither bytes nor pointer backing.
func (source *GoX86NumericalReadSource) sdkLiteralRead(ins Instr, index int, arch string) (bool, error) {
	if source.literals == nil || index < 0 || index >= len(ins.Args) {
		return false, nil
	}
	operand := ins.Args[index]
	if operand.Kind == OpSym {
		operand.Sym = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(operand.Sym), "$"))
		if parsed, err := parseOperandForArch(ArchAMD64, operand.Sym); err == nil {
			operand = parsed
		}
	}
	memory, valid := x86SBMemoryAddressRole(operand, arch)
	if !valid {
		return false, nil
	}
	base, _, valid := parseSBRef(memory.Sym)
	if !valid || !strings.HasSuffix(base, "<>") {
		return false, nil
	}
	name := numericalNativeName(strings.TrimSuffix(base, "<>"), source.request.PackagePath)
	for _, image := range source.literals.Initializers.Initializers {
		if image.SourceOrdinal != source.literals.SourceOrdinal || image.Definition.Name != name {
			continue
		}
		form, known := x86SDKLiteralOperandProperties(ins, index, arch)
		if !known || form.offset < 0 || form.offset > int64(len(image.Initial))-form.width {
			return true, numericalSBContext("private literal read has an unbound shape/direction/whole-byte extent")
		}
		return true, nil
	}
	return false, nil
}

func (source *GoX86NumericalReadSource) captureSDKAssemblySourceRole(ctx context.Context) error {
	joined := source.sdkAssemblyJoin()
	if err := source.verifySDKAssemblyIdentity(); err != nil {
		return err
	}
	observation := joined.Observation
	var selected goAMD64FrameSelection
	if json.Unmarshal(observation.RawSelection, &selected) != nil || !reflect.DeepEqual(selected, source.guard.selection) ||
		!numericalSameRawSelection(observation.RawSelection, source.rawSelection) {
		return numericalSBContext("literal/source complete actual selection differs")
	}
	var environment map[string]string
	if json.Unmarshal(observation.RawEnvironment, &environment) != nil || !reflect.DeepEqual(environment, source.guard.env) {
		return numericalSBContext("literal/source actual compiler environment differs")
	}
	for name, digest := range observation.Inputs {
		data, err := source.guard.read(name)
		if err != nil || sha256.Sum256(data) != digest {
			return numericalSBContext("literal/source input bytes differ: %s: %v", name, err)
		}
	}
	// Rebind the actual driver graph, not its diagnostic JSON projection.
	// A nil json.RawMessage is serialized as null and decodes as the bytes
	// "null"; that report round trip must not impersonate a driver Error field.
	imports, err := source.guard.bindOriginalDeclarationImports(observation.Graph)
	if err != nil {
		return err
	}
	actualImports, actualErr := json.Marshal(imports)
	observedImports, observedErr := json.Marshal(observation.Imports)
	if actualErr != nil || observedErr != nil || !bytes.Equal(actualImports, observedImports) {
		return numericalSBContext("literal source graph differs from its complete observed declaration imports")
	}
	source.guard.imports = imports
	members := make([]gostaticstorage.TextMember, len(observation.Objects.Members))
	for index, member := range observation.Objects.Members {
		members[index] = gostaticstorage.TextMember{Name: member.Name, Offset: member.Offset, Size: member.Size,
			Flags: member.Flags, Texts: member.Texts}
	}
	source.sdk = &numericalSBSDKObservation{Graph: observation.Graph, Archive: observation.ObjectInputs.Archive,
		ArchiveMembers: members, Imports: imports, Referenced: observation.ObjectInputs.Referenced,
		Inputs: cloneSDKASMDataInputs(source.guard.inputs), origin: source, context: ctx, originalContext: ctx}
	source.sdk.seal, err = source.sdkDigest()
	return err
}

func (source *GoX86NumericalReadSource) preprocessSDKLiterals() error {
	joined := source.literals
	if err := joined.verifyIdentity(source.request); err != nil {
		return err
	}
	ordinal := joined.SourceOrdinal
	input := joined.Observation.ObjectInputs.Sources[ordinal]
	raw, err := source.guard.read(filepath.Join(source.request.Directory, source.request.AssemblyFile))
	if err != nil || !bytes.Equal(raw, input.Original) {
		return numericalSBContext("literal source original assembly bytes changed: %v", err)
	}
	source.cpp = joined.Observation.CPP[ordinal]
	if !bytes.Equal([]byte(source.cpp.Output), input.Expanded) {
		return numericalSBContext("literal source complete CPP program differs")
	}
	source.file, err = Parse(ArchAMD64, source.cpp.Output)
	if err != nil || len(source.file.Funcs) == 0 || len(source.file.UnlinkedPrelude) != 0 {
		return numericalSBContext("literal source lacks its complete parsed program: %v", err)
	}
	return joined.verifyFile(source.file, source.request.PackagePath)
}

// Compare the byte image the ordinary emitter will actually create, not only
// the DATA source values. This also catches GLOBL shrink/order differences,
// sparse tails, narrow float encodings and any unregistered relocation role.
func (joined *numericalSDKLiteralJoin) verifyFile(file *File, pkg string) error {
	if file == nil || file.Arch != ArchAMD64 {
		return numericalSBContext("literal initializer lacks its original x86 file")
	}
	images := make(map[string]gostaticstorage.ReadonlyLiteralDataImage)
	flags := make(map[string]uint64)
	if joined.Observation.Objects == nil || joined.SourceOrdinal < 0 ||
		joined.SourceOrdinal >= len(joined.Observation.Objects.Sources) {
		return numericalSBContext("literal initializer lost its source layout inventory")
	}
	for _, layout := range joined.Observation.Objects.Sources[joined.SourceOrdinal].ExpandedLayouts {
		flags[layout.Definition.Name] = layout.Flags
	}
	for _, image := range joined.Initializers.Initializers {
		if image.SourceOrdinal == joined.SourceOrdinal {
			if _, duplicate := images[image.Definition.Name]; duplicate {
				return numericalSBContext("literal source repeats an object-local DATA name")
			}
			images[image.Definition.Name] = image
		}
	}
	if len(images) == 0 {
		// An independently observed SDK archive may place readonly DATA in
		// another selected member. This complete TEXT-only member receives
		// no initializer or literal-read authority from those other images.
		if len(flags) != 0 || len(file.Globl) != 0 || len(file.Data) != 0 {
			return numericalSBContext("literal source complete empty-member DATA inventory differs")
		}
		return nil
	}
	if len(file.Globl) != len(images) {
		return numericalSBContext("literal source complete DATA/GLOBL inventory differs")
	}
	initial := make(map[string][]byte)
	for _, global := range file.Globl {
		name := numericalNativeName(strings.TrimSuffix(global.Sym, "<>"), pkg)
		image, found := images[name]
		readOnly, err := globlReadOnly(global.Flags)
		expression := globlFlagName.ReplaceAllStringFunc(global.Flags, func(flag string) string {
			if value, known := goTextFlagValues[flag]; known {
				return value
			}
			return flag
		})
		value, validFlags := parseImmExpr(expression)
		if !found || !strings.HasSuffix(global.Sym, "<>") || initial[name] != nil || global.SizeRaw != "" ||
			global.Size != image.DeclaredSize || err != nil || !readOnly || !validFlags || value != flags[name] {
			return numericalSBContext("literal GLOBL identity/extent/readonly role differs")
		}
		initial[name] = make([]byte, len(image.Initial))
	}
	fragments := make(map[string]int)
	for _, datum := range file.Data {
		name := numericalNativeName(strings.TrimSuffix(datum.Sym, "<>"), pkg)
		image, found := images[name]
		index := fragments[name]
		if !found || !strings.HasSuffix(datum.Sym, "<>") || datum.Addr != "" || index >= len(image.Fragments) {
			return numericalSBContext("literal DATA lost its private numerical fragment identity")
		}
		fragment := image.Fragments[index]
		payload, err := dataStmtPayload(datum)
		if err != nil || datum.Off != fragment.Offset || datum.Width != fragment.Width ||
			datum.Off < 0 || datum.Off > int64(len(image.Initial))-datum.Width {
			return numericalSBContext("literal DATA fragment width/offset differs")
		}
		copy(initial[name][datum.Off:], payload)
		fragments[name]++
	}
	for name, image := range images {
		if fragments[name] != len(image.Fragments) || !bytes.Equal(initial[name], image.Initial) {
			return numericalSBContext("emitted literal byte image differs from the actual initializer")
		}
	}
	return nil
}
