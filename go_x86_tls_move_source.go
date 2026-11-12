package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/xgo-dev/plan9asm/internal/goasmmacros"
	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// GoX86TLSMoveCaptureRequest selects an actual standalone assembler invocation.
// PackagePath is its explicit -p identity, not a claim of package selection,
// declaration, caller or runtime ownership. Shared is the actual -shared flag.
type GoX86TLSMoveCaptureRequest struct {
	GoBinary, Directory, PackagePath, AssemblyFile, Target string
	Environment                                            []string
	Shared                                                 bool
}

// GoX86TLSMoveSource observes source-encoder effects only. Its first consumer
// accepts actual zero-width NOP rewrites; it does not bind native TLS addresses,
// g, segment-register state, storage, entry registers or a callable ABI.
// Reports and parsed files cannot recreate this live observation.
type GoX86TLSMoveSource struct {
	mu            sync.Mutex
	identity      *GoX86TLSMoveSource
	ready         bool
	lease         context.Context
	originalLease context.Context
	request       GoX86TLSMoveCaptureRequest
	guard         *GoAMD64FrameSource
	originalGuard *GoAMD64FrameSource
	original      []byte
	expanded      string
	file          *File
	noops         []x86TLSNoopSite
	objects       [2][]byte
	listings      [2][]byte
	texts         [2][]gostaticstorage.TextRecord
	builtin       []byte
	seal          [32]byte
}

type x86TLSNoopSite struct {
	Function, Instruction, Line int
	PC                          int64
}

func x86TLSMoveContext(format string, args ...any) error {
	return fmt.Errorf("%w: actual Go TLS move source: %s", ErrProbeNeedsContext, fmt.Sprintf(format, args...))
}

func CaptureGoX86TLSMoveSource(ctx context.Context, request GoX86TLSMoveCaptureRequest) (_ *GoX86TLSMoveSource, result error) {
	_, arch, valid := strings.Cut(request.Target, "/")
	if ctx == nil || !valid || arch != "386" && arch != "amd64" ||
		!filepath.IsAbs(request.GoBinary) || !filepath.IsAbs(request.Directory) ||
		filepath.Base(request.AssemblyFile) != request.AssemblyFile || !strings.HasSuffix(request.AssemblyFile, ".s") {
		return nil, x86TLSMoveContext("needs explicit bounded x86 source/tool inputs")
	}
	if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil {
		return nil, errors.Join(x86TLSMoveContext("requires a bounded live capture context"), ctx.Err())
	}
	values := make(map[string]string)
	for _, entry := range request.Environment {
		key, value, valid := strings.Cut(entry, "=")
		if !valid || key == "" {
			return nil, x86TLSMoveContext("malformed assembler environment")
		}
		values[key] = value // Match exec's actual last-value semantics.
	}
	for key, value := range map[string]string{"GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "GOFLAGS": "", "GOEXPERIMENT": ""} {
		if actual, present := values[key]; !present || actual != value {
			return nil, x86TLSMoveContext("unbound actual assembler environment: %s", key)
		}
	}
	request.Environment = nil
	for key, value := range values {
		request.Environment = append(request.Environment, key+"="+value)
	}
	sort.Strings(request.Environment)
	source := &GoX86TLSMoveSource{lease: ctx, originalLease: ctx, request: request}
	source.identity = source
	source.guard = newGoOriginalInputGuard(GoAMD64FrameCaptureRequest{GoBinary: request.GoBinary,
		Directory: request.Directory, AssemblyFile: request.AssemblyFile, Target: request.Target, Environment: request.Environment})
	source.originalGuard = source.guard
	resolved, err := sourcepath.Resolve(request.Directory)
	entries, directory, inventoryErr := gooriginalsrc.ReadDirectory(request.Directory, 4096)
	if err != nil || resolved != request.Directory || inventoryErr != nil || len(entries) == 0 {
		return nil, x86TLSMoveContext("original source directory identity/inventory differs")
	}
	source.guard.directoryInfo = directory
	for _, entry := range entries {
		source.guard.entries = append(source.guard.entries, entry.Name())
	}
	if err := source.guard.observe(ctx); err != nil {
		return nil, err
	}
	if !gotoolchain.AuditedGo127(source.guard.env["GOVERSION"]) {
		return nil, x86TLSMoveContext("object observation needs its exact audited Go 1.27 producer")
	}
	go386, err := source.guard.run(ctx, "env", "GO386")
	if err != nil {
		return nil, err
	}
	source.guard.env["GO386"] = strings.TrimSpace(string(go386))
	if _, err := goasmmacros.Capture(source.guard.env["GOROOT"], source.guard.env["GOVERSION"], request.PackagePath, source.guard.read); err != nil {
		return nil, x86TLSMoveContext("actual assembler macro registration: %v", err)
	}
	source.guard.assemblerDefines, err = GoAssemblerDefinesForEnvironment(source.guard.env["GOOS"], arch, source.guard.env)
	if err != nil {
		return nil, err
	}
	for role, hash := range gostaticstorage.DecoderObjectFormatSourceHashes() {
		data, err := source.guard.read(filepath.Join(source.guard.env["GOROOT"], filepath.FromSlash(role)))
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != hash {
			return nil, x86TLSMoveContext("actual object-format source differs: %s", role)
		}
		if role == "src/cmd/internal/goobj/builtinlist.go" {
			source.builtin = data
		}
	}
	source.original, err = source.guard.read(filepath.Join(request.Directory, request.AssemblyFile))
	if err != nil {
		return nil, err
	}
	expanded, err := source.guard.preprocess(request.AssemblyFile, source.original)
	if err != nil {
		return nil, err
	}
	source.expanded, err = x86TLSCanonicalSource(expanded)
	if err != nil {
		return nil, err
	}
	source.file, err = Parse(ArchAMD64, source.expanded)
	if err != nil || len(source.file.Funcs) == 0 || len(source.file.UnlinkedPrelude) != 0 {
		return nil, x86TLSMoveContext("complete original parsed source differs: %v", err)
	}
	for _, function := range source.file.Funcs {
		for _, instruction := range function.Instrs {
			if _, _, err := x86TLSMoveProperties(instruction, arch); err != nil {
				return nil, err
			}
		}
	}
	temporary := values["TMPDIR"]
	canonicalTemporary, err := sourcepath.Resolve(temporary)
	if !filepath.IsAbs(temporary) || err != nil || canonicalTemporary != temporary {
		return nil, x86TLSMoveContext("requires an explicit canonical assembler artifact root")
	}
	source.guard.owned, err = os.MkdirTemp(temporary, "plan9asm-tls-move-")
	if err != nil {
		return nil, err
	}
	source.guard.ownedInfo, err = sourcepath.Lstat(source.guard.owned)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, source.Close())
		}
	}()
	if err := os.WriteFile(filepath.Join(source.guard.owned, "expanded.s"), []byte(source.expanded), 0600); err != nil {
		return nil, err
	}
	if _, err := source.guard.read(filepath.Join(source.guard.owned, "expanded.s")); err != nil {
		return nil, err
	}
	for index := range source.objects {
		source.objects[index], source.listings[index], source.texts[index], err = source.assemble(ctx, index)
		if err != nil {
			return nil, err
		}
	}
	if err := x86TLSOriginalExpandedObjects(source.texts[0], source.texts[1]); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(x86TLSListingTextHeaders(source.listings[0]), x86TLSListingTextHeaders(source.listings[1])) {
		return nil, x86TLSMoveContext("complete original/expanded TEXT frame and argument metadata differs")
	}
	source.noops, err = x86TLSObservedNoops(source.expanded, source.file, source.texts[1], source.listings[1], request.PackagePath,
		filepath.Join(source.guard.owned, "expanded.s"), arch)
	if err != nil {
		return nil, err
	}
	if err := source.verifyInputs(); err != nil {
		return nil, err
	}
	source.seal, err = source.digest()
	if err != nil {
		return nil, err
	}
	source.ready = true
	return source, nil
}

// Canonicalize statement boundaries, without altering tokens. The actual
// assembler independently checks this complete expansion against the original
// object; each observed candidate then owns one unambiguous physical line.
func x86TLSCanonicalSource(expanded string) (string, error) {
	var result strings.Builder
	for _, line := range strings.Split(expanded, "\n") {
		for _, statement := range splitSemicolons(strings.TrimSpace(line)) {
			for {
				label, found := statementLabelPrefix(ArchAMD64, statement)
				if !found {
					break
				}
				result.WriteString(label.raw + "\n")
				statement = label.rest
			}
			if statement != "" {
				result.WriteString(statement + "\n")
			}
		}
	}
	if result.Len() == 0 || result.Len() > 16<<20 {
		return "", x86TLSMoveContext("empty or oversized expanded source")
	}
	return result.String(), nil
}

func (source *GoX86TLSMoveSource) assemble(ctx context.Context, index int) ([]byte, []byte, []gostaticstorage.TextRecord, error) {
	input := filepath.Join(source.request.Directory, source.request.AssemblyFile)
	if index == 1 {
		input = filepath.Join(source.guard.owned, "expanded.s")
	}
	output := filepath.Join(source.guard.owned, fmt.Sprintf("original-%d.o", index))
	args := []string{"tool", "asm", "-S", "-p", source.request.PackagePath, "-I", source.request.Directory,
		"-I", filepath.Join(source.guard.env["GOROOT"], "pkg", "include"), "-o", output}
	if source.request.Shared {
		args = append(args, "-shared")
	}
	for _, define := range source.guard.assemblerDefines {
		args = append(args, "-D", define)
	}
	args = append(args, input)
	listing, err := source.guard.run(ctx, args...)
	if err != nil {
		return nil, nil, nil, errors.Join(x86TLSMoveContext("actual assembler command failed"), err)
	}
	object, err := source.guard.read(output)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := gostaticstorage.ValidateObjectVersion(object, source.request.Target, source.guard.env["GOVERSION"]); err != nil {
		return nil, nil, nil, err
	}
	texts, err := gostaticstorage.ObserveX86TLSAssemblyText(object, source.builtin, source.request.Target, source.request.Shared)
	return object, listing, texts, err
}

func (source *GoX86TLSMoveSource) digest() ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		Request  GoX86TLSMoveCaptureRequest
		Original []byte
		Expanded string
		File     *File
		Noops    []x86TLSNoopSite
		Objects  [2][]byte
		Listings [2][]byte
		Texts    [2][]gostaticstorage.TextRecord
		Builtin  []byte
		Inputs   map[string][32]byte
		Env      map[string]string
		Defines  []string
		Owned    string
	}{source.request, source.original, source.expanded, source.file, source.noops, source.objects, source.listings,
		source.texts, source.builtin, source.guard.inputs, source.guard.env, source.guard.assemblerDefines, source.guard.owned})
	return sha256.Sum256(encoded), err
}

func (source *GoX86TLSMoveSource) verifyInputs() error {
	if err := source.guard.verifyOwned(); err != nil {
		return err
	}
	entries, directory, err := gooriginalsrc.ReadDirectory(source.request.Directory, 4096)
	if err != nil || !os.SameFile(directory, source.guard.directoryInfo) {
		return x86TLSMoveContext("original directory identity differs")
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if !reflect.DeepEqual(names, source.guard.entries) {
		return x86TLSMoveContext("original directory inventory differs")
	}
	for name, expected := range source.guard.inputs {
		actual, err := goAMD64FrameRead(name)
		if err != nil || sha256.Sum256(actual) != expected {
			return x86TLSMoveContext("source/tool/object input changed: %s", filepath.Base(name))
		}
	}
	return nil
}

func (source *GoX86TLSMoveSource) Verify(ctx context.Context) (result error) {
	if source == nil || source.identity != source {
		return x86TLSMoveContext("copied or missing source observation")
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	defer func() {
		if result != nil {
			source.ready = false
		}
	}()
	if ctx == nil || source.lease == nil || source.lease != source.originalLease || source.guard == nil ||
		source.guard != source.originalGuard || !source.ready || ctx.Err() != nil || source.lease.Err() != nil {
		return x86TLSMoveContext("capture/binding context or source is closed")
	}
	digest, err := source.digest()
	if err != nil || digest != source.seal {
		return x86TLSMoveContext("complete source observation seal differs")
	}
	if err := source.verifyInputs(); err != nil {
		return err
	}
	before := source.guard.env
	if err := source.guard.observe(ctx); err != nil {
		return err
	}
	go386, err := source.guard.run(ctx, "env", "GO386")
	if err != nil {
		return err
	}
	source.guard.env["GO386"] = strings.TrimSpace(string(go386))
	if !reflect.DeepEqual(source.guard.env, before) {
		return x86TLSMoveContext("actual driver/target/profile/tool routes differ")
	}
	for index := range source.objects {
		object, listing, texts, err := source.assemble(ctx, index)
		if err != nil || !bytes.Equal(object, source.objects[index]) || !bytes.Equal(listing, source.listings[index]) ||
			!reflect.DeepEqual(texts, source.texts[index]) {
			return errors.Join(x86TLSMoveContext("complete actual source/object/listing changed"), err)
		}
	}
	return source.verifyInputs()
}

// Close revokes the source before cleaning only its identity-checked artifacts.
func (source *GoX86TLSMoveSource) Close() error {
	if source == nil {
		return nil
	}
	if source.identity != source {
		return x86TLSMoveContext("copied or missing source cannot dispose original artifacts")
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	source.ready = false
	if source.guard == nil || source.guard != source.originalGuard {
		return x86TLSMoveContext("original artifact owner changed")
	}
	return source.guard.Close()
}

func (source *GoX86TLSMoveSource) revoke() {
	if source != nil && source.identity == source {
		source.mu.Lock()
		source.ready = false
		source.mu.Unlock()
	}
}

// AssemblySource returns the independently object-checked complete expansion.
// It is ordinary source data; BindTLSMoves still needs this live owner.
func (source *GoX86TLSMoveSource) AssemblySource(ctx context.Context) (string, error) {
	if err := source.Verify(ctx); err != nil {
		return "", err
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if !source.ready {
		return "", x86TLSMoveContext("source closed before expanded-source readback")
	}
	return source.expanded, nil
}
