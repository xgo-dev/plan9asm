package plan9asm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goabi"
	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/goasmmacros"
	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/arch/x86/x86asm"
)

// GoAMD64FrameCaptureRequest describes actual input locations, not permissions.
type GoAMD64FrameCaptureRequest struct {
	GoBinary, Directory, AssemblyFile, Target string
	Environment                               []string
	// NumericalReads joins one already authenticated original numerical-read
	// source. It observes relocations; it grants no additional memory role.
	NumericalReads *GoX86NumericalReadBinding
}

// GoAMD64FrameSource is a sealed actual-object observation. It does not grant
// a native backing, caller region, memory access or return certificate.
type GoAMD64FrameSource struct {
	mu                 sync.Mutex
	identity           *GoAMD64FrameSource
	ready              bool
	request            GoAMD64FrameCaptureRequest
	selection          goAMD64FrameSelection
	env                map[string]string
	assemblerDefines   []string
	inputs             map[string][32]byte
	entries            []string
	directoryInfo      os.FileInfo
	directoryInventory *gooriginalsrc.Snapshot // Immutable complete SDK membership; no source or ASM authority.
	owned              string
	ownedInfo          os.FileInfo
	functions          map[string]goAMD64FrameFunction
	declarations       map[string]goAMD64FrameDeclaration
	imports            map[string]goAMD64FrameSelection
	origins            map[string]int
	downloadedOrigin   *gooriginalsrc.OriginSet
	downloadedModule   *gooriginalsrc.Module
	downloadedImports  map[string]gooriginalsrc.Module
	numericalBinding   *GoX86NumericalReadBinding
	numericalOrigin    *GoAMD64FrameSource
	numericalSeal      [32]byte
	numericalPackage   GoPackage
	numericalCapturing bool
	numericalCommands  []numericalSBCommand // Actual capture output only; never an authority.
	sdkFrame           *goAMD64SDKFrameOrigin
}

// newGoOriginalInputGuard initializes only private input/cleanup ownership.
// It has no ready object, declaration, source-origin or frame capability.
func newGoOriginalInputGuard(request GoAMD64FrameCaptureRequest) *GoAMD64FrameSource {
	request.Environment = append([]string(nil), request.Environment...)
	source := &GoAMD64FrameSource{request: request,
		inputs: make(map[string][32]byte), origins: make(map[string]int)}
	source.identity = source
	return source
}

// Transport is an observation role, never a memory or alias permission.
type goAMD64FrameTransport uint8

const (
	goAMD64FrameNumericTransport goAMD64FrameTransport = iota + 1
	goAMD64FrameCompositeTransport
	goAMD64FrameFloatingScalarTransport
)

type goAMD64FrameDeclaration struct {
	signature    FuncSig
	transport    goAMD64FrameTransport
	languageType string // go/types model identity, not a native pointee extent
}

type goAMD64FrameFunction struct {
	objectSymbol, listingSymbol string
	sourceSymbol                string
	privateLeaf                 bool
	nativeABI                   uint16
	locals, args                int64
	split                       bool
	prologue                    int // original byte offset, after any generated stack check
	code                        []byte
	positions                   map[int]string
	sourcePositions             map[int][]goAMD64FrameSourcePosition
	signature                   FuncSig
	transport                   goAMD64FrameTransport
	languageType                string
}

func (fn goAMD64FrameFunction) nativeFlags() uint8 {
	if fn.split {
		return 0
	}
	return 16 // goobj.SymFlagNoSplit, not an assembly-origin flag.
}

type goAMD64FrameSourcePosition struct {
	file string
	line int
}

// This is decoded only from the actual driver stdout, never from a proof file.
type goAMD64FrameSelection struct {
	Dir, ImportPath, Name, Export, ForTest                                                 string
	GoFiles, CompiledGoFiles, SFiles, HFiles, CgoFiles, Imports, EmbedFiles, EmbedPatterns []string
	IgnoredGoFiles, IgnoredOtherFiles                                                      []string
	Standard                                                                               bool
	ImportMap                                                                              map[string]string
	CFiles, CXXFiles, MFiles, FFiles, SwigFiles, SwigCXXFiles, SysoFiles                   []string
	Module                                                                                 *struct {
		Path, Version, Dir, GoMod, GoVersion string
		Main                                 bool
		Replace                              json.RawMessage
	}
	Error      json.RawMessage
	DepsErrors []json.RawMessage
}

func (selected goAMD64FrameSelection) nonordinaryRole() bool {
	for _, files := range [][]string{selected.CgoFiles, selected.CFiles, selected.CXXFiles, selected.MFiles,
		selected.FFiles, selected.SwigFiles, selected.SwigCXXFiles, selected.SysoFiles, selected.EmbedFiles, selected.EmbedPatterns} {
		if len(files) != 0 {
			return true
		}
	}
	return false
}

func CaptureGoAMD64FrameSource(ctx context.Context, pkg GoPackage, request GoAMD64FrameCaptureRequest) (*GoAMD64FrameSource, error) {
	return captureGoAMD64FrameSource(ctx, pkg, request, nil)
}

func captureGoAMD64FrameSource(ctx context.Context, pkg GoPackage, request GoAMD64FrameCaptureRequest, exact *goAMD64DownloadedIdentity) (_ *GoAMD64FrameSource, captureErr error) {
	if ctx != nil && ctx.Err() != nil {
		if request.NumericalReads != nil {
			return nil, fmt.Errorf("capture numerical frame context: %w", ctx.Err())
		}
		return nil, errors.Join(goAMD64FrameContext("requires live capture context"), ctx.Err())
	}
	if ctx == nil || pkg.Types == nil || pkg.Path != pkg.Types.Path() ||
		!filepath.IsAbs(request.GoBinary) || !filepath.IsAbs(request.Directory) ||
		filepath.Base(request.AssemblyFile) != request.AssemblyFile || filepath.Ext(request.AssemblyFile) != ".s" {
		return nil, goAMD64FrameContext("requires live context, actual package and bounded absolute inputs")
	}
	parts := strings.Split(request.Target, "/")
	if len(parts) != 2 || parts[1] != "amd64" || parts[0] != "linux" && parts[0] != "darwin" && parts[0] != "windows" {
		return nil, goAMD64FrameContext("initial object capture supports ordinary AMD64 targets only")
	}
	var err error
	request.Directory, err = sourcepath.Resolve(request.Directory)
	if err != nil {
		return nil, err
	}
	source := newGoOriginalInputGuard(request)
	if request.NumericalReads != nil {
		if err := verifyGoAMD64FrameNumericalRequest(ctx, pkg, source.request); err != nil {
			return nil, err
		}
		source.numericalBinding = request.NumericalReads
		source.numericalOrigin = source
		source.numericalSeal = request.NumericalReads.seal
		source.numericalPackage = pkg
		source.numericalCapturing = true
	}
	provided := make(map[string]string)
	for _, value := range request.Environment {
		key, setting, valid := strings.Cut(value, "=")
		if !valid || key == "" {
			return nil, goAMD64FrameContext("malformed command environment")
		}
		provided[key] = setting
		if (key == "GOFLAGS" || key == "GOEXPERIMENT") && setting != "" || key == "GOPACKAGESDRIVER" && setting != "" && setting != "off" {
			return nil, goAMD64FrameContext("effective overlay, custom flags, experiments or driver require their own source mapping")
		}
	}
	for _, key := range []string{"GOPATH", "GOMODCACHE", "GOCACHE", "TMPDIR", "GOTMPDIR"} {
		if !filepath.IsAbs(provided[key]) {
			return nil, goAMD64FrameContext("explicit private %s directory is required", key)
		}
	}
	settings := map[string]string{"GOOS": parts[0], "GOARCH": "amd64", "CGO_ENABLED": "0", "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "GOFLAGS": "", "GOPROXY": "off"}
	var env []string
	for _, value := range source.request.Environment {
		key, _, _ := strings.Cut(value, "=")
		if _, replace := settings[key]; !replace {
			env = append(env, value)
		}
	}
	for key, value := range settings {
		env = append(env, key+"="+value)
	}
	source.request.Environment = env
	if err := source.snapshotDirectory(); err != nil {
		return nil, err
	}
	if err := source.observe(ctx); err != nil {
		return nil, err
	}
	if exact == nil {
		if err := source.verifyOwnedSourceDirectory(); err != nil {
			return nil, err
		}
	} else {
		inside, err := gostaticstorage.SourceDirectoryWithinRoot(request.Directory, source.env["GOROOT"])
		if err != nil || inside {
			return nil, errors.Join(goAMD64FrameContext("SDK source cannot acquire an exact downloaded role"), err)
		}
		if err := source.captureDownloadedOrigin(ctx, *exact, provided["GOTMPDIR"]); err != nil {
			return nil, err
		}
	}
	selected, err := source.load(ctx)
	if err != nil {
		return nil, err
	}
	source.selection = selected
	if source.numericalBinding != nil && (len(selected.SFiles) != 1 || selected.SFiles[0] != request.AssemblyFile) {
		return nil, goAMD64FrameContext("numerical frame join requires one complete original assembly selection")
	}
	moduleRoot := request.Directory
	if source.downloadedModule != nil {
		moduleRoot = source.downloadedModule.Root
	}
	mainRole, moduleVersion := true, ""
	metadata := filepath.Join(moduleRoot, "go.mod")
	if source.legacyDownloadedModule() {
		mainRole, moduleVersion = false, source.downloadedModule.SourceVersion
		metadata = source.downloadedModule.GoMod
	}
	if selected.Dir != request.Directory || selected.ImportPath != pkg.Path || selected.ForTest != "" || selected.Module == nil ||
		selected.Module.Main != mainRole || selected.Module.Version != moduleVersion || selected.Module.Dir != moduleRoot || len(selected.Module.Replace) != 0 && string(selected.Module.Replace) != "null" ||
		selected.nonordinaryRole() || len(selected.GoFiles) == 0 || len(selected.SFiles) == 0 {
		return nil, goAMD64FrameContext("capture needs complete ordinary original module sources")
	}
	if selected.Module.GoMod != metadata {
		return nil, goAMD64FrameContext("actual module metadata is outside the original source directory")
	}
	if source.downloadedModule != nil {
		original := source.downloadedModule
		path, err := goAMD64DownloadedPackagePath(*original, selected.Dir)
		if err != nil {
			return nil, err
		}
		if selected.Module.Path != original.ModulePath || selected.Module.GoVersion != gooriginalsrc.SelectedGoVersion(original.GoVersion, mainRole) ||
			selected.ImportPath != path {
			return nil, goAMD64FrameContext("exact downloaded capture requires its original primary module package")
		}
	}
	source.imports, err = source.loadOriginalDeclarationImports(ctx)
	if err != nil {
		return nil, err
	}
	source.declarations, err = source.typedDeclarations(pkg, false)
	if err != nil {
		return nil, err
	}
	rules, err := goasmmacros.Capture(source.env["GOROOT"], source.env["GOVERSION"], selected.ImportPath, source.read)
	if err != nil || rules.PackageRole != "ordinary_path" && rules.PackageRole != "legacy_no_experiment_macros" {
		return nil, goAMD64FrameContext("ordinary assembler macro source registration: %v", err)
	}
	source.assemblerDefines, err = GoAssemblerDefinesForEnvironment(source.env["GOOS"], source.env["GOARCH"], source.env)
	if err != nil {
		return nil, err
	}
	source.owned, err = os.MkdirTemp(provided["TMPDIR"], "plan9asm-go-frame-object-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if captureErr != nil {
			captureErr = errors.Join(captureErr, source.Close())
		}
	}()
	source.ownedInfo, err = sourcepath.Lstat(source.owned)
	if err != nil {
		return nil, err
	}
	canonicalOwned, err := sourcepath.Resolve(source.owned)
	if err != nil {
		return nil, err
	}
	source.owned = canonicalOwned
	if err := source.verifyOwned(); err != nil {
		return nil, err
	}
	source.functions = make(map[string]goAMD64FrameFunction)
	found := false
	for _, name := range selected.SFiles {
		found = found || name == request.AssemblyFile
		original, err := source.read(filepath.Join(request.Directory, name))
		if err != nil {
			return nil, err
		}
		expanded, err := source.preprocess(name, original)
		if err != nil {
			return nil, err
		}
		file, err := ParseWithDefines(ArchAMD64, expanded, nil)
		if err != nil || len(file.Funcs) == 0 || len(file.UnlinkedPrelude) != 0 {
			return nil, goAMD64FrameContext("full original assembly lacks complete TEXT: %v", err)
		}
		object := filepath.Join(source.owned, name+".o")
		assemblyInput := name
		if source.numericalBinding != nil {
			assemblyInput = filepath.Join(request.Directory, name)
		}
		// The independent actual assembler and source preprocessor consume
		// the same registered ordinary profile macros. Generated headers keep
		// their separate source mapping; CPU identity grants no memory role.
		args := []string{"tool", "asm", "-S", "-p", pkg.Path,
			"-I", request.Directory, "-I", filepath.Join(source.env["GOROOT"], "pkg", "include")}
		for _, define := range source.assemblerDefines {
			args = append(args, "-D", define)
		}
		args = append(args, "-o", object, assemblyInput)
		listing, err := source.run(ctx, args...)
		if err != nil {
			return nil, err
		}
		objectBytes, err := source.read(object)
		if err != nil || len(objectBytes) == 0 {
			if err == nil {
				err = goAMD64FrameContext("actual assembler produced an empty object")
			}
			return nil, err
		}
		if err := os.WriteFile(object+".listing", listing, 0600); err != nil {
			return nil, err
		}
		if _, err := source.read(object + ".listing"); err != nil {
			return nil, err
		}
		var texts []gostaticstorage.TextRecord
		if source.numericalBinding != nil {
			texts, err = source.numericalFrameObject(object, file)
			if err != nil {
				return nil, err
			}
		}
		var functions map[string]goAMD64FrameFunction
		// An ordinary symbolic reference also needs its complete original
		// relocation inventory, even when this source defines no ASM DATA.
		if len(file.Data)+len(file.Globl) != 0 || source.numericalBinding == nil && bytes.Contains(listing, []byte("\trel ")) {
			observed, readErr := source.frameDataObject(expanded, objectBytes)
			if readErr != nil {
				return nil, readErr
			}
			filtered := listing
			if len(observed.Layouts) != 0 {
				filtered, readErr = goAMD64FrameDataListing(listing, observed)
				if readErr != nil {
					return nil, readErr
				}
			}
			var unwind *gostaticstorage.WindowsAMD64AssemblyUnwind
			if source.request.Target == "windows/amd64" {
				leaves, readErr := goAMD64WindowsPrivateLeafTexts(file, pkg, listing, observed)
				if readErr != nil {
					return nil, readErr
				}
				value, readErr := source.observeWindowsUnwind(objectBytes, leaves)
				if readErr != nil {
					return nil, readErr
				}
				unwind = &value
			}
			functions, err = goAMD64FrameListingWithDataObject(filtered, file, pkg, source.origins, observed, unwind,
				source.request.Target, source.request.Directory, "")
			if err == nil {
				err = goAMD64FrameDataTextJoin(functions, observed, source.request.Directory, source.origins, "")
			}
			if err == nil && unwind != nil {
				err = goAMD64FrameWindowsUnwindFunctions(functions, source.origins, source.request.Directory, *unwind)
			}
		} else if source.request.Target == "windows/amd64" && (gotoolchain.AuditedGo127(source.env["GOVERSION"]) ||
			bytes.Contains(listing, []byte(" SSEHUNWINDINFO "))) {
			unwind, readErr := source.observeWindowsUnwind(objectBytes)
			if readErr != nil {
				return nil, readErr
			}
			functions, err = goAMD64FrameWindowsUnwindListing(listing, file, pkg, source.origins,
				source.request.Directory, unwind)
		} else {
			if source.numericalBinding == nil && goAMD64FrameSplitListing(listing) {
				observed, readErr := source.frameDataObject(expanded, objectBytes)
				if readErr != nil {
					return nil, readErr
				}
				functions, err = goAMD64FrameListingWithSplitObject(listing, file, pkg, source.origins,
					observed.Member.Texts, nil, source.request.Target, source.request.Directory, "")
				if err == nil {
					err = goAMD64FrameDataTextJoin(functions, observed, source.request.Directory, source.origins, "")
				}
			} else {
				functions, err = goAMD64FrameListingWithNumericalObject(listing, file, pkg, source.origins, texts)
			}
		}
		if err != nil {
			return nil, err
		}
		if source.numericalBinding != nil && !bytes.Equal(listing, source.numericalBinding.source.native.OriginalListing) {
			return nil, goAMD64FrameContext("independent complete original numerical/frame listing differs")
		}
		for _, text := range texts {
			if !bytes.Equal(functions[text.Name].code, text.Code) {
				return nil, goAMD64FrameContext("independent complete object/listing code bytes differ")
			}
		}
		if err := source.verifyObjectListing(ctx, object, functions); err != nil {
			return nil, err
		}
		for symbol, fn := range functions {
			if _, duplicate := source.functions[symbol]; duplicate {
				return nil, goAMD64FrameContext("duplicate original TEXT symbol")
			}
			declaration, exists := source.declarations[symbol]
			if fn.privateLeaf {
				if exists {
					return nil, goAMD64FrameContext("private leaf acquired a Go declaration")
				}
			} else if !exists || !reflect.DeepEqual(fn.signature, declaration.signature) {
				return nil, goAMD64FrameContext("object lacks its independently checked declaration/layout")
			}
			fn.transport, fn.languageType = declaration.transport, declaration.languageType
			source.functions[symbol] = fn
		}
	}
	if !found {
		return nil, goAMD64FrameContext("requested assembly is absent from actual complete selection")
	}
	withFrame := false
	for _, fn := range source.functions {
		withFrame = withFrame || fn.locals > 0
	}
	if !withFrame {
		return nil, goAMD64FrameContext("complete source has no nonzero native frame")
	}
	source.ready = true
	source.numericalCapturing = false
	if err := source.Verify(ctx); err != nil {
		return nil, err
	}
	return source, nil
}

// Verify rechecks actual routing/selection and all original/tool/export/artifact
// bytes. Failure permanently revokes this observation; it grants no memory.
func (source *GoAMD64FrameSource) Verify(ctx context.Context) (verifyErr error) {
	if source == nil || source.identity != source {
		return goAMD64FrameContext("missing sealed actual-object observation")
	}
	if source.sdkFrame != nil {
		return source.verifySDKFrame(ctx)
	}
	if err := source.verifyNumericalFrameInputs(ctx); err != nil {
		source.revokeNumericalFrame()
		return err
	}
	defer func() {
		if err := source.verifyNumericalFrameInputs(ctx); err != nil {
			source.revokeNumericalFrame()
			// The inner observer already revokes on failure. Its own closed
			// generation must not relabel an actual command/cancellation
			// failure as a source exclusion during the outer postcheck.
			if verifyErr == nil || !errors.Is(err, ErrProbeNeedsContext) {
				verifyErr = errors.Join(verifyErr, err)
			}
		}
	}()
	return source.verifyFrameOnly(ctx)
}

func (source *GoAMD64FrameSource) verifyFrameOnly(ctx context.Context) (verifyErr error) {
	if source == nil {
		return goAMD64FrameContext("missing sealed actual-object observation")
	}
	private, contextErr := captureGoAMD64FramePrivateContext(ctx)
	if contextErr != nil {
		source.mu.Lock()
		source.ready = false
		source.mu.Unlock()
		if source.numericalOrigin != nil {
			return fmt.Errorf("verify numerical frame observer context: %w", contextErr)
		}
		return errors.Join(goAMD64FrameContext("expired actual-object observation"), contextErr)
	}
	defer private.stop()
	defer func() {
		// Run every caller callback after the locked command/input round.
		// A callback may Close or change original inputs; no authority may
		// survive that final boundary even if its Err method returns nil.
		contextErr := private.verify()
		source.mu.Lock()
		defer source.mu.Unlock()
		if contextErr != nil {
			if source.numericalOrigin != nil {
				verifyErr = errors.Join(verifyErr, fmt.Errorf("numerical frame caller context expired after actual commands: %w", contextErr))
			} else {
				verifyErr = errors.Join(verifyErr, goAMD64FrameContext("caller context expired after actual commands"), contextErr)
			}
		}
		if !source.ready && verifyErr == nil {
			verifyErr = goAMD64FrameContext("source closed during caller context callbacks")
		}
		if verifyErr == nil {
			verifyErr = errors.Join(source.verifyInputs(), source.verifyDownloadedOrigin())
		}
		if verifyErr != nil {
			source.ready = false
		}
	}()
	ctx = private
	source.mu.Lock()
	defer source.mu.Unlock()
	defer func() {
		if verifyErr != nil {
			source.ready = false
		}
	}()
	if ctx != nil && ctx.Err() != nil {
		if source.numericalOrigin != nil {
			return fmt.Errorf("verify numerical frame observer context: %w", ctx.Err())
		}
		return errors.Join(goAMD64FrameContext("expired actual-object observation"), ctx.Err())
	}
	if !source.ready || ctx == nil {
		return goAMD64FrameContext("closed, uninitialized or expired actual-object observation")
	}
	if err := source.verifyDownloadedOrigin(); err != nil {
		return err
	}
	before := source.env
	if err := source.observe(ctx); err != nil {
		return err
	}
	if !reflect.DeepEqual(before, source.env) {
		return goAMD64FrameContext("actual Go environment changed")
	}
	if source.downloadedOrigin == nil {
		if err := source.verifyOwnedSourceDirectory(); err != nil {
			return err
		}
	}
	if err := source.verifyInputs(); err != nil {
		return err
	}
	selected, err := source.load(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(source.selection, selected) {
		return goAMD64FrameContext("actual complete package selection/export changed")
	}
	imports, err := source.loadOriginalDeclarationImports(ctx)
	if err != nil && source.numericalOrigin != nil {
		return err
	}
	if err != nil || !reflect.DeepEqual(source.imports, imports) {
		return goAMD64FrameContext("actual complete declaration import graph changed: %v", err)
	}
	if err := ctx.Err(); err != nil {
		if source.numericalOrigin != nil {
			return fmt.Errorf("numerical frame verification context expired after actual commands: %w", err)
		}
		return errors.Join(goAMD64FrameContext("verification context expired after actual commands"), err)
	}
	// The final complete input/origin check follows caller callbacks in the
	// outer deferred boundary; do not repeat a whole-map read before it.
	return nil
}

func (source *GoAMD64FrameSource) verifyOwnedSourceDirectory() error {
	if err := gostaticstorage.ValidateOwnedSourceDirectory(source.request.Directory, source.env["GOROOT"], source.env["GOMODCACHE"]); err != nil {
		return errors.Join(goAMD64FrameContext("owned source needs a distinct physical SDK/cache role"), err)
	}
	return nil
}

func (source *GoAMD64FrameSource) verifyInputs() error {
	if err := source.verifyOwned(); err != nil {
		return err
	}
	maximum := 256 // Ordinary owned-main retains its original flat bound.
	if inventory := source.directoryInventory; inventory != nil {
		if err := inventory.Verify(); err != nil {
			return goAMD64FrameContext("complete SDK directory membership changed: %v", err)
		}
		view := inventory.View()
		original := view.Directories[source.request.Directory]
		if original == nil || source.directoryInfo == nil || !os.SameFile(original, source.directoryInfo) ||
			len(view.Entries[source.request.Directory]) != len(source.entries) {
			return goAMD64FrameContext("complete SDK directory inventory lost its original role")
		}
		maximum = len(view.Entries[source.request.Directory])
	}
	entries, directoryInfo, err := gooriginalsrc.ReadDirectory(source.request.Directory, maximum)
	if err != nil || source.directoryInfo == nil || !os.SameFile(source.directoryInfo, directoryInfo) {
		return goAMD64FrameContext("original package directory inventory or identity changed: %v", err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if !reflect.DeepEqual(names, source.entries) {
		return goAMD64FrameContext("original package directory inventory changed")
	}
	for name, expected := range source.inputs {
		digest, err := gooriginalsrc.HashRegularFile(name, 64<<20)
		if err != nil || digest != expected {
			return goAMD64FrameContext("original/tool/export/object input changed: %s: %v", filepath.Base(name), err)
		}
	}
	return nil
}

func (source *GoAMD64FrameSource) verifyOwned() error {
	info, err := os.Lstat(source.owned)
	if err != nil || source.ownedInfo == nil || !info.IsDir() || !os.SameFile(source.ownedInfo, info) {
		return goAMD64FrameContext("factory artifact directory identity changed or is inaccessible: %v", err)
	}
	return nil
}

// Close invalidates the token before removing only its factory-owned artifacts.
// Calling it again is harmless; no source, tool or cache-owned file is removed.
func (source *GoAMD64FrameSource) Close() error {
	if source == nil {
		return nil
	}
	if source.identity != source {
		return goAMD64FrameContext("copied or uninitialized observation cannot dispose original artifacts")
	}
	if source.sdkFrame != nil {
		return source.closeSDKFrame()
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	source.ready = false
	if source.numericalOrigin != nil && source.numericalOrigin != source {
		return goAMD64FrameContext("copied numerical frame cannot close the original artifact owner")
	}
	if source.owned == "" {
		return nil
	}
	if err := source.verifyOwned(); err != nil {
		return err
	}
	err := os.RemoveAll(source.owned)
	if err == nil {
		source.owned = ""
		source.ownedInfo = nil
	}
	return err
}

func goAMD64FrameContext(format string, args ...any) error {
	return fmt.Errorf("%w: actual Go frame source: %s", ErrProbeNeedsContext, fmt.Sprintf(format, args...))
}

func (source *GoAMD64FrameSource) run(ctx context.Context, args ...string) ([]byte, error) {
	if ctx == nil {
		return nil, goAMD64FrameContext("actual command requires live context")
	}
	if err := ctx.Err(); err != nil {
		if source.numericalOrigin != nil {
			return nil, fmt.Errorf("numerical frame actual command context expired: %w", err)
		}
		return nil, errors.Join(goAMD64FrameContext("actual command context expired"), err)
	}
	if err := source.verifyDownloadedOrigin(); err != nil {
		return nil, err
	}
	// Capture has not published the source and holds no Frame lock. Verify's
	// existing locked command path is guarded outside the entire round instead.
	if source.numericalCapturing {
		if err := source.numericalBinding.verify(); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	var output []byte
	var err error
	if source.legacyDownloadedModule() && len(args) > 0 && args[0] == "list" {
		output, err = source.runDownloadedList(ctx, args)
	} else {
		output, err = goasmcmd.Run(ctx, source.request.Directory, source.request.Environment, source.request.GoBinary, args...)
	}
	if source.numericalCapturing {
		source.numericalCommands = append(source.numericalCommands, numericalSBCommand{
			Directory: source.request.Directory, Binary: source.request.GoBinary,
			Arguments: append([]string(nil), args...), Stdout: append([]byte(nil), output...),
		})
		err = errors.Join(err, source.numericalBinding.verify())
	}
	// Preserve both independent origins and cancellation when commands race
	// revocation. Neither observation grants the other's source permission.
	return output, errors.Join(err, ctx.Err(), source.verifyDownloadedOrigin())
}

func goAMD64FrameRead(name string) (_ []byte, readErr error) {
	return goAMD64FrameReadBound(name, 64<<20)
}

func goAMD64FrameReadBound(name string, maximum int64) (_ []byte, readErr error) {
	resolved, err := sourcepath.Resolve(name)
	if err != nil || resolved != name {
		return nil, goAMD64FrameContext("input path is redirected or inaccessible: %s", filepath.Base(name))
	}
	before, err := os.Lstat(name)
	if err != nil || !before.Mode().IsRegular() {
		return nil, goAMD64FrameContext("input role changed before opening")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { readErr = errors.Join(readErr, file.Close()) }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) || maximum < 0 || maximum > 64<<20 || info.Size() > maximum {
		return nil, goAMD64FrameContext("input is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, goAMD64FrameContext("input byte bound/read failure: %v", err)
	}
	after, err := os.Lstat(name)
	if err != nil || !os.SameFile(info, after) || !after.Mode().IsRegular() || int64(len(data)) != info.Size() {
		afterSize, sameFile, regular := int64(-1), false, false
		if err == nil {
			afterSize, sameFile, regular = after.Size(), os.SameFile(info, after), after.Mode().IsRegular()
		}
		return nil, goAMD64FrameContext("input role/extent changed while reading %q: opened=%d read=%d after=%d same_file=%t regular=%t after_stat=%v",
			filepath.Base(name), info.Size(), len(data), afterSize, sameFile, regular, err)
	}
	return data, nil
}

func (source *GoAMD64FrameSource) read(name string) ([]byte, error) {
	data, err := goAMD64FrameRead(name)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	if before, exists := source.inputs[name]; exists && before != digest {
		return nil, goAMD64FrameContext("input changed during capture: %s", filepath.Base(name))
	}
	source.inputs[name] = digest
	return data, nil
}

func (source *GoAMD64FrameSource) snapshotDirectory() error {
	resolved, err := sourcepath.Resolve(source.request.Directory)
	if err != nil || resolved != source.request.Directory {
		return goAMD64FrameContext("requires canonical actual package directory")
	}
	entries, directoryInfo, err := gooriginalsrc.ReadDirectory(resolved, 256)
	if err != nil || len(entries) == 0 || len(entries) > 256 {
		return goAMD64FrameContext("package directory is unavailable or exceeds its bound")
	}
	source.directoryInfo = directoryInfo
	var total int
	for _, entry := range entries {
		if entry.IsDir() {
			return goAMD64FrameContext("initial source root requires a flat complete inventory")
		}
		source.entries = append(source.entries, entry.Name())
		data, err := source.read(filepath.Join(resolved, entry.Name()))
		if err != nil {
			return err
		}
		total += len(data)
		if total > 16<<20 {
			return goAMD64FrameContext("original package byte inventory exceeds its bound")
		}
	}
	return nil
}

func (source *GoAMD64FrameSource) observe(ctx context.Context) error {
	if _, err := source.read(source.request.GoBinary); err != nil {
		return err
	}
	data, err := source.run(ctx, "env", "-json", "GOROOT", "GOTOOLDIR", "GOCACHE", "GOMODCACHE", "GOPATH", "GOTMPDIR", "GOVERSION", "GOOS", "GOARCH", "GOFLAGS", "GOEXPERIMENT", "GOAMD64")
	if err != nil {
		return err
	}
	var env map[string]string
	if err := json.Unmarshal(data, &env); err != nil {
		return err
	}
	// Commands must keep their observed SDK spelling: changing it can rebuild
	// builtin tools with different bytes. File reads and driver ownership use
	// the independently resolved physical SDK. Verify compares both identities.
	root, err := sourcepath.Resolve(env["GOROOT"])
	if err != nil || !filepath.IsAbs(env["GOROOT"]) {
		return goAMD64FrameContext("actual SDK root is not an accessible absolute directory: %v", err)
	}
	env["command/GOROOT"], env["GOROOT"] = env["GOROOT"], root
	if env["GOOS"]+"/"+env["GOARCH"] != source.request.Target || env["GOFLAGS"] != "" || env["GOEXPERIMENT"] != "" ||
		filepath.Join(env["GOROOT"], "bin", gotoolchain.HostExecutable("go")) != source.request.GoBinary {
		return goAMD64FrameContext("actual driver/target/CPU/source routing needs a separate audited contract")
	}
	switch env["GOAMD64"] {
	case "v1", "v2", "v3", "v4":
		// Each actual profile retains its own selected original Go sources,
		// exports and object bytes. Verify compares this environment exactly;
		// no capture is relabeled or reused across different CPU profiles.
	default:
		return goAMD64FrameContext("unregistered actual GOAMD64 profile %q", env["GOAMD64"])
	}
	version, err := source.read(filepath.Join(env["GOROOT"], "VERSION"))
	if err != nil || strings.Split(string(version), "\n")[0] != env["GOVERSION"] {
		return goAMD64FrameContext("actual driver differs from source VERSION")
	}
	for _, tool := range []string{"asm", "compile", "objdump"} {
		executable := gotoolchain.HostExecutable(tool)
		data, err := source.run(ctx, "tool", "-n", tool)
		if err != nil {
			return err
		}
		name := strings.TrimSpace(string(data))
		if !filepath.IsAbs(name) || strings.ContainsAny(name, "\r\n") || tool != "objdump" && name != filepath.Join(env["GOTOOLDIR"], executable) {
			return goAMD64FrameContext("unrecognized actual %s route", tool)
		}
		resolved, err := sourcepath.Resolve(name)
		if err != nil {
			return err
		}
		if tool == "objdump" && name != filepath.Join(env["GOTOOLDIR"], executable) {
			cache, err := sourcepath.Resolve(env["GOCACHE"])
			if err != nil || !goAssemblyPathWithinRoot(cache, resolved) || filepath.Base(resolved) != executable {
				return goAMD64FrameContext("unknown builtin object observer origin")
			}
		}
		name = resolved
		env["route/"+tool] = name
		if _, err := source.read(name); err != nil {
			return err
		}
	}
	for _, name := range []string{"src/cmd/internal/obj/x86/obj6.go", "src/cmd/internal/obj/x86/asm6.go", "src/cmd/go/internal/work/gc.go", "src/cmd/asm/main.go", "src/cmd/go/internal/tool/tool.go", "src/cmd/internal/objabi/stack.go"} {
		if _, err := source.read(filepath.Join(env["GOROOT"], filepath.FromSlash(name))); err != nil {
			return err
		}
	}
	source.env = env
	return nil
}

func (source *GoAMD64FrameSource) load(ctx context.Context) (goAMD64FrameSelection, error) {
	selected, _, err := source.loadWithRaw(ctx)
	return selected, err
}

func (source *GoAMD64FrameSource) loadWithRaw(ctx context.Context) (goAMD64FrameSelection, []byte, error) {
	return source.loadWithRawPackage(ctx, ".")
}

func (source *GoAMD64FrameSource) loadWithRawPackage(ctx context.Context, packageQuery string) (goAMD64FrameSelection, []byte, error) {
	data, err := source.run(ctx, "list", "-json", "-compiled", "-export", "-mod=readonly", packageQuery)
	if err != nil {
		return goAMD64FrameSelection{}, data, err
	}
	return source.readRawPackageSelection(data)
}

// Both root-only and dependency queries retain the same complete root record
// and physical export read. This does not authenticate a caller-supplied JSON.
func (source *GoAMD64FrameSource) readRawPackageSelection(data []byte) (goAMD64FrameSelection, []byte, error) {
	var selected goAMD64FrameSelection
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&selected); err != nil {
		return selected, data, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || len(selected.Error) != 0 || len(selected.DepsErrors) != 0 {
		return selected, data, goAMD64FrameContext("incomplete or ambiguous actual package export")
	}
	if selected.Export == "" {
		return selected, data, goAMD64FrameContext("actual package has no compiled export")
	}
	export, err := sourcepath.Resolve(selected.Export)
	selected.Export = export
	cache, cacheErr := sourcepath.Resolve(source.env["GOCACHE"])
	if err != nil || cacheErr != nil || !goAssemblyPathWithinRoot(cache, selected.Export) {
		return selected, data, goAMD64FrameContext("compiled export is outside the actual build cache")
	}
	if export, err := source.read(selected.Export); err != nil || len(export) == 0 {
		if err == nil {
			err = goAMD64FrameContext("actual package export is empty")
		}
		return selected, data, err
	}
	return selected, data, nil
}

func (source *GoAMD64FrameSource) numericDeclarations(pkg GoPackage) error {
	_, err := source.typedDeclarations(pkg, true)
	return err
}

// The numeric-only query remains strict. The fixed-local binder separately
// checks the closed transport role and replays each actual typed component;
// observation itself never supplies local or incoming memory permission.
func (source *GoAMD64FrameSource) typedDeclarations(pkg GoPackage, numericOnly bool) (map[string]goAMD64FrameDeclaration, error) {
	return source.typedDeclarationsForArch(pkg, numericOnly, "amd64")
}

// The numerical SB binding also observes 386 declarations. This helper only
// rechecks language/ABI0 identity; it does not extend the AMD64 frame factory.
func (source *GoAMD64FrameSource) typedDeclarationsForArch(pkg GoPackage, numericOnly bool, arch string) (map[string]goAMD64FrameDeclaration, error) {
	return source.typedDeclarationsForArchRole(pkg, numericOnly, arch, false, nil)
}

func (source *GoAMD64FrameSource) typedDeclarationsForArchRole(pkg GoPackage, numericOnly bool, arch string,
	opaqueUnsafePointer bool, entries map[string]bool,
) (map[string]goAMD64FrameDeclaration, error) {
	return source.typedDeclarationsForSourceRole(pkg, numericOnly, arch, opaqueUnsafePointer, entries, false)
}

// Numerical-source binding observes ordinary F32/F64 declaration identity and
// ABI0 slots, not the frame factory's integer transport. This separate route
// supplies no physical frame, caller, register-entry or numerical input facts.
func (source *GoAMD64FrameSource) typedNumericalDeclarationsForArchRole(pkg GoPackage, arch string,
	opaqueUnsafePointer bool, entries map[string]bool,
) (map[string]goAMD64FrameDeclaration, error) {
	return source.typedDeclarationsForSourceRole(pkg, false, arch, opaqueUnsafePointer, entries, true)
}

func (source *GoAMD64FrameSource) typedDeclarationsForSourceRole(pkg GoPackage, numericOnly bool, arch string,
	opaqueUnsafePointer bool, entries map[string]bool, floatingScalars bool, globals ...map[string]goReadOnlyObject,
) (map[string]goAMD64FrameDeclaration, error) {
	if len(globals) > 1 {
		return nil, goAMD64FrameContext("ambiguous original Go variable inventory")
	}
	fset := token.NewFileSet()
	var syntax []*ast.File
	var compiled []string
	bodyless := make(map[string]bool)
	for _, name := range source.selection.GoFiles {
		filename := filepath.Join(source.request.Directory, name)
		data, err := source.read(filename)
		if err != nil {
			return nil, err
		}
		file, err := parser.ParseFile(fset, filename, data, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		for _, declaration := range file.Decls {
			switch declaration := declaration.(type) {
			case *ast.FuncDecl:
				if declaration.Body == nil && declaration.Recv == nil {
					bodyless[declaration.Name.Name] = true
				}
			case *ast.GenDecl:
				if declaration.Tok != token.TYPE && declaration.Tok != token.IMPORT &&
					declaration.Tok != token.CONST && declaration.Tok != token.VAR {
					return nil, goAMD64FrameContext("unknown original declaration role")
				}
			default:
				return nil, goAMD64FrameContext("unknown original declaration role")
			}
		}
		syntax = append(syntax, file)
		compiled = append(compiled, filename)
	}
	if len(pkg.Syntax) != len(syntax) {
		return nil, goAMD64FrameContext("supplied syntax omitted complete ordinary source files")
	}
	if len(bodyless) == 0 {
		return nil, goAMD64FrameContext("original source has no bodyless assembly declaration")
	}
	sort.Strings(compiled)
	actual := append([]string(nil), source.selection.CompiledGoFiles...)
	for i, name := range actual {
		if !filepath.IsAbs(name) {
			actual[i] = filepath.Join(source.request.Directory, name)
		}
	}
	sort.Strings(actual)
	if !reflect.DeepEqual(compiled, actual) {
		return nil, goAMD64FrameContext("effective/generated compiled source mapping is unbound")
	}
	sizes := types.SizesFor("gc", arch)
	actualImporter := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		if target, mapped := source.selection.ImportMap[path]; mapped {
			path = target
		}
		dependency, present := source.imports[path]
		if !present || dependency.Export == "" {
			return nil, goAMD64FrameContext("missing captured actual compiler export: %s", path)
		}
		data, err := source.read(dependency.Export)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	config := &types.Config{Sizes: sizes, Importer: actualImporter}
	if source.legacyDownloadedModule() {
		config.GoVersion = "go1.16"
	}
	typed, err := config.Check(pkg.Path, fset, syntax, nil)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(typed.Scope().Names(), pkg.Types.Scope().Names()) {
		return nil, goAMD64FrameContext("actual selected declarations differ from supplied types")
	}
	if len(globals) == 1 {
		if err := joinFixedLocalGlobalDeclarations(typed, pkg.Types, syntax, sizes, globals[0]); err != nil {
			return nil, err
		}
	}
	languageType := goAMD64FrameLanguageTypeRole
	if floatingScalars {
		languageType = goAMD64NumericalScalarLanguageType
	}
	declarations := make(map[string]goAMD64FrameDeclaration)
	for _, name := range typed.Scope().Names() {
		if named, ok := typed.Scope().Lookup(name).(*types.TypeName); ok {
			previous, supplied := pkg.Types.Scope().Lookup(name).(*types.TypeName)
			if !supplied || named.IsAlias() != previous.IsAlias() {
				return nil, goAMD64FrameContext("actual local type declaration differs: %s", name)
			}
			// The complete original Go program has already been typechecked.
			// Unrelated interfaces, callbacks, maps or recursive/generic types
			// do not cross an assembly ABI and must not enter its restricted
			// transport grammar. Every type reachable from an actual assembly
			// parameter/result is independently compared in full below.
			continue
		}
		// Bodies and values are independently typechecked, but only original
		// bodyless assembly declarations enter the frame observation table.
		if !bodyless[name] {
			continue
		}
		if entries != nil && !entries[name] {
			// All original sources, bodies, declarations and complete scope
			// names were independently checked above. An unrelated bodyless
			// runtime declaration does not enter this selected ASM entry set.
			continue
		}
		fn, ok := typed.Scope().Lookup(name).(*types.Func)
		previous, supplied := pkg.Types.Scope().Lookup(name).(*types.Func)
		if !ok || !supplied {
			return nil, goAMD64FrameContext("missing actual typed declaration")
		}
		signature := fn.Type().(*types.Signature)
		priorSignature, valid := previous.Type().(*types.Signature)
		if !valid || priorSignature == nil || signature.Recv() != nil || signature.Variadic() || signature.TypeParams().Len() != 0 ||
			priorSignature.Recv() != nil || priorSignature.Variadic() || priorSignature.TypeParams().Len() != 0 {
			return nil, goAMD64FrameContext("custom, generic or variadic declaration transport")
		}
		role := goAMD64FrameNumericTransport
		var language strings.Builder
		for _, tuple := range []*types.Tuple{signature.Params(), signature.Results()} {
			if tuple.Len() > 4096 {
				return nil, goAMD64FrameContext("declaration tuple bound")
			}
			language.WriteString("[")
			for i := 0; i < tuple.Len(); i++ {
				typ := tuple.At(i).Type()
				switch underlying := typ.Underlying().(type) {
				case *types.Basic:
					if floatingScalars && goAMD64NumericalFloatingScalar(typ) {
						if role == goAMD64FrameNumericTransport {
							role = goAMD64FrameFloatingScalarTransport
						}
					} else if underlying.Kind() == types.Bool || opaqueUnsafePointer && underlying.Kind() == types.UnsafePointer {
						role = goAMD64FrameCompositeTransport
					} else if underlying.Info()&types.IsInteger == 0 {
						return nil, goAMD64FrameContext("observation excludes noninteger scalar transport")
					}
				case *types.Pointer, *types.Slice:
					role = goAMD64FrameCompositeTransport
				default:
					return nil, goAMD64FrameContext("by-value aggregate transport needs a separate observation contract")
				}
				identity, err := languageType(typ, sizes, opaqueUnsafePointer)
				if err != nil {
					return nil, err
				}
				fmt.Fprintf(&language, "%q:%s;", tuple.At(i).Name(), identity)
				if language.Len() > 64<<10 {
					return nil, goAMD64FrameContext("declaration language byte bound")
				}
			}
			language.WriteString("]")
		}
		if numericOnly && role != goAMD64FrameNumericTransport {
			return nil, goAMD64FrameContext("fixed-local consumer requires numeric transport, not pointer/slice observation")
		}
		// Named types from two independent typechecks have different object
		// identities. Compare their complete language/layout trees, not Ptr or
		// qualified spelling alone; underlying and pointee changes must fail.
		priorLanguage := strings.Builder{}
		for _, tuple := range []*types.Tuple{priorSignature.Params(), priorSignature.Results()} {
			if tuple.Len() > 4096 {
				return nil, goAMD64FrameContext("supplied declaration tuple bound")
			}
			priorLanguage.WriteString("[")
			for i := 0; i < tuple.Len(); i++ {
				identity, err := languageType(tuple.At(i).Type(), sizes, opaqueUnsafePointer)
				if err != nil {
					return nil, err
				}
				fmt.Fprintf(&priorLanguage, "%q:%s;", tuple.At(i).Name(), identity)
				if priorLanguage.Len() > 64<<10 {
					return nil, goAMD64FrameContext("supplied declaration language byte bound")
				}
			}
			priorLanguage.WriteString("]")
		}
		if language.String() != priorLanguage.String() {
			return nil, goAMD64FrameContext("actual language type/pointee/field identity mismatch: %s", name)
		}
		actual, err := DeriveGoFuncABI0Signature(pkg.Path+"."+name, fn, arch, sizes)
		prior, priorErr := DeriveGoFuncABI0Signature(pkg.Path+"."+name, previous, arch, sizes)
		if err != nil || priorErr != nil || !reflect.DeepEqual(actual, prior) {
			return nil, goAMD64FrameContext("actual typed declaration/layout mismatch: %s", name)
		}
		declarations[actual.Name] = goAMD64FrameDeclaration{signature: actual, transport: role, languageType: language.String()}
	}
	if entries != nil && len(declarations) != len(entries) {
		return nil, goAMD64FrameContext("complete selected ASM entry declaration inventory differs")
	}
	return declarations, nil
}

// A bounded semantic language tree distinguishes equal-sized LLVM pointers,
// named-underlying changes and aggregate element/field models. Sizes belongs
// to the independent go/types model, not an observation of native pointee
// padding (Go1.20 StdSizes differs from its compiler). Only pointer/slice ABI0
// slots are bound to the actual object. No pointee extent, alias or GC grant.
func goAMD64FrameLanguageType(typ types.Type, sizes types.Sizes) (string, error) {
	return goAMD64FrameLanguageTypeRole(typ, sizes, false)
}

// The SDK numerical declaration observer may retain an unsafe.Pointer only as
// an opaque language identity. The ordinary frame observer remains strict;
// no pointee, extent, numerical bytes, GC or physical frame follows from it.
func goAMD64FrameLanguageTypeRole(typ types.Type, sizes types.Sizes, opaqueUnsafePointer bool) (string, error) {
	return goAMD64LanguageTypeRole(typ, sizes, opaqueUnsafePointer, false)
}

func goAMD64NumericalFloatingScalar(typ types.Type) bool {
	for depth := 0; depth <= 32 && typ != nil; depth++ {
		switch concrete := typ.(type) {
		case *types.Basic:
			return concrete.Kind() == types.Float32 || concrete.Kind() == types.Float64
		case *types.Named:
			if concrete.TypeParams().Len() != 0 {
				return false
			}
			typ = concrete.Underlying()
		default:
			if !goAMD64FrameIsAlias(typ) {
				return false // Never sample caller-defined types.Type callbacks.
			}
			rhs := reflect.ValueOf(typ).MethodByName("Rhs")
			if !rhs.IsValid() || rhs.Type().NumIn() != 0 || rhs.Type().NumOut() != 1 {
				return false
			}
			var valid bool
			typ, valid = rhs.Call(nil)[0].Interface().(types.Type)
			if !valid {
				return false
			}
		}
	}
	return false
}

// Only a top-level scalar (including its named/alias identity) selects this
// language role. Pointers, slices and aggregates keep the ordinary recursive
// restrictions; this cannot borrow the broader ABIInternal argument grammar.
func goAMD64NumericalScalarLanguageType(typ types.Type, sizes types.Sizes, opaqueUnsafePointer bool) (string, error) {
	return goAMD64LanguageTypeForSourceRole(typ, sizes, opaqueUnsafePointer, false, goAMD64NumericalFloatingScalar(typ))
}

// The SDK argument role compares language identities only. It never grants
// the ordinary frame observer floating/string storage or a pointee extent.
func goAMD64LanguageTypeRole(typ types.Type, sizes types.Sizes, opaqueUnsafePointer, argumentCarriers bool) (string, error) {
	return goAMD64LanguageTypeForSourceRole(typ, sizes, opaqueUnsafePointer, argumentCarriers, false)
}

func goAMD64LanguageTypeForSourceRole(typ types.Type, sizes types.Sizes, opaqueUnsafePointer, argumentCarriers, floatingScalar bool) (string, error) {
	if sizes == nil {
		return "", goAMD64FrameContext("missing target language layout")
	}
	var output strings.Builder
	active := make(map[types.Type]bool)
	nodes := 0
	var appendType func(types.Type, int) error
	appendType = func(typ types.Type, depth int) error {
		nodes++
		if typ == nil || depth > 32 || nodes > 4096 || active[typ] || output.Len() > 64<<10 {
			return goAMD64FrameContext("recursive or unbounded language type")
		}
		active[typ] = true
		defer delete(active, typ)
		// Check the language role before invoking Sizes: gc Sizes may panic
		// for type parameters. An unknown or generic role is not a layout.
		switch concrete := typ.(type) {
		case *types.Basic:
			if concrete.Info()&(types.IsInteger|types.IsBoolean) == 0 && !(opaqueUnsafePointer && concrete.Kind() == types.UnsafePointer) &&
				!(argumentCarriers && concrete.Info()&(types.IsFloat|types.IsComplex|types.IsString) != 0) &&
				!(floatingScalar && goAMD64NumericalFloatingScalar(concrete)) ||
				concrete.Info()&types.IsUntyped != 0 {
				return goAMD64FrameContext("unsupported noninteger or untyped language type")
			}
		case *types.Named:
			if concrete.TypeParams().Len() != 0 {
				return goAMD64FrameContext("generic language type")
			}
		case *types.Pointer, *types.Slice, *types.Array, *types.Struct:
		default:
			if !goAMD64FrameIsAlias(typ) {
				return goAMD64FrameContext("unknown language type role")
			}
			if method := reflect.ValueOf(typ).MethodByName("TypeParams"); method.IsValid() {
				parameters, ok := method.Call(nil)[0].Interface().(*types.TypeParamList)
				if !ok || parameters.Len() != 0 {
					return goAMD64FrameContext("generic alias language type")
				}
			}
		}
		// Composite identity is written below one node at a time. Asking
		// TypeString to expand an anonymous DAG defeats the node/byte bound.
		spelling := ""
		switch typ.(type) {
		case *types.Basic, *types.Named:
			spelling = types.TypeString(typ, func(pkg *types.Package) string { return pkg.Path() })
		default:
			if goAMD64FrameIsAlias(typ) {
				spelling = types.TypeString(typ, func(pkg *types.Package) string { return pkg.Path() })
			}
		}
		fmt.Fprintf(&output, "(%q:", spelling)
		switch typ := typ.(type) {
		case *types.Basic:
			if opaqueUnsafePointer && typ.Kind() == types.UnsafePointer {
				output.WriteString("opaque_unsafe_pointer")
			} else if typ.Kind() == types.Bool {
				output.WriteString("bool")
			} else if typ.Info()&types.IsInteger != 0 {
				fmt.Fprintf(&output, "integer%d", typ.Kind())
			} else if floatingScalar && goAMD64NumericalFloatingScalar(typ) {
				fmt.Fprintf(&output, "floating_scalar%d", typ.Kind())
			} else if argumentCarriers && typ.Info()&(types.IsFloat|types.IsComplex|types.IsString) != 0 {
				fmt.Fprintf(&output, "argument_scalar%d", typ.Kind())
			} else {
				return goAMD64FrameContext("unsupported noninteger pointee/element")
			}
		case *types.Named:
			if typ.TypeParams().Len() != 0 {
				return goAMD64FrameContext("generic language type")
			}
			output.WriteString("named:")
			if err := appendType(typ.Underlying(), depth+1); err != nil {
				return err
			}
		case *types.Pointer:
			output.WriteString("pointer:")
			if err := appendType(typ.Elem(), depth+1); err != nil {
				return err
			}
		case *types.Slice:
			output.WriteString("slice:")
			if err := appendType(typ.Elem(), depth+1); err != nil {
				return err
			}
		case *types.Array:
			fmt.Fprintf(&output, "array%d:", typ.Len())
			if err := appendType(typ.Elem(), depth+1); err != nil {
				return err
			}
			// Go1.20's Sizes can wrap a large array to zero. Its recorded
			// result is not evidence of a representable concrete layout.
			element, alignment := sizes.Sizeof(typ.Elem()), sizes.Alignof(typ.Elem())
			const maxLayout = int64(1<<63 - 1)
			if typ.Len() < 0 || element < 0 || alignment <= 0 || element > maxLayout-(alignment-1) {
				return goAMD64FrameContext("array element layout is unrepresentable")
			}
			stride := (element + alignment - 1) / alignment * alignment
			if typ.Len() > 0 && stride != 0 && typ.Len()-1 > (maxLayout-element)/stride {
				return goAMD64FrameContext("array language layout overflow")
			}
		case *types.Struct:
			if typ.NumFields() > 4096-nodes {
				return goAMD64FrameContext("language field bound")
			}
			fields := make([]*types.Var, typ.NumFields())
			for i := range fields {
				fields[i] = typ.Field(i)
			}
			// Validate every descendant before Sizes traverses the aggregate:
			// generic/incomplete elements are not a concrete layout.
			for _, field := range fields {
				if err := appendType(field.Type(), depth+1); err != nil {
					return err
				}
			}
			offsets := sizes.Offsetsof(fields)
			output.WriteString("struct:")
			for i, field := range fields {
				pkg := ""
				if field.Pkg() != nil {
					pkg = field.Pkg().Path()
				}
				width := sizes.Sizeof(field.Type())
				if offsets[i] < 0 || width < 0 || offsets[i] > (1<<63-1)-width {
					return goAMD64FrameContext("struct language layout overflow")
				}
				fmt.Fprintf(&output, "%q/%q/%q/%t/%d:", pkg, field.Name(), typ.Tag(i), field.Embedded(), offsets[i])
				if output.Len() > 64<<10 {
					return goAMD64FrameContext("language field metadata byte bound")
				}
			}
		default:
			// Alias is newer than Go1.20. Its actual spelling and the local
			// TypeName.IsAlias role are retained alongside the complete RHS.
			// Underlying alone would lose a named RHS's language identity.
			if !goAMD64FrameIsAlias(typ) {
				return goAMD64FrameContext("unknown language type role")
			}
			method := reflect.ValueOf(typ).MethodByName("Rhs")
			if !method.IsValid() || method.Type().NumIn() != 0 || method.Type().NumOut() != 1 {
				return goAMD64FrameContext("unknown alias RHS contract")
			}
			rhs, ok := method.Call(nil)[0].Interface().(types.Type)
			if !ok {
				return goAMD64FrameContext("missing alias RHS language type")
			}
			output.WriteString("alias:")
			if err := appendType(rhs, depth+1); err != nil {
				return err
			}
		}
		size, align := sizes.Sizeof(typ), sizes.Alignof(typ)
		if size < 0 || align <= 0 {
			return goAMD64FrameContext("language type lacks a concrete target layout")
		}
		fmt.Fprintf(&output, ";model_size=%d,model_align=%d)", size, align)
		return nil
	}
	if err := appendType(typ, 0); err != nil {
		return "", err
	}
	if output.Len() > 64<<10 {
		return "", goAMD64FrameContext("language type byte bound")
	}
	return output.String(), nil
}

func goAMD64FrameIsAlias(typ types.Type) bool {
	kind := reflect.TypeOf(typ)
	return kind != nil && kind.Kind() == reflect.Pointer && kind.Elem().PkgPath() == "go/types" && kind.Elem().Name() == "Alias"
}

func (source *GoAMD64FrameSource) preprocess(name string, original []byte) (string, error) {
	if source.sdkFrame != nil {
		return source.preprocessSDKFrame(name, original)
	}
	if len(source.assemblerDefines) == 0 {
		return "", goAMD64FrameContext("CPP lacks its actual assembler macro registration")
	}
	source.origins[filepath.Join(source.request.Directory, name)] = bytes.Count(original, []byte("\n")) + 1
	// The owned asm command passes this exact basename from the canonical
	// package directory; stock Go can retain that relative spelling in -S.
	source.origins[name] = source.origins[filepath.Join(source.request.Directory, name)]
	var expand func(string, []byte) (string, error)
	expand = func(name string, data []byte) (string, error) {
		return PreprocessAssemblySource(string(data), AssemblyPreprocessOptions{FileName: name, Defines: source.assemblerDefines, ReadInclude: func(parent, include string) (string, []byte, error) {
			if filepath.Base(include) != include || include == "go_asm.h" {
				return "", nil, goAMD64FrameContext("generated/relative CPP origin requires qualified metadata")
			}
			file := filepath.Join(source.request.Directory, include)
			if _, err := os.Stat(file); os.IsNotExist(err) {
				file = filepath.Join(source.env["GOROOT"], "pkg", "include", include)
			}
			data, err := source.read(file)
			if err != nil {
				return "", nil, err
			}
			source.origins[file] = bytes.Count(data, []byte("\n")) + 1
			return file, data, nil
		}})
	}
	return expand(name, original)
}

var goAMD64FrameRow = regexp.MustCompile(`^\s*0x([0-9a-f]+) [0-9]+ \((.+)\)\s+(.+)$`)

// Zero-frame ordinary entries have no automatic saved-BP slot. They remain
// in the complete source inventory without acquiring private local backing.
func goAMD64FrameNativeLocals(frame int64) int64 {
	if frame == 0 {
		return 0
	}
	return frame + 8
}

func goAMD64FrameListing(listing []byte, file *File, pkg GoPackage, origins map[string]int) (map[string]goAMD64FrameFunction, error) {
	return goAMD64FrameListingWithObservations(listing, file, pkg, origins, nil, nil)
}

func goAMD64FrameListingWithNumericalObject(listing []byte, file *File, pkg GoPackage, origins map[string]int, texts []gostaticstorage.TextRecord) (map[string]goAMD64FrameFunction, error) {
	return goAMD64FrameListingWithObservations(listing, file, pkg, origins, texts, nil)
}

func goAMD64FrameListingWithWindowsUnwind(listing []byte, file *File, pkg GoPackage, origins map[string]int, unwind *gostaticstorage.WindowsAMD64AssemblyUnwind) (map[string]goAMD64FrameFunction, error) {
	return goAMD64FrameListingWithObservations(listing, file, pkg, origins, nil, unwind)
}

// These independent, target-specific observation routes retain the strict
// default parser. A numerical relocation does not authorize Windows metadata,
// and Windows unwind metadata does not authorize a numerical memory read.
func goAMD64FrameListingWithObservations(listing []byte, file *File, pkg GoPackage, origins map[string]int, texts []gostaticstorage.TextRecord, unwind *gostaticstorage.WindowsAMD64AssemblyUnwind) (map[string]goAMD64FrameFunction, error) {
	if texts != nil && unwind != nil {
		return nil, goAMD64FrameContext("mixed target-specific object observation roles")
	}
	return goAMD64FrameListingRecords(listing, file, pkg, origins, texts, unwind, nil, "", "", "")
}

func goAMD64FrameListingWithDataObject(listing []byte, file *File, pkg GoPackage, origins map[string]int,
	data *gostaticstorage.AMD64AssemblyData, unwind *gostaticstorage.WindowsAMD64AssemblyUnwind, target, directory, root string) (map[string]goAMD64FrameFunction, error) {
	if data == nil || unwind != nil && !reflect.DeepEqual(data.Member.Texts, unwind.Texts) {
		return nil, goAMD64FrameContext("mixed DATA/Windows complete object TEXT observations differ")
	}
	texts, err := goAMD64FrameSourceTexts(listing, data)
	if err != nil {
		return nil, err
	}
	return goAMD64FrameListingRecords(listing, file, pkg, origins, texts, unwind, data, target, directory, root)
}

func goAMD64FrameListingRecords(listing []byte, file *File, pkg GoPackage, origins map[string]int, texts []gostaticstorage.TextRecord, unwind *gostaticstorage.WindowsAMD64AssemblyUnwind, data *gostaticstorage.AMD64AssemblyData, splitTarget, splitDirectory, splitRoot string) (map[string]goAMD64FrameFunction, error) {
	leaves, err := goAMD64FramePrivateLeaves(file, pkg)
	if err != nil {
		return nil, err
	}
	if len(leaves) != 0 && data == nil {
		return nil, goAMD64FrameContext("private leaf requires complete original source/object association")
	}
	names := make(map[string]string)
	if data != nil {
		if len(data.TextOrder) != len(file.Funcs) {
			return nil, goAMD64FrameContext("complete parsed/source-object TEXT counts differ")
		}
		for index, fn := range file.Funcs {
			names[fn.Sym] = data.TextOrder[index].Name
		}
	}
	functions := make(map[string]goAMD64FrameFunction)
	objects := make(map[string]gostaticstorage.TextRecord)
	metadata := make(map[string][]byte)
	metadataHeaders := make(map[string]string)
	seenMetadata := make(map[string]bool)
	if unwind != nil {
		for _, record := range unwind.Unwind {
			if _, duplicate := metadata[record.Name]; duplicate {
				return nil, goAMD64FrameContext("duplicate actual Windows metadata definition")
			}
			metadata[record.Name] = record.Data
			header := record.Name + " SSEHUNWINDINFO dupok size=12"
			if unwind.ListingAlignment {
				header += " align=0x4"
			}
			metadataHeaders[header] = record.Name
		}
	}
	scanner := bufio.NewScanner(bytes.NewReader(listing))
	scanner.Buffer(nil, 4<<20)
	name := ""
	metadataName := ""
	var metadataBytes []byte
	var expected int64
	textIndex, relocationIndex := -1, 0
	finishRelocations := func() error {
		if texts != nil && textIndex >= 0 && relocationIndex != len(texts[textIndex].Relocations) {
			return goAMD64FrameContext("missing complete original object/listing relocations")
		}
		return nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if header, valid := parseGoAMD64NativeHeader(line); valid {
			if !header.ordinaryFrameRole() {
				return nil, goAMD64FrameContext("native header has no ordinary/private frame entry role")
			}
			if !header.NoSplit && (splitTarget == "" || texts == nil) {
				return nil, goAMD64FrameContext("automatic split layout requires its complete original object")
			}
			if metadataName != "" {
				return nil, goAMD64FrameContext("Windows listing TEXT follows its metadata inventory")
			}
			if err := finishRelocations(); err != nil {
				return nil, err
			}
			if texts != nil {
				textIndex++
				relocationIndex = 0
				if textIndex >= len(texts) || texts[textIndex].Name != header.Symbol {
					return nil, goAMD64FrameContext("reordered or foreign complete object/listing TEXT")
				}
				abi := uint16(0)
				if header.Static {
					abi = 65535
				}
				if texts[textIndex].Kind != header.Kind || texts[textIndex].ABI != abi ||
					header.objectFlags() != texts[textIndex].Flags&0x19 {
					return nil, goAMD64FrameContext("complete object/listing TEXT kind or ABI differs")
				}
				if splitTarget != "" && texts[textIndex].Flags != header.objectFlags() {
					return nil, goAMD64FrameContext("complete object/listing TEXT NOSPLIT flags differ")
				}
				objects[header.Symbol] = texts[textIndex]
			} else if header.Kind != 1 {
				return nil, goAMD64FrameContext("FIPS TEXT needs its complete original object kind")
			}
			if name != "" && int64(len(functions[name].code)) != expected {
				return nil, goAMD64FrameContext("partial native symbol bytes")
			}
			name = header.Symbol
			if _, duplicate := functions[name]; duplicate {
				return nil, goAMD64FrameContext("duplicate native TEXT")
			}
			expected = int64(header.Size)
			functions[name] = goAMD64FrameFunction{locals: int64(header.Locals), args: header.Args, split: !header.NoSplit, positions: make(map[int]string), sourcePositions: make(map[int][]goAMD64FrameSourcePosition)}
			continue
		}
		if header, exists := metadataHeaders[line]; exists {
			if seenMetadata[header] || metadata[header] == nil ||
				name != "" && int64(len(functions[name].code)) != expected ||
				metadataName != "" && !bytes.Equal(metadataBytes, metadata[metadataName]) {
				return nil, goAMD64FrameContext("unbound, duplicate or incomplete Windows metadata listing")
			}
			metadataName, name, metadataBytes = header, "", nil
			seenMetadata[metadataName] = true
			continue
		}
		if metadataName != "" {
			row, err := goAMD64WindowsUnwindByteRow(line, len(metadataBytes), metadata[metadataName])
			if err != nil {
				return nil, err
			}
			metadataBytes = append(metadataBytes, row...)
			continue
		}
		if name == "" {
			return nil, goAMD64FrameContext("native listing contains unbound/unknown symbol")
		}
		fn := functions[name]
		if strings.HasPrefix(strings.TrimSpace(line), "rel ") && texts != nil {
			relocations := texts[textIndex].Relocations
			if relocationIndex >= len(relocations) {
				return nil, goAMD64FrameContext("extra actual object/listing relocation")
			}
			expectedLine := goAMD64FrameNumericalRelocationLine(relocations[relocationIndex])
			if splitTarget != "" {
				expectedLine = ""
			}
			if data != nil {
				expectedLine = goAMD64FrameDataRelocationLine(relocations[relocationIndex], data)
			}
			if fn.split && splitTarget != "" {
				if generated := goAMD64FrameSplitRelocationLine(relocations[relocationIndex], splitTarget); generated != "" {
					expectedLine = generated
				}
			}
			if expectedLine == "" || strings.Join(strings.Fields(line), " ") != expectedLine {
				return nil, goAMD64FrameContext("foreign, duplicate or reordered actual object/listing relocation")
			}
			relocationIndex++
			continue
		}
		if row := goAMD64FrameRow.FindStringSubmatch(line); row != nil {
			pc, err := strconv.ParseInt(row[1], 16, 32)
			if err != nil || pc < 0 || pc >= expected {
				return nil, goAMD64FrameContext("invalid original instruction/source PC")
			}
			separator := strings.LastIndexByte(row[2], ':')
			if separator < 0 {
				return nil, goAMD64FrameContext("unbound original instruction/source path")
			}
			line, err := strconv.Atoi(row[2][separator+1:])
			if err != nil || line <= 0 || line > origins[row[2][:separator]] {
				return nil, goAMD64FrameContext("unbound original instruction/source line: %s", row[2])
			}
			fn.positions[int(pc)] += row[2] + "\t" + row[3] + "\n"
			fn.sourcePositions[int(pc)] = append(fn.sourcePositions[int(pc)],
				goAMD64FrameSourcePosition{row[2][:separator], line})
		} else {
			pc, code, err := goAssemblyListingByteRow(line)
			if err != nil || pc != len(fn.code) || int64(pc+len(code)) > expected {
				return nil, goAMD64FrameContext("invalid native byte record or gap/overlap: %v", err)
			}
			fn.code = append(fn.code, code...)
		}
		functions[name] = fn
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if err := finishRelocations(); err != nil {
		return nil, err
	}
	if texts != nil && textIndex+1 != len(texts) {
		return nil, goAMD64FrameContext("missing complete original object/listing TEXT")
	}
	if len(functions) != len(file.Funcs) ||
		metadataName == "" && (name == "" || int64(len(functions[name].code)) != expected) ||
		metadataName != "" && !bytes.Equal(metadataBytes, metadata[metadataName]) ||
		len(seenMetadata) != len(metadata) {
		return nil, goAMD64FrameContext("missing/incomplete original TEXT inventory")
	}
	bound := make(map[string]goAMD64FrameFunction)
	for _, original := range file.Funcs {
		symbol := pkg.Path + "." + strings.TrimPrefix(original.Sym, "·")
		if leaves[original.Sym] {
			symbol = names[original.Sym]
		}
		observed := symbol
		fn, exists := functions[observed]
		if !exists {
			// Older actual Go objects retain PkgIdxSelf's empty-package
			// spelling. Keep those observed bytes/symbols distinct from the
			// package identity independently selected and type-checked above.
			observed = `"".` + strings.TrimPrefix(original.Sym, "·")
			fn, exists = functions[observed]
		}
		declaration, declared := pkg.Types.Scope().Lookup(strings.TrimPrefix(original.Sym, "·")).(*types.Func)
		fn.sourceSymbol, fn.privateLeaf = original.Sym, leaves[original.Sym]
		if text, found := objects[observed]; found {
			fn.nativeABI = text.ABI
		}
		if fn.privateLeaf {
			if !exists || declared || fn.split || fn.locals != goAMD64FrameNativeLocals(original.FrameSize) ||
				fn.args != 0 && fn.args != -0x80000000 {
				return nil, goAMD64FrameContext("original private leaf/native frame identity differs")
			}
		} else if !exists || !declared || original.FrameSize < 0 || original.FrameSize%8 != 0 || fn.locals != goAMD64FrameNativeLocals(original.FrameSize) || fn.args != original.ArgSize || strings.Contains(original.Sym, "<") {
			return nil, goAMD64FrameContext("original ABI0 TEXT/declaration/frame identity mismatch")
		}
		var err error
		if !fn.privateLeaf {
			fn.signature, err = DeriveGoFuncABI0Signature(symbol, declaration, "amd64", types.SizesFor("gc", "amd64"))
			if err != nil {
				return nil, err
			}
			var end int64
			for _, slot := range append(append([]FrameSlot(nil), fn.signature.Frame.Params...), fn.signature.Frame.Results...) {
				if next := slot.Offset + frameTypeSize(slot.Type, 8); next > end {
					end = next
				}
			}
			if !goabi.MatchesABI0TextSize("amd64", fn.args, end) {
				return nil, goAMD64FrameContext("original TEXT args disagree with actual declaration")
			}
		}
		if err := goAMD64FrameSourceInstructions(original, leaves); err != nil {
			return nil, err
		}
		if original.FrameSize > 0 {
			shape := fn
			if fn.split {
				shape, err = goAMD64FrameSplitProjection(fn, objects[observed], original.FrameSize, splitTarget, splitDirectory, splitRoot, data)
				if err != nil {
					return nil, err
				}
				fn.prologue = shape.prologue
			}
			calls, err := goAMD64FramePrivateCallPCs(shape, original, objects[observed], leaves, names)
			if err != nil {
				return nil, err
			}
			if err := goAMD64FrameMachineShapeWithCalls(shape, original.FrameSize, calls); err != nil {
				return nil, err
			}
		} else if fn.privateLeaf {
			if err := goAMD64FrameMachineShapeWithCalls(fn, 0, nil); err != nil {
				return nil, err
			}
		} else if fn.split {
			return nil, goAMD64FrameContext("zero-frame split entry needs its separate native layout")
		}
		if text, exists := objects[observed]; exists && !bytes.Equal(text.Code, fn.code) {
			return nil, goAMD64FrameContext("complete original object/listing TEXT bytes differ")
		}
		fn.listingSymbol, fn.objectSymbol = observed, symbol
		bound[symbol] = fn
	}
	return bound, nil
}

func goAMD64FrameSourceInstructions(fn Func, privateLeaves ...map[string]bool) error {
	localJump := false
	for _, ins := range fn.Instrs {
		switch ins.Op {
		case OpCALL:
			if len(privateLeaves) != 1 || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
				return goAMD64FrameContext("original CALL needs its complete same-source leaf")
			}
			name, offset, valid := parseSBRef(ins.Args[0].Sym)
			if !valid || offset != 0 || !privateLeaves[0][name] {
				return goAMD64FrameContext("original CALL needs its complete same-source leaf")
			}
		case "BYTE", "WORD", "LONG", "QUAD", "PCALIGN", "PCALIGNMAX":
			return goAMD64FrameContext("raw, calling or address-sensitive original frame requires a later source contract")
		case OpJMP:
			localJump = true
		case OpRET:
			if len(ins.Args) != 0 {
				return goAMD64FrameContext("nonordinary original RET transport")
			}
		}
	}
	if localJump {
		// Share the complete local-label inventory with the fixed-frame CFG.
		// A named branch within this TEXT is not an external tail-call contract.
		_, _, err := fixedLocalEdges(fn)
		return err
	}
	return nil
}

func goAMD64FrameMachineShape(fn goAMD64FrameFunction, frame int64) error {
	return goAMD64FrameMachineShapeWithCalls(fn, frame, nil)
}

func goAMD64FrameMachineShapeWithCalls(fn goAMD64FrameFunction, frame int64, calls map[int]bool) error {
	var instructions []x86asm.Inst
	starts := make(map[int]bool)
	for pc := 0; pc < len(fn.code); {
		var ins x86asm.Inst
		if x86NumericalVectorPrefix(fn.code[pc:], 64) {
			length, err := x86NumericalVectorBoundary(fn.code[pc:], 64)
			if err != nil || length <= 0 {
				end := pc + 15
				if end > len(fn.code) {
					end = len(fn.code)
				}
				return goAMD64FrameContext("unbound original vector machine instruction at PC %d (%x): %v", pc+fn.prologue, fn.code[pc:end], err)
			}
			// Exact boundaries only: these cannot impersonate the scalar
			// automatic prologue, epilogue, native CALL or return below.
			ins.Len = length
		} else if _, length, known, err := decodedX86SHAInstructionWithMemory(fn.code[pc:], 64, x86RawMemoryDecoder{physicalPC: true}); known || err != nil {
			if err != nil || length <= 0 {
				return goAMD64FrameContext("unbound original SHA machine instruction at PC %d: %v", pc+fn.prologue, err)
			}
			ins.Len = length // No scalar prologue, epilogue or branch authority.
		} else if _, length, _, known, err := decodeX86RawADXWithMemory(fn.code[pc:], 0, 64, x86RawMemoryDecoder{physicalPC: true}); known || err != nil {
			if err != nil || length <= 0 {
				return goAMD64FrameContext("unbound original ADX machine instruction at PC %d: %v", pc+fn.prologue, err)
			}
			ins.Len = length // The numerical boundary decoder grants no scalar frame role.
		} else {
			var err error
			ins, err = x86asm.Decode(fn.code[pc:], 64)
			if err != nil || ins.Len == 0 || ins.Op == 0 || ins.Op == x86asm.LCALL ||
				ins.Op == x86asm.CALL && (!calls[pc] || ins.Len != 5) {
				return goAMD64FrameContext("unknown or calling original machine instruction in %s at PC %d (%s): %v",
					fn.sourceSymbol, pc+fn.prologue, fn.positions[pc], err)
			}
		}
		if len(fn.positions[pc]) == 0 {
			return goAMD64FrameContext("machine instruction lacks its original source position")
		}
		// A projected source body must not jump back into the discarded
		// automatic stack check or forward into its runtime retry tail.
		if relative, ok := ins.Args[0].(x86asm.Rel); ok && fn.split && ins.Op != x86asm.CALL {
			destination := pc + ins.Len + int(relative)
			if destination < 0 || destination >= len(fn.code) {
				return goAMD64FrameContext("source branch enters an automatic split region")
			}
		}
		starts[pc] = true
		instructions = append(instructions, ins)
		pc += ins.Len
	}
	for pc := range fn.positions {
		if !starts[pc] {
			return goAMD64FrameContext("original source position is not a machine instruction boundary")
		}
	}
	if frame == 0 {
		returns := 0
		for _, ins := range instructions {
			if ins.Op == x86asm.PUSH || ins.Op == x86asm.POP {
				return goAMD64FrameContext("private leaf acquired an implicit native BP/SP frame")
			}
			for _, arg := range ins.Args {
				if reg, ok := arg.(x86asm.Reg); ok && (reg == x86asm.RSP || reg == x86asm.ESP || reg == x86asm.SP || reg == x86asm.SPB) {
					return goAMD64FrameContext("private leaf machine instruction observes its physical SP")
				}
				if memory, ok := arg.(x86asm.Mem); ok && (memory.Base == x86asm.RSP || memory.Index == x86asm.RSP) {
					return goAMD64FrameContext("private leaf machine memory observes its physical SP")
				}
			}
			if ins.Op == x86asm.RET {
				returns++
			}
		}
		if returns == 0 {
			return goAMD64FrameContext("private leaf has no original native return")
		}
		return goAMD64FrameMachineBranches(instructions, starts)
	}
	if len(instructions) < 6 {
		return goAMD64FrameContext("partial automatic BP/SP frame")
	}
	first, second, third := instructions[0], instructions[1], instructions[2]
	push := first.Op == x86asm.PUSH && first.Args[0] == x86asm.RBP &&
		second.Op == x86asm.MOV && second.Args[0] == x86asm.RBP && second.Args[1] == x86asm.RSP &&
		goAMD64FrameStackAdjustment(third, -frame)
	slot := x86asm.Mem{Base: x86asm.RSP, Scale: 1, Disp: frame}
	stored := goAMD64FrameStackAdjustment(first, -frame-8) &&
		second.Op == x86asm.MOV && second.Args[0] == slot && second.Args[1] == x86asm.RBP && second.DataSize == 64 &&
		third.Op == x86asm.LEA && third.Args[0] == x86asm.RBP && third.Args[1] == slot && third.DataSize == 64
	if !push && !stored {
		return goAMD64FrameContext("unrecognized automatic BP/SP prologue")
	}
	// Source control flow may return before the physical end of TEXT, then
	// close the final block with a local backedge. No source edge may enter an
	// automatic prologue or skip part of a return's automatic stack restoration.
	starts[0], starts[first.Len], starts[first.Len+second.Len] = false, false, false
	returns := 0
	pc := 0
	for i, ins := range instructions {
		if ins.Op == x86asm.RET {
			returns++
			if i < 2 {
				return goAMD64FrameContext("partial original RET epilogue")
			}
			penultimate, previous := instructions[i-2], instructions[i-1]
			pushReturn := push && previous.Op == x86asm.POP && previous.Args[0] == x86asm.RBP &&
				goAMD64FrameStackAdjustment(penultimate, frame)
			storedReturn := stored && penultimate.Op == x86asm.MOV && penultimate.Args[0] == x86asm.RBP && penultimate.Args[1] == slot && penultimate.DataSize == 64 &&
				goAMD64FrameStackAdjustment(previous, frame+8)
			if !pushReturn && !storedReturn {
				return goAMD64FrameContext("unrecognized original RET epilogue")
			}
			starts[pc], starts[pc-previous.Len] = false, false
		}
		pc += ins.Len
	}
	last := instructions[len(instructions)-1]
	if returns == 0 || last.Op != x86asm.RET && last.Op != x86asm.JMP {
		return goAMD64FrameContext("original frame has no conventional RET")
	}
	return goAMD64FrameMachineBranches(instructions, starts)
}

func goAMD64FrameMachineBranches(instructions []x86asm.Inst, starts map[int]bool) error {
	pc := 0
	for _, ins := range instructions {
		pc += ins.Len
		if ins.Op == x86asm.CALL {
			continue // Exact source/relocation target, not a local body branch.
		}
		relative, direct := ins.Args[0].(x86asm.Rel)
		if ins.Op == x86asm.JMP && !direct || direct && !starts[pc+int(relative)] {
			return goAMD64FrameContext("original branch leaves the source body or enters an automatic frame interior")
		}
	}
	return nil
}

// Go's ADJSP encoder chooses ADD/SUB and a signed immediate together. At
// 128 bytes the opposite operation with -128 has the shorter encoding.
// Validate the exact 64-bit stack delta, not one spelling of that delta.
func goAMD64FrameStackAdjustment(ins x86asm.Inst, delta int64) bool {
	if ins.DataSize != 64 || ins.Args[0] != x86asm.RSP || ins.Args[2] != nil || ins.Args[3] != nil {
		return false
	}
	amount, immediate := ins.Args[1].(x86asm.Imm)
	return immediate && (ins.Op == x86asm.ADD && int64(amount) == delta ||
		ins.Op == x86asm.SUB && int64(amount) == -delta)
}

func (source *GoAMD64FrameSource) verifyObjectListing(ctx context.Context, object string, wanted map[string]goAMD64FrameFunction) error {
	data, err := source.run(ctx, "tool", "objdump", object)
	if err != nil {
		return err
	}
	return goAMD64FrameObjectBytes(data, wanted)
}

func goAMD64FrameObjectBytes(data []byte, wanted map[string]goAMD64FrameFunction) error {
	actual := make(map[string][]byte)
	addresses := make(map[string]uint64)
	name := ""
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 3 && fields[0] == "TEXT" && strings.HasSuffix(fields[1], "(SB)") {
			name = strings.TrimSuffix(fields[1], "(SB)")
			if _, duplicate := actual[name]; duplicate {
				return goAMD64FrameContext("duplicate actual object symbol")
			}
			actual[name] = nil
			continue
		}
		if len(fields) < 4 || name == "" || !strings.HasPrefix(fields[1], "0x") {
			return goAMD64FrameContext("unknown actual object disassembly record")
		}
		value, err := hex.DecodeString(fields[2])
		if err != nil || len(value) == 0 {
			return goAMD64FrameContext("invalid actual object bytes")
		}
		address, err := strconv.ParseUint(strings.TrimPrefix(fields[1], "0x"), 16, 64)
		if len(actual[name]) == 0 {
			addresses[name] = address
		}
		if err != nil || address != addresses[name]+uint64(len(actual[name])) {
			return goAMD64FrameContext("actual object instruction bytes have a gap/overlap")
		}
		actual[name] = append(actual[name], value...)
	}
	if len(actual) != len(wanted) {
		return goAMD64FrameContext("object/listing symbol inventories differ")
	}
	for _, fn := range wanted {
		name := fn.objectSymbol
		if fn.privateLeaf && fn.nativeABI == 65535 {
			// cmd/internal/objfile.goobjName renders the actual static ABI
			// bank as version 1. Do not strip arbitrary symbol suffixes.
			name += "<1>"
		}
		if !bytes.Equal(actual[name], fn.code) {
			return goAMD64FrameContext("object/listing physical bytes differ for %s", fn.objectSymbol)
		}
	}
	return nil
}
