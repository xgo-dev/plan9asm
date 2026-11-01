package gotoolprofile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

const instrumentationSourceRejectionProtocol = "original_instrumented_package_redeclaration_v1"

// This proof covers only actual package-scope redeclarations. It grants no
// export, generated-source, CPP, LLVM-object or runtime credit. Complete original
// source selection and the same-mode compiler are independently prerequisites.
type InstrumentationSourceRejection struct {
	Protocol                 string                              `json:"protocol"`
	Plan                     *InstrumentationOriginalPackagePlan `json:"plan"`
	MarkerObservationID      string                              `json:"marker_observation_id"`
	InvocationConfigSHA256   map[string]string                   `json:"invocation_config_sha256"`
	ExportArgs               []string                            `json:"export_args"`
	ExitCode                 int                                 `json:"exit_code"`
	StdoutSHA256             string                              `json:"stdout_sha256"`
	OriginalDiagnosticSHA256 string                              `json:"original_diagnostic_sha256"`
	Redeclarations           []InstrumentationRedeclaration      `json:"redeclarations"`
}

type InstrumentationDeclarationPosition struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

type InstrumentationRedeclaration struct {
	Name     string                             `json:"name"`
	Previous InstrumentationDeclarationPosition `json:"previous"`
	Current  InstrumentationDeclarationPosition `json:"current"`
}

// Replay the complete selected syntax, never a declaration-name hint from a
// diagnostic. Blank names, multiple init functions, method names and locals do
// not occupy the package declaration namespace. Go line directives need their
// own physical attribution mechanism and cannot enter this proof.
func replayInstrumentationRedeclarations(inventory *InstrumentationOriginalSourceInventory, plan *InstrumentationOriginalPackagePlan) ([]InstrumentationRedeclaration, error) {
	if inventory == nil || plan == nil || len(plan.CgoFiles) != 0 || len(plan.GoFiles) == 0 {
		return nil, fmt.Errorf("redeclaration replay lacks complete ordinary Go source roles")
	}
	set := token.NewFileSet()
	seen := make(map[string]InstrumentationDeclarationPosition)
	result := []InstrumentationRedeclaration{}
	for _, name := range plan.GoFiles {
		contents, found := inventory.Contents[name]
		if !found {
			return nil, fmt.Errorf("redeclaration source is missing")
		}
		file, err := parser.ParseFile(set, name, contents, parser.ParseComments)
		if err != nil || file.Name.Name != plan.PackageName {
			return nil, fmt.Errorf("redeclaration replay has another syntax/package failure: %v", err)
		}
		for _, group := range file.Comments {
			for _, comment := range group.List {
				if strings.HasPrefix(comment.Text, "//line ") || strings.HasPrefix(comment.Text, "/*line ") {
					return nil, fmt.Errorf("redeclaration source has unbound physical line attribution")
				}
			}
		}
		register := func(identifier *ast.Ident) error {
			if identifier.Name == "_" {
				return nil
			}
			if len(seen) >= 32768 || len(result) >= 32768 {
				return fmt.Errorf("redeclaration replay exceeds its finite declaration bound")
			}
			position := set.PositionFor(identifier.Pos(), false)
			current := InstrumentationDeclarationPosition{File: name, Line: position.Line, Column: position.Column}
			if previous, found := seen[identifier.Name]; found {
				result = append(result, InstrumentationRedeclaration{Name: identifier.Name, Previous: previous, Current: current})
			} else {
				seen[identifier.Name] = current
			}
			return nil
		}
		for _, declaration := range file.Decls {
			var names []*ast.Ident
			switch declaration := declaration.(type) {
			case *ast.FuncDecl:
				if declaration.Recv == nil && declaration.Name.Name != "init" {
					names = append(names, declaration.Name)
				}
			case *ast.GenDecl:
				for _, spec := range declaration.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						names = append(names, spec.Name)
					case *ast.ValueSpec:
						names = append(names, spec.Names...)
					}
				}
			}
			for _, name := range names {
				if err := register(name); err != nil {
					return nil, err
				}
			}
		}
	}
	return result, nil
}

func ValidateInstrumentationSourceRejection(input *ConsumerInput, inventory *InstrumentationOriginalSourceInventory, marker *InstrumentationExportObservation, plan *InstrumentationOriginalPackagePlan, proof *InstrumentationSourceRejection) error {
	if proof == nil || plan == nil || proof.Protocol != instrumentationSourceRejectionProtocol || proof.ExitCode != 1 {
		return fmt.Errorf("missing original same-mode redeclaration rejection protocol/exit")
	}
	if err := ValidateInstrumentationExportObservation(marker); err != nil {
		return err
	}
	if err := ValidateInstrumentationOriginalPackagePlan(input, inventory, marker.Early, plan.PackageDirectory, plan.CustomTags, proof.Plan); err != nil {
		return err
	}
	if !reflect.DeepEqual(plan, proof.Plan) || proof.MarkerObservationID != instrumentationObjectSHA(marker) ||
		!reflect.DeepEqual(proof.ExportArgs, instrumentationOriginalCommand(plan, false)) ||
		!discoverySHA256Pattern.MatchString(proof.StdoutSHA256) || !discoverySHA256Pattern.MatchString(proof.OriginalDiagnosticSHA256) ||
		len(proof.InvocationConfigSHA256) < 1 || len(proof.InvocationConfigSHA256) > 2 || proof.InvocationConfigSHA256["go.mod"] == "" {
		return fmt.Errorf("redeclaration rejection changed its original source/tool/command scope")
	}
	for name, digest := range proof.InvocationConfigSHA256 {
		if name != "go.mod" && name != "go.sum" || !discoverySHA256Pattern.MatchString(digest) {
			return fmt.Errorf("redeclaration rejection has an unknown invocation configuration")
		}
	}
	if input.SourceModule == "" && proof.InvocationConfigSHA256["go.mod"] != input.Sources["go.mod"] {
		return fmt.Errorf("main-package source refusal changed its original invocation metadata")
	}
	wanted, err := replayInstrumentationRedeclarations(inventory, plan)
	if err != nil || len(wanted) == 0 || !reflect.DeepEqual(wanted, proof.Redeclarations) {
		return fmt.Errorf("rejection differs from independent complete original declaration replay: %v", err)
	}
	return nil
}

func CaptureInstrumentationSourceRejection(ctx context.Context, binary, invocationDir string, env []string, input *ConsumerInput, inventory *InstrumentationOriginalSourceInventory, marker *InstrumentationExportObservation, plan *InstrumentationOriginalPackagePlan, run Runner) (*InstrumentationSourceRejection, error) {
	if ctx == nil || ctx.Err() != nil || run == nil || !filepath.IsAbs(binary) || !filepath.IsAbs(invocationDir) || plan == nil {
		return nil, fmt.Errorf("source rejection requires a live bounded original invocation")
	}
	if err := ValidateInstrumentationExportObservation(marker); err != nil {
		return nil, err
	}
	if err := ValidateInstrumentationOriginalPackagePlan(input, inventory, marker.Early, plan.PackageDirectory, plan.CustomTags, plan); err != nil {
		return nil, err
	}
	redeclarations, err := replayInstrumentationRedeclarations(inventory, plan)
	if err != nil || len(redeclarations) == 0 {
		return nil, fmt.Errorf("original source lacks a replayable package redeclaration: %v", err)
	}
	guard, err := newInstrumentationRejectionGuard(ctx, binary, invocationDir, env, input, marker, run)
	if err != nil {
		return nil, err
	}
	args := instrumentationOriginalCommand(plan, false)
	stdout, stderr, commandErr := run(ctx, guard.directory, guard.env, binary, args...)
	// Check sources, tools and environment even after an observed command failure.
	guardErr := guard.verify(ctx)
	code, plain := instrumentationRejectionExitCode(commandErr)
	if guardErr != nil || !plain || code != 1 || ctx.Err() != nil {
		return nil, fmt.Errorf("original compiler failure is not a guarded plain source refusal: %w", errors.Join(commandErr, guardErr, ctx.Err()))
	}
	metadata, err := validateInstrumentationRejectedSelection(stdout, input, plan)
	if err != nil {
		return nil, fmt.Errorf("%w; actual original command: %w", err, commandErr)
	}
	if err := validateInstrumentationRedeclarationDiagnostic(stderr, guard.directory, input, plan, redeclarations); err != nil {
		return nil, err
	}
	if err := guard.verify(ctx); err != nil {
		return nil, err
	}
	if err := metadata.verify(); err != nil {
		return nil, err
	}
	proof := &InstrumentationSourceRejection{
		Protocol: instrumentationSourceRejectionProtocol, Plan: plan,
		MarkerObservationID: instrumentationObjectSHA(marker), InvocationConfigSHA256: guard.configs,
		ExportArgs: args, ExitCode: 1, StdoutSHA256: bytesSHA256(stdout),
		OriginalDiagnosticSHA256: bytesSHA256(stderr), Redeclarations: redeclarations,
	}
	return proof, ValidateInstrumentationSourceRejection(input, inventory, marker, plan, proof)
}

// RunBounded wraps a normal exit in one error chain. A joined timeout,
// overflow, transport or cleanup failure is not that plain compiler exit.
func instrumentationRejectionExitCode(err error) (int, bool) {
	for err != nil {
		switch current := err.(type) {
		case *exec.ExitError:
			return current.ExitCode(), true
		case interface{ Unwrap() []error }:
			return 0, false
		case interface{ Unwrap() error }:
			err = current.Unwrap()
		default:
			return 0, false
		}
	}
	return 0, false
}

func validateInstrumentationRedeclarationDiagnostic(data []byte, invocationDir string, input *ConsumerInput, plan *InstrumentationOriginalPackagePlan, declarations []InstrumentationRedeclaration) error {
	if len(data) == 0 || len(data) > commandOutputLimit || !strings.HasSuffix(string(data), "\n") {
		return fmt.Errorf("missing or over-bound complete original compiler diagnostic")
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 1+2*len(declarations) || lines[0] != "# "+plan.PackagePath {
		return fmt.Errorf("source rejection has unknown, incomplete or mixed diagnostics")
	}
	positionMatches := func(line, message string, expected InstrumentationDeclarationPosition) bool {
		suffix := fmt.Sprintf(":%d:%d: %s", expected.Line, expected.Column, message)
		if !strings.HasSuffix(line, suffix) {
			return false
		}
		filename := strings.TrimSuffix(line, suffix)
		if !filepath.IsAbs(filename) {
			filename = filepath.Join(invocationDir, filename)
		}
		physical, err := CPPRegularSource(input.SourceRoot, expected.File)
		if err != nil {
			return false
		}
		resolved, err := sourcepath.Resolve(filename)
		return err == nil && resolved == physical
	}
	for index, declaration := range declarations {
		if !positionMatches(lines[1+2*index], declaration.Name+" redeclared in this block", declaration.Current) ||
			!strings.HasPrefix(lines[2+2*index], "\t") ||
			!positionMatches(strings.TrimPrefix(lines[2+2*index], "\t"), "other declaration of "+declaration.Name, declaration.Previous) {
			return fmt.Errorf("compiler refusal lacks complete physical attribution to the original redeclarations")
		}
	}
	return nil
}

type instrumentationRejectedMetadata struct {
	path, physical, digest string
}

func (metadata instrumentationRejectedMetadata) verify() error {
	info, err := os.Lstat(metadata.path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return fmt.Errorf("actual rejected module metadata is missing, redirected or over-bound")
	}
	physical, err := sourcepath.Resolve(metadata.path)
	if err != nil || physical != metadata.physical {
		return fmt.Errorf("actual rejected module metadata changed its physical origin")
	}
	if digest, err := FileSHA256(physical); err != nil || digest != metadata.digest {
		return fmt.Errorf("actual rejected module metadata changed original bytes")
	}
	return nil
}

func validateInstrumentationRejectedSelection(data []byte, input *ConsumerInput, plan *InstrumentationOriginalPackagePlan) (*instrumentationRejectedMetadata, error) {
	if len(data) == 0 || len(data) > commandOutputLimit {
		return nil, fmt.Errorf("source refusal lacks bounded actual package-selection JSON")
	}
	var selected struct {
		Dir, ImportPath, Name, Export, BuildID, ForTest             string
		GoFiles, CompiledGoFiles, SFiles                            []string
		CgoFiles, CFiles, CXXFiles, FFiles, SwigFiles, SwigCXXFiles []string
		Incomplete                                                  bool
		Error                                                       json.RawMessage
		DepsErrors                                                  []json.RawMessage
		Module                                                      *struct {
			Path, Version, Dir, GoMod string
			Main                      bool
			Replace                   *struct {
				Path, Version, Dir string
				Replace            json.RawMessage
			}
		}
	}
	if err := json.Unmarshal(data, &selected); err != nil {
		return nil, err
	}
	root, err := sourcepath.Resolve(input.SourceRoot)
	if err != nil {
		return nil, err
	}
	directory, err := sourcepath.Resolve(selected.Dir)
	if err != nil || directory != filepath.Join(root, filepath.FromSlash(plan.PackageDirectory)) ||
		selected.ImportPath != plan.PackagePath || selected.Name != plan.PackageName || selected.ForTest != "" ||
		selected.Export != "" || selected.BuildID != "" || selected.Incomplete || len(selected.Error) != 0 || len(selected.DepsErrors) != 0 ||
		len(selected.CgoFiles)+len(selected.CFiles)+len(selected.CXXFiles)+len(selected.FFiles)+len(selected.SwigFiles)+len(selected.SwigCXXFiles) != 0 {
		return nil, fmt.Errorf("source refusal has foreign, generated, native, incomplete or exported package roles")
	}
	for _, files := range []struct{ actual, wanted []string }{
		{selected.GoFiles, plan.GoFiles}, {selected.CompiledGoFiles, plan.GoFiles}, {selected.SFiles, plan.SFiles},
	} {
		var actual []string
		for _, name := range files.actual {
			if path.Base(name) != name || !CPPLocalSource(name) {
				return nil, fmt.Errorf("source refusal has unbound compiled source origins")
			}
			actual = append(actual, path.Join(plan.PackageDirectory, name))
		}
		if !reflect.DeepEqual(actual, files.wanted) {
			return nil, fmt.Errorf("source refusal changed complete actual Go/ASM selection")
		}
	}
	owner := selected.Module
	if owner == nil || owner.Path != input.Module || owner.Version != input.Version || owner.Main != (input.SourceModule == "") {
		return nil, fmt.Errorf("source refusal changed actual module/version/main ownership")
	}
	if input.SourceModule != "" && input.SourceModule != input.Module {
		if owner.Replace == nil || owner.Replace.Path != input.SourceModule || owner.Replace.Version != input.Version || len(owner.Replace.Replace) != 0 {
			return nil, fmt.Errorf("source refusal lacks its exact versioned namespace replacement")
		}
		replaced, err := sourcepath.Resolve(owner.Replace.Dir)
		if err != nil || replaced != root {
			return nil, fmt.Errorf("source refusal changed original replaced archive root")
		}
	} else if owner.Replace != nil {
		return nil, fmt.Errorf("source refusal has an unregistered replacement")
	}
	owned, err := sourcepath.Resolve(owner.Dir)
	if err != nil || owned != root {
		return nil, fmt.Errorf("source refusal changed original module root")
	}
	physical, err := sourcepath.Resolve(owner.GoMod)
	if err != nil || !discoverySHA256Pattern.MatchString(input.Sources["go.mod"]) {
		return nil, fmt.Errorf("rejected package metadata lacks its original physical/byte identity")
	}
	metadata := &instrumentationRejectedMetadata{path: owner.GoMod, physical: physical, digest: input.Sources["go.mod"]}
	return metadata, metadata.verify()
}
