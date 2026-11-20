package gotoolprofile

import (
	"fmt"
	"go/build"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/module"
)

const instrumentationOriginalPlanProtocol = "actual_go_instrumentation_original_package_plan_v1"

// InstrumentationOriginalPackagePlan is a single original package's complete
// source-selection denominator under one independently observed mode. It is
// never an ordinary selection/exclusion proof or a translation outcome.
// OriginalInputSHA256 binds the entire existing input, including supplemental
// protocols and resources; none of those ordinary proofs becomes a mode proof.
type InstrumentationOriginalPackagePlan struct {
	Protocol              string                          `json:"protocol"`
	OriginalInputSHA256   string                          `json:"original_input_sha256"`
	SourceInventorySHA256 string                          `json:"source_inventory_sha256"`
	ModeProfileID         string                          `json:"mode_profile_id"`
	Target                string                          `json:"target"`
	Mode                  InstrumentationMode             `json:"mode"`
	CGOEnabled            string                          `json:"cgo_enabled"`
	PackageDirectory      string                          `json:"package_directory"`
	PackagePath           string                          `json:"package_path"`
	PackageName           string                          `json:"package_name"`
	CustomTags            []string                        `json:"custom_tags,omitempty"`
	BuildFlags            []string                        `json:"build_flags"`
	GoFiles               []string                        `json:"go_files"`
	CgoFiles              []string                        `json:"cgo_files,omitempty"`
	SFiles                []string                        `json:"s_files"`
	Decisions             []InstrumentationSourceDecision `json:"decisions"`
	Status                string                          `json:"status"`
}

type InstrumentationSourceDecision struct {
	File         string `json:"file"`
	SourceSHA256 string `json:"source_sha256"`
	HeaderSHA256 string `json:"header_sha256"`
	Selected     bool   `json:"selected"`
	ModeRequired bool   `json:"mode_required"`
	Reason       string `json:"reason"`
}

// PlanInstrumentationOriginalPackage replays source predicates, not a tool
// invocation. A mode-required decision compares the same target/CPU/custom
// tags/CGO with instrumentation false; this counterfactual is not a baseline
// export or a CGO=1 observation manufactured from the CGO=0 CPU foundation.
// The caller must independently authenticate these original source inputs
// against the exact ZIP/metadata and retain the existing unchanged guards.
func PlanInstrumentationOriginalPackage(input *ConsumerInput, sources *InstrumentationOriginalSourceInventory, early *InstrumentationEarlyObservation, directory string, tags []string) (*InstrumentationOriginalPackagePlan, error) {
	if input == nil || input.Protocol != ConsumerProtocol || input.Observed == nil || input.ID != ProfileID(input.Observed) ||
		module.CheckPath(input.Module) != nil || input.SourceRoot == "" || !filepath.IsAbs(input.SourceRoot) {
		return nil, fmt.Errorf("missing complete original source/module input")
	}
	if err := ValidateInstrumentationEarlyObservation(early); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(input.Observed, early.BaselineFeatures) {
		return nil, fmt.Errorf("original CPU input differs from the actual mode foundation")
	}
	if directory != "." && !validInstrumentationSourcePath(directory) {
		return nil, fmt.Errorf("noncanonical original package directory")
	}
	if err := validateInstrumentationCustomTags(tags, early); err != nil {
		return nil, err
	}
	if err := ValidateInstrumentationOriginalSourceInventory(input, directory, sources); err != nil {
		return nil, err
	}
	names, present := input.Directories[directory]
	if !present || len(names) == 0 || len(names) > 65536 || !sort.StringsAreSorted(names) {
		return nil, fmt.Errorf("original package lacks its complete canonical directory")
	}
	ctx, err := instrumentationOriginalBuildContext(sources, early, tags, true)
	if err != nil {
		return nil, err
	}
	baseline, err := instrumentationOriginalBuildContext(sources, early, tags, false)
	if err != nil {
		return nil, err
	}
	headerContext := ctx
	headerContext.OpenFile = func(file string) (io.ReadCloser, error) {
		header, found := input.Headers[filepath.ToSlash(file)]
		if !found {
			return nil, fmt.Errorf("missing original selection header: %s", file)
		}
		return io.NopCloser(strings.NewReader(header)), nil
	}
	packagePath := input.Module
	if directory != "." {
		packagePath += "/" + directory
	}
	if module.CheckImportPath(packagePath) != nil {
		return nil, fmt.Errorf("invalid original package import path")
	}
	plan := &InstrumentationOriginalPackagePlan{
		Protocol: instrumentationOriginalPlanProtocol, OriginalInputSHA256: instrumentationOriginalInputSHA(input),
		SourceInventorySHA256: instrumentationObjectSHA(sources),
		ModeProfileID:         InstrumentationEarlyProfileID(early), Target: early.Target, Mode: early.Mode,
		CGOEnabled: early.CGOEnabled, PackageDirectory: directory, PackagePath: packagePath,
		CustomTags: append([]string(nil), tags...), BuildFlags: append([]string(nil), early.BuildFlags...),
		Status: "consumer_pending",
	}
	packageName := ""
	for index, name := range names {
		if path.Base(name) != name || name == "." || name == ".." || index > 0 && name == names[index-1] {
			return nil, fmt.Errorf("invalid or duplicate original directory member")
		}
		file := path.Join(directory, name)
		if path.Ext(name) != ".go" && path.Ext(name) != ".s" {
			continue
		}
		header, found := input.Headers[file]
		if !found || len(header) > 1<<20 || !discoverySHA256Pattern.MatchString(input.Sources[file]) {
			return nil, fmt.Errorf("original source lacks a bounded header or full byte identity: %s", file)
		}
		selected, err := ctx.MatchFile(directory, name)
		if err != nil {
			return nil, fmt.Errorf("original mode selection %s: %w", file, err)
		}
		fromHeader, err := headerContext.MatchFile(directory, name)
		if err != nil || fromHeader != selected {
			return nil, fmt.Errorf("original compact header and full source disagree on selection: %s", file)
		}
		withoutMode, err := baseline.MatchFile(directory, name)
		if err != nil {
			return nil, err
		}
		decision := InstrumentationSourceDecision{
			File: file, SourceSHA256: input.Sources[file], HeaderSHA256: bytesSHA256([]byte(header)),
			Selected: selected, ModeRequired: selected && !withoutMode, Reason: "matchfile_excluded",
		}
		if strings.HasSuffix(name, "_test.go") {
			decision.Selected, decision.ModeRequired, decision.Reason = false, false, "not_ordinary_test_source"
		} else if selected {
			decision.Reason = "selected_original_source"
			if path.Ext(name) == ".s" {
				plan.SFiles = append(plan.SFiles, file)
			} else {
				parsed, err := parser.ParseFile(token.NewFileSet(), file, sources.Contents[file], parser.ImportsOnly)
				if err != nil {
					return nil, fmt.Errorf("unproved original Go package/import role: %s", file)
				}
				usesCgo := false
				for _, imported := range parsed.Imports {
					value, err := strconv.Unquote(imported.Path.Value)
					if err != nil {
						return nil, fmt.Errorf("invalid original import literal: %s", file)
					}
					usesCgo = usesCgo || value == "C"
				}
				if usesCgo && early.CGOEnabled == "0" {
					decision.Selected, decision.ModeRequired, decision.Reason = false, false, "cgo_import_disabled"
					plan.Decisions = append(plan.Decisions, decision)
					continue
				}
				if parsed.Name.Name == "documentation" || packageName != "" && packageName != parsed.Name.Name {
					return nil, fmt.Errorf("unproved or conflicting original ordinary Go package role: %s", file)
				}
				packageName = parsed.Name.Name
				if usesCgo {
					plan.CgoFiles = append(plan.CgoFiles, file)
				} else {
					plan.GoFiles = append(plan.GoFiles, file)
				}
			}
		}
		plan.Decisions = append(plan.Decisions, decision)
	}
	plan.PackageName = packageName
	if len(plan.GoFiles)+len(plan.CgoFiles) == 0 || len(plan.SFiles) == 0 {
		return nil, fmt.Errorf("mode package lacks an original ordinary Go/ASM pair; not an exclusion proof")
	}
	return plan, nil
}

func ValidateInstrumentationOriginalPackagePlan(input *ConsumerInput, sources *InstrumentationOriginalSourceInventory, early *InstrumentationEarlyObservation, directory string, tags []string, plan *InstrumentationOriginalPackagePlan) error {
	if plan == nil || plan.Protocol != instrumentationOriginalPlanProtocol {
		return fmt.Errorf("missing original instrumentation planning protocol")
	}
	wanted, err := PlanInstrumentationOriginalPackage(input, sources, early, directory, tags)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(plan, wanted) {
		return fmt.Errorf("original mode plan lost or changed a source/profile/tag scope")
	}
	return nil
}

func instrumentationOriginalInputSHA(input *ConsumerInput) string {
	copy := *input
	// Physical roots are invocation-only. All original/source/resource/protocol
	// fields remain in this binding, including fields not consumed by phase 1.
	copy.SourceRoot, copy.ProxyGoModPath = "", ""
	return instrumentationObjectSHA(&copy)
}

func instrumentationOriginalBuildContext(sources *InstrumentationOriginalSourceInventory, early *InstrumentationEarlyObservation, tags []string, mode bool) (build.Context, error) {
	minor, err := goMinor(early.SourceRules.GoVersion)
	if err != nil {
		return build.Context{}, err
	}
	ctx := build.Default
	ctx.JoinPath = path.Join
	ctx.GOOS, ctx.GOARCH = early.Environment["GOOS"], early.Environment["GOARCH"]
	ctx.Compiler, ctx.CgoEnabled = "gc", early.CGOEnabled == "1"
	ctx.BuildTags = append([]string(nil), tags...)
	if mode {
		ctx.BuildTags = append(ctx.BuildTags, string(early.Mode))
	}
	ctx.ToolTags = append([]string(nil), early.BaselineFeatures.ToolTags...)
	ctx.ReleaseTags = nil
	for version := 1; version <= minor; version++ {
		ctx.ReleaseTags = append(ctx.ReleaseTags, fmt.Sprintf("go1.%d", version))
	}
	ctx.OpenFile = func(file string) (io.ReadCloser, error) {
		header, found := sources.Contents[file]
		if !found {
			return nil, fmt.Errorf("uncaptured original selection input: %s", file)
		}
		return io.NopCloser(strings.NewReader(header)), nil
	}
	return ctx, nil
}

func validInstrumentationSourcePath(file string) bool {
	return CPPLocalSource(file)
}

func validateInstrumentationCustomTags(tags []string, early *InstrumentationEarlyObservation) error {
	if len(tags) > 16 || !sort.StringsAreSorted(tags) {
		return fmt.Errorf("custom tag scope exceeds its bound or is noncanonical")
	}
	for index, tag := range tags {
		expr, err := constraint.Parse("//go:build " + tag)
		one, ok := expr.(*constraint.TagExpr)
		_, builtin := early.MarkerSelection[tag]
		if err != nil || !ok || one.Tag != tag || index > 0 && tag == tags[index-1] || builtin ||
			tag == "race" || tag == "msan" || tag == "asan" || tag == "cgo" || tag == "gc" || tag == "gccgo" || strings.HasPrefix(tag, "go1.") ||
			strings.HasPrefix(tag, "goexperiment.") {
			return fmt.Errorf("custom tags cannot impersonate mode/builtin flags: %q", tag)
		}
	}
	return nil
}
