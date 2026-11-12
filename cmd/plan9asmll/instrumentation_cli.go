package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

// The explicit mode entry has separate input/result protocols. It never
// creates an ordinary feature selection, source exclusion or runtime outcome.
type instrumentationCLIOptions struct {
	Profile, Directory, Metadata, OrdinaryProfile string
	Targets                                       []targetSpec
	Patterns, Tags, AsmFiles                      []string
	Module, Output, LLC                           string
	MetadataOnly, SignatureQuery                  bool
	Compile, KeepObject                           bool
	OptLevel, Limit                               int
	AllTargets, ExplicitTargets, ListOnly         bool
	StrictLoad, KeepGoing, Annotate               bool
}

func requestedInstrumentationCLI(flags *flag.FlagSet) bool {
	requested := false
	flags.Visit(func(option *flag.Flag) {
		switch option.Name {
		case "instrumentation-profile", "instrumentation-package-dir", "instrumentation-metadata":
			requested = true
		}
	})
	return requested
}

func validateInstrumentationCLIOptions(options instrumentationCLIOptions) error {
	if options.Profile == "" || options.OrdinaryProfile != "" || options.Output == "" || len(options.Targets) != 1 ||
		len(options.Patterns) != 1 || options.Module == "" || len(options.AsmFiles) == 0 ||
		options.AllTargets || options.ExplicitTargets || options.ListOnly || options.SignatureQuery || options.Limit != 0 ||
		!options.StrictLoad || options.KeepGoing || options.Annotate || options.LLC != "" {
		return fmt.Errorf("mode entry requires one exact original target/package/module/file scope, not ordinary/query/list/matrix evidence")
	}
	if options.MetadataOnly {
		if options.Metadata != "" || options.Compile || options.KeepObject {
			return fmt.Errorf("mode metadata query cannot emit or borrow assembly objects")
		}
	} else if options.Metadata == "" || !options.Compile || !options.KeepObject || options.OptLevel != 0 {
		return fmt.Errorf("mode objects require separate actual metadata and complete LLVM22 O0 objects")
	}
	return nil
}

func runInstrumentationCLI(ctx context.Context, options instrumentationCLIOptions) (*gotoolprofile.InstrumentationInvocationProof, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("mode entry requires a live bounded context")
	}
	if err := validateInstrumentationCLIOptions(options); err != nil {
		return nil, err
	}
	reader, err := os.Open(options.Profile)
	if err != nil {
		return nil, err
	}
	input, readErr := gotoolprofile.DecodeInstrumentationConsumerInput(reader, options.Directory, options.Tags)
	if err := errors.Join(readErr, reader.Close()); err != nil {
		return nil, err
	}
	plan := input.Plan
	if options.Targets[0].Goos+"/"+options.Targets[0].Goarch != plan.Target || options.Patterns[0] != plan.PackagePath ||
		options.Module != input.Original.Module || !equalInstrumentationCLIStrings(options.AsmFiles, plan.SFiles) ||
		!equalInstrumentationCLIStrings(options.Tags, plan.CustomTags) {
		return nil, fmt.Errorf("mode invocation changed its actual original target/package/module/files/custom tags")
	}
	invocation, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	output, err := filepath.Abs(options.Output)
	if err != nil {
		return nil, err
	}
	if options.MetadataOnly {
		consumer, err := captureInstrumentationMetadata(ctx, input, invocation, os.Environ(), output, packages.Load)
		if err != nil {
			return nil, err
		}
		return gotoolprofile.NewInstrumentationInvocation(input, gotoolprofile.InstrumentationMetadataQuery, consumer.Metadata, nil, nil)
	}
	reader, err = os.Open(options.Metadata)
	if err != nil {
		return nil, err
	}
	producer, readErr := gotoolprofile.DecodeInstrumentationInvocation(reader, input, gotoolprofile.InstrumentationMetadataQuery, nil, nil)
	if err := errors.Join(readErr, reader.Close()); err != nil {
		return nil, err
	}
	proof, llvm, err := consumeInstrumentationAssembly(ctx, input, producer.Metadata, invocation, os.Environ(), output)
	if err != nil {
		return nil, err
	}
	return gotoolprofile.NewInstrumentationInvocation(input, gotoolprofile.InstrumentationObjectCompile, producer.Metadata, proof, llvm)
}

func equalInstrumentationCLIStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
