package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

// A parser's no-TEXT result is not evidence of an empty Go object. In
// particular, macros, conditional definitions and invalid source still need
// the actual assembler and its exact package/CPU definitions.
func proveEmptyAssembly(pkg *packages.Package, task asmTask, target string, defines []string, cfg compileConfig) (_ *gotoolprofile.EmptyAssemblyProof, proofErr error) {
	return proveAssemblyListing(pkg, task, target, defines, cfg, func(listing []byte, _ string) error {
		if len(listing) != 0 {
			return fmt.Errorf("actual Go assembler did not emit an empty symbol/data listing\n%s", listing)
		}
		return nil
	})
}

// Both empty and data-only proofs require an independently accepted original
// Go object. Their listing predicates differ; neither replaces LLVM output.
func proveAssemblyListing(pkg *packages.Package, task asmTask, target string, defines []string, cfg compileConfig, accept func([]byte, string) error) (_ *gotoolprofile.EmptyAssemblyProof, proofErr error) {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	binary, err := exec.LookPath("go")
	if err != nil {
		return nil, err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return nil, err
	}
	env := os.Environ()
	parts := strings.Split(target, "/")
	if len(parts) != 2 || pkg == nil || pkg.PkgPath == "" {
		return nil, fmt.Errorf("empty object requires an actual package and target")
	}
	env = featureEnvironment(env, map[string]string{"GOOS": parts[0], "GOARCH": parts[1], "CGO_ENABLED": "0"})
	root, name := "", filepath.Base(task.AsmFile)
	proof := &gotoolprofile.EmptyAssemblyProof{Protocol: gotoolprofile.EmptyAssemblyProtocol, Target: target, PackagePath: pkg.PkgPath}
	if cfg.Feature != nil {
		env, root = cfg.Feature.Env, cfg.Feature.Root
		proof.ProfileID, proof.GoVersion = cfg.Feature.ID, cfg.Feature.Observed.GoVersion
		proof.AsmToolSHA256 = cfg.Feature.Observed.ToolBinarySHA256["asm"]
		name, err = cfg.Feature.sourceName(task.AsmFile)
		if err != nil {
			return nil, err
		}
	}
	if mode := cfg.nativeListingMode; mode != nil {
		if cfg.Feature != nil || mode.Input == nil || mode.Metadata == nil || mode.Source == nil ||
			mode.Input.Plan.Target != target || mode.Input.Plan.PackagePath != pkg.PkgPath {
			return nil, fmt.Errorf("native assembly listing has a mixed or missing actual mode scope")
		}
		if err := gotoolprofile.ValidateInstrumentationMetadata(mode.Input, mode.Input.Plan.PackageDirectory, mode.Input.Plan.CustomTags, mode.Metadata); err != nil {
			return nil, err
		}
		if err := mode.verifySources(); err != nil {
			return nil, err
		}
		defer func() { proofErr = errors.Join(proofErr, mode.verifySources()) }()
		env, root = mode.Source.Env, mode.Source.Root
		proof.ProfileID = mode.Input.ID
		proof.GoVersion = mode.Input.Observation.Early.BaselineFeatures.GoVersion
		proof.AsmToolSHA256 = mode.Input.Observation.Early.ModeTools.BinarySHA256["asm"]
		name, err = mode.Source.sourceName(task.AsmFile)
		if err != nil {
			return nil, err
		}
		if _, err := gotoolprofile.CPPRegularSource(mode.Source.Dir, name); err != nil {
			return nil, err
		}
	}
	if root == "" {
		output, stderr, err := gotoolprofile.RunBounded(ctx, "", env, binary, "env", "GOROOT", "GOVERSION")
		if err != nil {
			return nil, err
		}
		fields := strings.Split(strings.TrimSpace(string(output)), "\n")
		if len(stderr) != 0 || len(fields) != 2 {
			return nil, fmt.Errorf("original assembly listing lacks its actual SDK root/version")
		}
		root, proof.GoVersion = strings.TrimSuffix(fields[0], "\r"), fields[1]
	}
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("empty object assembler requires the actual absolute GOROOT")
	}
	proof.File, proof.SourceSHA256 = name, ""
	proof.SourceSHA256, err = gotoolprofile.FileSHA256(task.AsmFile)
	if err != nil {
		return nil, err
	}
	if mode := cfg.nativeListingMode; mode != nil && proof.SourceSHA256 != mode.Input.Original.Sources[name] {
		return nil, fmt.Errorf("native assembly listing lost the actual original mode source")
	}
	defer func() {
		after, err := gotoolprofile.FileSHA256(task.AsmFile)
		if err == nil && after != proof.SourceSHA256 {
			err = fmt.Errorf("empty-object assembly source changed during its actual Go check")
		}
		proofErr = errors.Join(proofErr, err)
	}()
	owned, err := os.MkdirTemp("", "plan9asm-empty-object-")
	if err != nil {
		return nil, err
	}
	defer func() { proofErr = errors.Join(proofErr, os.RemoveAll(owned)) }()
	object := filepath.Join(owned, "source.o")
	dir := filepath.Dir(task.AsmFile)
	args := []string{"tool", "asm", "-S", "-p", pkg.PkgPath, "-I", dir}
	var definitions map[string]string
	needsHeader := false
	if cfg.Feature != nil && cfg.Feature.Proof != nil && cfg.Feature.Proof.GeneratedHeaders != nil {
		needsHeader = true
		for _, header := range cfg.Feature.Proof.GeneratedHeaders.Headers {
			if header.PackagePath == pkg.PkgPath {
				definitions = header.Definitions
			}
		}
	}
	if mode := cfg.nativeListingMode; mode != nil {
		definitions = mode.Metadata.Headers[0].Header.Definitions
		needsHeader = true
	}
	if needsHeader {
		data, err := gotoolprofile.CanonicalGeneratedHeader(definitions)
		if err != nil {
			return nil, fmt.Errorf("native empty-object generated header lacks actual selected package origin: %w", err)
		}
		headerFile := filepath.Join(owned, "go_asm.h")
		if err := os.WriteFile(headerFile, data, 0600); err != nil {
			return nil, err
		}
		before := featureBytesSHA256(data)
		defer func() {
			after, err := gotoolprofile.FileSHA256(headerFile)
			if err == nil && before != after {
				err = fmt.Errorf("actual full generated header changed during native empty-object assembly")
			}
			proofErr = errors.Join(proofErr, err)
		}()
		// The Go-generated object directory follows the original package CWD
		// and precedes tool headers. This is the complete independently
		// compiled header, never cmd/go's earlier empty gensymabis stub.
		args = append(args, "-I", owned)
	}
	args = append(args, "-I", filepath.Join(root, "pkg", "include"), "-o", object)
	for _, define := range defines {
		args = append(args, "-D", define)
	}
	args = append(args, filepath.Base(task.AsmFile))
	listing, stderr, err := gotoolprofile.RunBounded(ctx, dir, env, binary, args...)
	if err != nil {
		return nil, fmt.Errorf("actual Go empty-object assembly: %w", err)
	}
	if len(stderr) != 0 {
		return nil, fmt.Errorf("actual Go assembler emitted unexpected diagnostics: %s", stderr)
	}
	if err := accept(listing, proof.GoVersion); err != nil {
		return nil, err
	}
	if info, err := os.Stat(object); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, fmt.Errorf("actual Go did not generate a nonempty object: %v", err)
	}
	proof.ObjectSHA256, err = gotoolprofile.FileSHA256(object)
	if err != nil {
		return nil, err
	}
	proof.ListingSHA256 = featureBytesSHA256(listing)
	return proof, nil
}
