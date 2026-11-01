package gotoolprofile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
)

// CaptureInstrumentationNativeHeaderQuerySources also returns the unchanged
// signature-only input required by an actual metadata query. Both projections
// come from one independently selected/exported physical graph, not from two
// agreeing JSON records. Only the separate property result can reduce planning.
// Original ZIP/signed module and SDK authentication are prerequisites, exactly
// as for the existing type-source capture; caller JSON is not source authority.
func CaptureInstrumentationNativeHeaderQuerySources(ctx context.Context, binary, directory string, env []string,
	input *InstrumentationConsumerInput, modules []TestModuleSource, run Runner,
) (*InstrumentationNativeHeaderSourceProof, *InstrumentationTypeSourceProof, error) {
	proof := &InstrumentationNativeHeaderSourceProof{Protocol: InstrumentationNativeHeaderSourcesProtocol, GoMods: make(map[string]string)}
	var signatures InstrumentationTypeSourceProof
	types, err := captureInstrumentationTypeSources(ctx, binary, directory, env, input, modules, run,
		func(input *InstrumentationConsumerInput, types *InstrumentationTypeSourceProof, captured *instrumentationTypeGraph) error {
			if err := retainInstrumentationRequiredTypeSources(input, types, captured); err != nil {
				return err
			}
			data, err := json.Marshal(types)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(data, &signatures); err != nil {
				return err
			}
			proof.Types = types
			for id, file := range captured.moduleFiles {
				data, err := os.ReadFile(file)
				if err != nil || len(data) > instrumentationOriginalFileLimit || bytesSHA256(data) != captured.hashes[file] {
					return fmt.Errorf("native property original module metadata changed during capture: %v", err)
				}
				proof.GoMods[id] = string(data)
			}
			load := func(pkg *InstrumentationTypeSourcePackage) error {
				files := captured.files[pkg.Dependency.Source.PackagePath]
				if len(files) != len(pkg.Dependency.Source.GoSHA256) {
					return fmt.Errorf("native property dependency lost its complete compiler source paths")
				}
				pkg.Contents = make(map[string]string)
				for name, file := range files {
					data, err := os.ReadFile(file)
					captured.bytes += len(data)
					if err != nil || len(data) > instrumentationOriginalFileLimit || captured.bytes > instrumentationOriginalInventoryLimit || bytesSHA256(data) != pkg.Dependency.Source.GoSHA256[name] {
						return fmt.Errorf("native property dependency bytes changed or exceed their bound: %v", err)
					}
					pkg.Contents[name] = string(data)
				}
				return nil
			}
			_, _, _, _, err = instrumentationNativeHeaderReplay(input, proof, load)
			return err
		})
	if err != nil {
		return nil, nil, err
	}
	proof.Types = types
	if _, _, err := ReplayInstrumentationNativeGeneratedHeader(input, proof); err != nil {
		return nil, nil, err
	}
	return proof, &signatures, nil
}
