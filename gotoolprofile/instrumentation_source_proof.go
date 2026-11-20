package gotoolprofile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
)

const instrumentationSourceProofProtocol = "actual_go_instrumentation_rule_sources_v1"
const instrumentationSourceProofJSONLimit = 16 << 20

// InstrumentationSourceProof retains three bounded original tool sources,
// not a self-reported Supported flag. Offline readers replay the complete
// registered syntax and digests; only production rechecks authenticate these
// bytes to the observed tool tree and driver. Inventory users should retain
// one hash-addressed observation rather than copying it into each scope.
type InstrumentationSourceProof struct {
	Protocol           string            `json:"protocol"`
	GoVersion          string            `json:"go_version"`
	SourceText         map[string]string `json:"source_text"`
	SourceSHA256       map[string]string `json:"source_sha256"`
	RegistrationSHA256 map[string]string `json:"registration_ast_sha256"`
}

func CaptureInstrumentationSourceProof(root, version string) (*InstrumentationSourceProof, error) {
	rules, err := CaptureInstrumentationSourceRules(root, version)
	if err != nil {
		return nil, err
	}
	proof := &InstrumentationSourceProof{
		Protocol: instrumentationSourceProofProtocol, GoVersion: version,
		SourceText: make(map[string]string), SourceSHA256: rules.SourceHashes(),
		RegistrationSHA256: rules.RegistrationHashes(),
	}
	for _, name := range instrumentationRuleSources {
		data, err := readInstrumentationRegistration(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return nil, fmt.Errorf("read actual instrumentation source before portable capture: %s: %w", name, err)
		}
		if bytesSHA256(data) != proof.SourceSHA256[name] {
			return nil, fmt.Errorf("actual instrumentation source changed before portable capture: %s", name)
		}
		proof.SourceText[name] = string(data)
	}
	if _, err := ReplayInstrumentationSourceProof(proof); err != nil {
		return nil, err
	}
	if err := rules.Recheck(); err != nil {
		return nil, err
	}
	return proof, nil
}

func DecodeInstrumentationSourceProof(reader io.Reader) (*InstrumentationSourceProof, error) {
	if reader == nil {
		return nil, fmt.Errorf("missing instrumentation source-proof reader")
	}
	data, err := io.ReadAll(io.LimitReader(reader, instrumentationSourceProofJSONLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read instrumentation source-proof JSON: %w", err)
	}
	if len(data) > instrumentationSourceProofJSONLimit {
		return nil, fmt.Errorf("instrumentation source-proof JSON exceeds its byte bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var proof InstrumentationSourceProof
	if err := decoder.Decode(&proof); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("instrumentation source-proof JSON contains trailing input")
	}
	if _, err := ReplayInstrumentationSourceProof(&proof); err != nil {
		return nil, err
	}
	return &proof, nil
}

func ReplayInstrumentationSourceProof(proof *InstrumentationSourceProof) (*InstrumentationSourceRules, error) {
	if proof == nil || proof.Protocol != instrumentationSourceProofProtocol {
		return nil, fmt.Errorf("missing complete instrumentation source-rule protocol")
	}
	minor, err := goMinor(proof.GoVersion)
	if err != nil || minor < 20 || minor > 27 {
		return nil, fmt.Errorf("unregistered instrumentation source-rule version")
	}
	if len(proof.SourceText) != len(instrumentationRuleSources) || len(proof.SourceSHA256) != len(instrumentationRuleSources) || len(proof.RegistrationSHA256) != 4 {
		return nil, fmt.Errorf("incomplete or additional instrumentation source-rule inputs")
	}
	contents := make(map[string][]byte)
	for _, name := range instrumentationRuleSources {
		text, present := proof.SourceText[name]
		if !present || len(text) == 0 || len(text) > instrumentationRegistrationByteLimit {
			return nil, fmt.Errorf("missing or over-bound instrumentation source: %s", name)
		}
		data := []byte(text)
		if !discoverySHA256Pattern.MatchString(proof.SourceSHA256[name]) || proof.SourceSHA256[name] != bytesSHA256(data) {
			return nil, fmt.Errorf("instrumentation source bytes differ from their digest: %s", name)
		}
		contents[name] = data
	}
	rules, err := replayInstrumentationRuleSources("", proof.GoVersion, contents)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(proof.RegistrationSHA256, rules.registration) {
		return nil, fmt.Errorf("instrumentation source-rule AST evidence does not match complete original sources")
	}
	if !reflect.DeepEqual(rules.registration, instrumentationRuleRegistrations(minor)) {
		return nil, fmt.Errorf("instrumentation source-rule AST is outside its audited Go-version registration")
	}
	return rules, nil
}

// These are fingerprints of complete Go function ASTs, not support lists.
// Original source audits cover Go 1.20.14, 1.21.13, 1.22.12, 1.23.12,
// 1.24.13, 1.25.14, 1.26.8 and 1.27.1. Offline replay must not accept a
// self-consistent rewritten table paired with fabricated hashes.
func instrumentationRuleRegistrations(minor int) map[string]string {
	registration := map[string]string{
		"instrumentInit":        instrumentationInitRegistration,
		"RaceDetectorSupported": "f1077a853d15f529b979311e75e49657047b411dd25755e761507790e52bc19d",
		"MSanSupported":         "98c808b64cf52346cb385372298f0766ecc0d5531edcfaea22c86a3a4b891ecd",
		"ASanSupported":         "65371a8e429e1c91409dc53ded81e1350fc40b15be906c2d251661a9420acb12",
	}
	switch {
	case minor <= 22:
		registration["RaceDetectorSupported"] = "07ebe2ac0fe0dd91355ef1c9695b13b503c3a70f352572a1089ab787cda47c05"
	case minor <= 24:
		registration["RaceDetectorSupported"] = "95447113f45d943fb1ce1c39192534bec6470449235b2a5e2101346abb471b86"
	case minor == 25:
		registration["RaceDetectorSupported"] = "1b319ef10d602e24610a779974ad2eb3627c17fae84a2e8e2dc3b44d92f9a59e"
	}
	if minor <= 21 {
		registration["MSanSupported"] = "3ba0479097ba90f8cffea03acdc0676902de4007a83ab05f1ac832cc95c4abf7"
		registration["ASanSupported"] = "14108d20a2612a3ed49f8e6067a22e2e57958e2a3e5a980fea44fff2c2671504"
	}
	return registration
}
