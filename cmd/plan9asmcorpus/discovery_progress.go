package main

import "fmt"

type discoveryCandidateProgress struct {
	Module                string                                `json:"module"`
	Version               string                                `json:"version"`
	Status                string                                `json:"status"`
	InvalidSourceReason   string                                `json:"invalid_source_reason,omitempty"`
	InvalidSourceEvidence []discoveryInvalidMachineCodeEvidence `json:"invalid_source_evidence,omitempty"`
	Superseded            *discoverySupersededSkip              `json:"superseded,omitempty"`
	PrivateExtension      *discoveryPrivateExtensionSkip        `json:"private_extension,omitempty"`
}

// This is a derived view, not a mutable flag attached to a scanned version.
// Keeping test evidence outside the immutable scan ledger avoids making a
// report invalidate its own input fingerprint when it is published.
type discoveryProgress struct {
	SchemaVersion             int                          `json:"schema_version"`
	ValidationKind            string                       `json:"validation_kind"`
	Source                    discoverySourceIdentity      `json:"source"`
	LedgerSHA256              string                       `json:"ledger_sha256"`
	Targets                   []string                     `json:"targets"`
	Provenance                *discoveryCorpusProvenance   `json:"provenance,omitempty"`
	ShardCount                int                          `json:"shard_count"`
	ReportedShards            int                          `json:"reported_shards"`
	PassedShards              int                          `json:"passed_shards"`
	FailedShards              int                          `json:"failed_shards"`
	PartialShards             []int                        `json:"partial_shards"`
	PendingShards             []int                        `json:"pending_shards"`
	CandidateTotal            int                          `json:"candidate_total"`
	Passed                    int                          `json:"passed"`
	Failed                    int                          `json:"failed"`
	NotApplicable             int                          `json:"not_applicable"`
	SkippedInvalidSource      int                          `json:"skipped_invalid_source"`
	SkippedSuperseded         int                          `json:"skipped_superseded"`
	SkippedPrivateExtension   int                          `json:"skipped_private_extension"`
	Pending                   int                          `json:"pending"`
	DiscoveredAsmFiles        int                          `json:"discovered_asm_files"`
	Translations              int                          `json:"translations"`
	NotApplicableTranslations int                          `json:"not_applicable_translations"`
	Complete                  bool                         `json:"complete"`
	Verified                  bool                         `json:"verified"`
	Candidates                []discoveryCandidateProgress `json:"candidates"`
}

func collectDiscoveryProgress(ledgerPath, reportsPath string, targets []string, source discoverySourceIdentity, shardCount int, repoRoot ...string) (discoveryProgress, error) {
	if shardCount < 0 {
		return discoveryProgress{}, fmt.Errorf("invalid discovery shard count %d", shardCount)
	}
	if len(repoRoot) > 1 {
		return discoveryProgress{}, fmt.Errorf("discovery progress accepts at most one repository root")
	}
	var skips map[string]discoveryInvalidMachineCodeSkip
	var superseded map[string]discoverySupersededSkip
	var privateExtensions map[string]discoveryPrivateExtensionSkip
	if len(repoRoot) == 1 {
		var err error
		skips, err = loadInvalidMachineCodeSkips(repoRoot[0])
		if err != nil {
			return discoveryProgress{}, err
		}
		if skips == nil {
			skips = map[string]discoveryInvalidMachineCodeSkip{}
		}
		superseded, err = loadSupersededSkips(repoRoot[0], ledgerPath)
		if err != nil {
			return discoveryProgress{}, err
		}
		if superseded == nil {
			superseded = map[string]discoverySupersededSkip{}
		}
		privateExtensions, err = loadPrivateExtensionSkips(repoRoot[0], ledgerPath)
		if err != nil {
			return discoveryProgress{}, err
		}
		if privateExtensions == nil {
			privateExtensions = map[string]discoveryPrivateExtensionSkip{}
		}
	}
	progress := discoveryProgress{
		SchemaVersion:  1,
		ValidationKind: "translation_and_llvm22_object_compilation",
		Source:         source,
		Targets:        append([]string(nil), targets...),
		ShardCount:     shardCount,
		PartialShards:  []int{},
		PendingShards:  []int{},
		Candidates:     []discoveryCandidateProgress{},
	}
	if err := auditDiscoveryCorpusReports(ledgerPath, reportsPath, targets, source, skips, superseded, privateExtensions, &progress); err != nil {
		// Never return a plausible partial total after detecting corrupt evidence.
		return discoveryProgress{}, err
	}
	return progress, nil
}
