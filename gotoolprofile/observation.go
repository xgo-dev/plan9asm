package gotoolprofile

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/xgo-dev/plan9asm/internal/goasmmacros"
)

// Observation is the canonical source/tool-provenance feature evidence shared
// by producers and compiler consumers. It is not a runtime-coverage claim.
type Observation struct {
	Protocol               string            `json:"protocol"`
	Target                 string            `json:"target"`
	Environment            map[string]string `json:"environment"`
	GoVersion              string            `json:"go_version"`
	DriverSHA256           string            `json:"driver_sha256"`
	ToolDirectory          string            `json:"tool_directory"`
	ToolBinarySHA256       map[string]string `json:"tool_binary_sha256"`
	ToolBinaryOrigins      map[string]string `json:"tool_binary_origins"`
	ToolRoutingSHA256      string            `json:"tool_routing_sha256"`
	ToolDispatcherSHA256   string            `json:"tool_dispatcher_sha256"`
	ToolSourceSHA256       map[string]string `json:"tool_source_sha256"`
	ToolTags               []string          `json:"tool_tags"`
	MarkerSelection        map[string]bool   `json:"marker_selection"`
	MarkerSourceSHA256     string            `json:"marker_source_sha256"`
	DriverSelectionSHA256  string            `json:"driver_selection_sha256"`
	EnvStderrSHA256        string            `json:"env_stderr_sha256"`
	EnvRecheckStderrSHA256 string            `json:"env_recheck_stderr_sha256"`
	ListStderrSHA256       string            `json:"list_stderr_sha256"`
}

func ProfileID(observed *Observation) string {
	data, _ := json.Marshal(observed)
	return bytesSHA256(data)
}

func bytesSHA256(data []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func goMinor(version string) (int, error) {
	return goasmmacros.GoMinor(version)
}
