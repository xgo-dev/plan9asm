package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

const ciProtocol = "actual_go_selected_ci_partitions_v1"

type ciScope struct {
	SourceSHA   string            `json:"source_sha256"`
	Head        string            `json:"git_head"`
	SDKSource   string            `json:"sdk_source_sha256"`
	GoVersion   string            `json:"go_version"`
	Environment map[string]string `json:"effective_environment"`
	Tools       map[string]string `json:"tool_sha256"`
}

type ciPlan struct {
	Protocol     string   `json:"protocol"`
	Package      string   `json:"package"`
	Flags        []string `json:"go_flags"`
	Timeout      string   `json:"per_root_timeout"`
	Selector     string   `json:"selector"`
	Isolate      string   `json:"isolated_root"`
	Owners       int      `json:"owners"`
	Inventory    []string `json:"full_inventory"`
	Benchmarks   []string `json:"benchmarks_not_executed"`
	InventorySHA string   `json:"full_inventory_sha256"`
	Selected     []string `json:"selected_inventory"`
	SelectedSHA  string   `json:"selected_inventory_sha256"`
	Scope        ciScope  `json:"scope"`
}

func ciNamesSHA(names []string) string {
	hash := sha256.Sum256([]byte(strings.Join(names, "\n") + "\n"))
	return hex.EncodeToString(hash[:])
}

func ciAssignments(plan ciPlan) ([][]string, error) {
	if plan.Protocol != ciProtocol || plan.Owners < 2 || plan.Owners > 1024 || plan.Selector == "" || strings.Contains(plan.Selector, "/") {
		return nil, fmt.Errorf("registered CI protocol, slash-free selector and 2..1024 owners required")
	}
	selector, err := regexp.Compile(plan.Selector)
	if err != nil {
		return nil, err
	}
	if _, err := partition(plan.Inventory, 1); err != nil {
		return nil, err
	}
	if !sort.StringsAreSorted(plan.Inventory) || plan.InventorySHA != ciNamesSHA(plan.Inventory) {
		return nil, fmt.Errorf("full inventory identity differs")
	}
	var selected []string
	for _, name := range plan.Inventory {
		if selector.MatchString(name) {
			selected = append(selected, name)
		}
	}
	if len(selected) == 0 || !reflect.DeepEqual(selected, plan.Selected) || plan.SelectedSHA != ciNamesSHA(selected) {
		return nil, fmt.Errorf("selected inventory is not the complete selector projection")
	}
	isolated := false
	owners := make([][]string, plan.Owners)
	for _, name := range selected {
		owner := 0
		if name == plan.Isolate {
			isolated = true
		} else {
			hash := sha256.Sum256([]byte(name))
			owner = 1 + int(binary.BigEndian.Uint64(hash[:8])%uint64(plan.Owners-1))
		}
		owners[owner] = append(owners[owner], name)
	}
	if !isolated || !validName(plan.Isolate) {
		return nil, fmt.Errorf("isolated root must exist exactly once in actual selected inventory")
	}
	return owners, nil
}
