package main

import (
	"reflect"
	"sort"
	"testing"
)

func testCIPlan() ciPlan {
	names := []string{"FuzzSeeds", "TestAlpha", "TestBeta", "TestGiant", "TestOther"}
	selected := []string{"TestAlpha", "TestBeta", "TestGiant"}
	return ciPlan{Protocol: ciProtocol, Selector: "^(TestAlpha|TestBeta|TestGiant)$", Isolate: "TestGiant", Owners: 16, Inventory: names, InventorySHA: ciNamesSHA(names), Selected: selected, SelectedSHA: ciNamesSHA(selected)}
}

func TestCIPlanExhaustiveDisjointOwnership(t *testing.T) {
	plan := testCIPlan()
	owners, err := ciAssignments(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(owners[0], []string{"TestGiant"}) || len(owners) != 16 {
		t.Fatal("giant root lost its exclusive budget", owners)
	}
	var union []string
	for _, names := range owners {
		union = append(union, names...)
	}
	sort.Strings(union)
	if !reflect.DeepEqual(union, plan.Selected) || len(plan.Inventory) != 5 {
		t.Fatal("selected/full denominator changed", union)
	}
}

func TestCIPlanRejectsAlteredDenominators(t *testing.T) {
	for name, mutation := range map[string]func(*ciPlan){
		"missing":           func(p *ciPlan) { p.Selected = p.Selected[1:]; p.SelectedSHA = ciNamesSHA(p.Selected) },
		"duplicate":         func(p *ciPlan) { p.Selected[1] = p.Selected[0]; p.SelectedSHA = ciNamesSHA(p.Selected) },
		"unknown":           func(p *ciPlan) { p.Selected[1] = "TestUnknown"; p.SelectedSHA = ciNamesSHA(p.Selected) },
		"foreign selector":  func(p *ciPlan) { p.Selector = "^TestGiant$" },
		"missing isolated":  func(p *ciPlan) { p.Isolate = "TestUnknown" },
		"too few owners":    func(p *ciPlan) { p.Owners = 1 },
		"foreign protocol":  func(p *ciPlan) { p.Protocol = "ordinary" },
		"full hash":         func(p *ciPlan) { p.InventorySHA = "" },
		"unknown full name": func(p *ciPlan) { p.Inventory[0] = "Unknown"; p.InventorySHA = ciNamesSHA(p.Inventory) },
		"slash selector":    func(p *ciPlan) { p.Selector += "/sub" },
	} {
		t.Run(name, func(t *testing.T) {
			plan := testCIPlan()
			mutation(&plan)
			if _, err := ciAssignments(plan); err == nil {
				t.Fatal("altered plan admitted")
			}
		})
	}
}

func TestCIPlanNewPrefixedRootIsNotDropped(t *testing.T) {
	plan := testCIPlan()
	plan.Selector = "^(TestCrossLinuxRuntimeMatrix|TestARM64Conformance|TestARM64RawSQSHLURuntimeSemantics|TestARMIntegerMemoryRuntimeCross|TestARMRawSaturationRuntimeCross)"
	plan.Isolate = "TestCrossLinuxRuntimeMatrix"
	plan.Inventory = []string{"TestARM64Conformance", "TestCrossLinuxRuntimeMatrix", "TestCrossLinuxRuntimeMatrixQEMUOriginalGoAndCArguments", "TestOther"}
	plan.Selected = append([]string(nil), plan.Inventory[:3]...)
	plan.InventorySHA, plan.SelectedSHA = ciNamesSHA(plan.Inventory), ciNamesSHA(plan.Selected)
	owners, err := ciAssignments(plan)
	if err != nil {
		t.Fatal(err)
	}
	var union []string
	for _, names := range owners {
		union = append(union, names...)
	}
	sort.Strings(union)
	if !reflect.DeepEqual(union, plan.Selected) || len(owners[0]) != 1 {
		t.Fatal("new actual prefix root silently omitted or grouped with giant", union)
	}
}
