package gotoolprofile

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

var instrumentationRedeclarationKinds = []struct {
	name, declaration string
	column            int
}{
	{"const", "const Item = 1", 7},
	{"var", "var Item int", 5},
	{"type", "type Item int", 6},
	{"func", "func Item() {}", 6},
}

func TestInstrumentationSourceRejectionDeclarationNamespaceFamily(t *testing.T) {
	for _, previous := range instrumentationRedeclarationKinds {
		for _, current := range instrumentationRedeclarationKinds {
			t.Run(previous.name+"/"+current.name, func(t *testing.T) {
				inventory := &InstrumentationOriginalSourceInventory{Contents: map[string]string{
					"a.go": "package sample\n\n" + previous.declaration + "\n",
					"b.go": "package sample\n\n" + current.declaration + "\n",
				}}
				plan := &InstrumentationOriginalPackagePlan{PackageName: "sample", GoFiles: []string{"a.go", "b.go"}}
				actual, err := replayInstrumentationRedeclarations(inventory, plan)
				wanted := []InstrumentationRedeclaration{{
					Name: "Item",
					Previous: InstrumentationDeclarationPosition{
						File: "a.go", Line: 3, Column: previous.column,
					},
					Current: InstrumentationDeclarationPosition{
						File: "b.go", Line: 3, Column: current.column,
					},
				}}
				if err != nil || !reflect.DeepEqual(actual, wanted) {
					t.Fatalf("complete package namespace replay: got=%+v wanted=%+v error=%v", actual, wanted, err)
				}
			})
		}
	}
}

func TestInstrumentationSourceRejectionKeepsPhysicalNamesAndCompleteNamespace(t *testing.T) {
	inventory := &InstrumentationOriginalSourceInventory{Contents: map[string]string{
		"a.go": "package sample\nconst Item = 1\nvar _ int\nfunc init() {}\ntype A struct{}\nfunc (A) Method() {}\n",
		"b.go": "package sample\nvar _ int\nfunc init() {}\ntype B struct{}\nfunc (B) Method() {}\nfunc local() { Item := 2; _ = Item }\nconst directiveText = \"//line somewhere.go:1\"\n",
	}}
	plan := &InstrumentationOriginalPackagePlan{PackageName: "sample", GoFiles: []string{"a.go", "b.go"}}
	actual, err := replayInstrumentationRedeclarations(inventory, plan)
	if err != nil || len(actual) != 0 {
		t.Fatalf("blank/init/method/local/string names are not package redeclarations: %+v %v", actual, err)
	}
	inventory.Contents["b.go"] += "var Item int\ntype Item int\n"
	actual, err = replayInstrumentationRedeclarations(inventory, plan)
	if err != nil || len(actual) != 2 || actual[0].Previous != actual[1].Previous ||
		actual[0].Previous != (InstrumentationDeclarationPosition{File: "a.go", Line: 2, Column: 7}) ||
		actual[0].Current != (InstrumentationDeclarationPosition{File: "b.go", Line: 8, Column: 5}) ||
		actual[1].Current != (InstrumentationDeclarationPosition{File: "b.go", Line: 9, Column: 6}) {
		t.Fatalf("every duplicate must retain the first physical declaration: %+v %v", actual, err)
	}
}

func TestInstrumentationSourceRejectionRefusesIncompleteOrReattributedSyntax(t *testing.T) {
	for name, source := range map[string]string{
		"missing":         "",
		"another package": "package elsewhere\nconst Item = 2\n",
		"syntax failure":  "package sample\nfunc broken(\n",
		"line directive":  "package sample\n//line elsewhere.go:1\nconst Item = 2\n",
		"block directive": "package sample\n/*line elsewhere.go:1*/ const Item = 2\n",
	} {
		t.Run(name, func(t *testing.T) {
			inventory := &InstrumentationOriginalSourceInventory{Contents: map[string]string{
				"a.go": "package sample\nconst Item = 1\n",
			}}
			if source != "" {
				inventory.Contents["b.go"] = source
			}
			plan := &InstrumentationOriginalPackagePlan{PackageName: "sample", GoFiles: []string{"a.go", "b.go"}}
			if _, err := replayInstrumentationRedeclarations(inventory, plan); err == nil {
				t.Fatal("incomplete or physically reattributed source became a declaration witness")
			}
		})
	}
	for name, plan := range map[string]*InstrumentationOriginalPackagePlan{
		"missing plan": nil,
		"empty Go":     {PackageName: "sample"},
		"cgo role":     {PackageName: "sample", GoFiles: []string{"a.go"}, CgoFiles: []string{"cgo.go"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := replayInstrumentationRedeclarations(&InstrumentationOriginalSourceInventory{}, plan); err == nil {
				t.Fatal("missing or different source role became a declaration witness")
			}
		})
	}
}

func TestInstrumentationSourceRejectionBoundsDeclarationWork(t *testing.T) {
	var source strings.Builder
	source.WriteString("package sample\n")
	for index := 0; index <= 32768; index++ {
		fmt.Fprintf(&source, "var Item%d int\n", index)
	}
	inventory := &InstrumentationOriginalSourceInventory{Contents: map[string]string{"a.go": source.String()}}
	plan := &InstrumentationOriginalPackagePlan{PackageName: "sample", GoFiles: []string{"a.go"}}
	if _, err := replayInstrumentationRedeclarations(inventory, plan); err == nil {
		t.Fatal("unbounded declaration inventory was accepted")
	}
}
