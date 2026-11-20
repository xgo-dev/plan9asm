package plan9asm

import (
	"fmt"
	"go/ast"
	"reflect"
	"strings"
	"testing"
)

type x86CMOVFixedLocalSourceUnit struct {
	start, end             int
	assembly, declarations string
	names                  []string
}

func x86CMOVFixedLocalObjectSources(kernels []x86CMOVFixedLocalKernel, batch int) ([]x86CMOVFixedLocalSourceUnit, bool) {
	start, end, ok := fixedLocalObjectBatchRange(len(kernels), batch)
	if !ok {
		return nil, false
	}
	var units []x86CMOVFixedLocalSourceUnit
	for chunk := start; chunk < end; chunk += 32 {
		limit := chunk + 32
		if limit > end {
			limit = end
		}
		units = append(units, x86CMOVFixedLocalSourceForRange(kernels, chunk, limit))
	}
	return units, true
}

func x86CMOVFixedLocalSourceForRange(kernels []x86CMOVFixedLocalKernel, start, end int) x86CMOVFixedLocalSourceUnit {
	unit := x86CMOVFixedLocalSourceUnit{start: start, end: end}
	var assembly, declarations strings.Builder
	for _, kernel := range kernels[start:end] {
		assembly.WriteString(kernel.assembly)
		fmt.Fprintf(&declarations, "func %s(a,b uint64) uint64\n", kernel.name)
		unit.names = append(unit.names, "example.invalid/framefixture."+kernel.name)
	}
	unit.assembly, unit.declarations = assembly.String(), declarations.String()
	return unit
}

func TestFixedLocalCMOVObjectSourcesPreserveCompleteOriginalUnion(t *testing.T) {
	kernels := x86CMOVFixedLocalKernels(false)
	runtimeKernels := x86CMOVFixedLocalKernels(true)
	if len(kernels) != 384 || len(runtimeKernels) != 387 ||
		!reflect.DeepEqual(runtimeKernels[:len(kernels)], kernels) {
		t.Fatal("complete CMOV grammar or original runtime GP/SIMD suffix changed")
	}
	// Independent axes prevent a cropped or duplicated producer table from
	// validating its own source union merely by retaining the same count.
	conditions := []string{
		"CC", "CS", "EQ", "GE", "GT", "HI", "LE", "LS",
		"LT", "MI", "NE", "OC", "OS", "PC", "PL", "PS",
	}
	sources := []string{
		"AX", "8(SP)", "tmp(SP)", "UNKNOWN(SP)",
		"tmp+0(SP)", "tmp+(0*4)(SP)", "tmp-8(SP)", "tmp-(2*4)(SP)",
	}
	if !reflect.DeepEqual(x86CMOVAUTOSources, sources[2:]) || len(x86CMOVOracleConditions) != len(conditions) {
		t.Fatal("complete independent CMOV condition/source spelling inventory changed")
	}
	for index, condition := range x86CMOVOracleConditions {
		if condition.name != conditions[index] {
			t.Fatal("original CMOV condition ordering changed", index, condition)
		}
	}
	var originalAssembly, originalDeclarations strings.Builder
	for index, kernel := range kernels {
		operation := "CMOV" + []string{"W", "L", "Q"}[index/128] + conditions[index/8%16]
		if kernel.name != fmt.Sprintf("F%d", index) || kernel.width != []int{2, 4, 8}[index/128] ||
			kernel.condition != index/8%16 || kernel.mode != 0 ||
			kernel.assembly != x86CMOVFixedLocalAssembly(kernel.name, operation, sources[index%8]) ||
			!strings.HasPrefix(kernel.assembly, "TEXT ·"+kernel.name+"(SB),4,$16-24\n") {
			t.Fatal("original condition/width/source ordinal, symbol or ABI changed", index, kernel)
		}
		originalAssembly.WriteString(kernel.assembly)
		fmt.Fprintf(&originalDeclarations, "func F%d(a,b uint64) uint64\n", index)
	}
	for index, kernel := range runtimeKernels[384:] {
		if kernel.name != fmt.Sprintf("F%d", 384+index) || kernel.width != 8 || kernel.mode != index+1 {
			t.Fatal("original runtime private GP/SIMD kernel changed", index, kernel)
		}
	}
	seen, sourceCount := make([]int, len(kernels)), 0
	var actualAssembly, actualDeclarations strings.Builder
	for batch := 0; batch < 6; batch++ {
		start, end, ok := fixedLocalObjectBatchRange(len(kernels), batch)
		if !ok || end-start != 64 {
			t.Fatal("the six complete scheduling owners changed", batch, start, end, ok)
		}
		units, ok := x86CMOVFixedLocalObjectSources(kernels, batch)
		if !ok || len(units) == 0 {
			t.Fatal("missing independently complete original source units", batch)
		}
		next := start
		for _, unit := range units {
			if unit.start != next || unit.end <= unit.start || unit.end > end {
				t.Fatal("source units cropped, overlap or escape the original owner", batch, unit.start, unit.end, next)
			}
			if unit.end-unit.start > 32 {
				t.Error("one five-minute API lease still carries more than 32 complete functions", batch, unit.end-unit.start)
			}
			file, err := Parse(ArchAMD64, unit.assembly)
			if err != nil || file == nil || len(file.Funcs) != unit.end-unit.start || len(unit.names) != len(file.Funcs) {
				t.Fatal("source unit is not an independently complete parsed program", batch, err)
			}
			for index := unit.start; index < unit.end; index++ {
				local := index - unit.start
				if file.Funcs[local].Sym != fmt.Sprintf("·F%d", index) ||
					unit.names[local] != fmt.Sprintf("example.invalid/framefixture.F%d", index) {
					t.Fatal("source unit renamed, reordered or substituted an original function", index)
				}
				seen[index]++
			}
			actualAssembly.WriteString(unit.assembly)
			actualDeclarations.WriteString(unit.declarations)
			next, sourceCount = unit.end, sourceCount+1
		}
		if next != end {
			t.Fatal("source units omitted the end of a complete scheduling owner", batch, next, end)
		}
	}
	if sourceCount != 12 || actualAssembly.String() != originalAssembly.String() ||
		actualDeclarations.String() != originalDeclarations.String() {
		t.Error("independent source units must reproduce all original ASM/declarations in twelve bounded programs", sourceCount)
	}
	for index, owners := range seen {
		if owners != 1 {
			t.Fatal("missing or duplicated original CMOV function", index, owners)
		}
	}
	for _, batch := range []int{-1, 6} {
		if units, ok := x86CMOVFixedLocalObjectSources(kernels, batch); ok || len(units) != 0 {
			t.Fatal("invalid source owner accepted", batch)
		}
	}
	if units, ok := x86CMOVFixedLocalObjectSources(nil, 0); ok || len(units) != 0 {
		t.Fatal("empty original source inventory accepted")
	}

	function := fixedLocalLeaseFunctions(t, "amd64_cmov_fixed_local_test.go")["x86CMOVFixedLocalActualObjects"]
	if function == nil || fixedLocalLeaseCalls(function.Body)["x86CMOVFixedLocalObjectSources"] != 1 {
		t.Error("actual object consumer still captures one unpartitioned scheduling source")
		return
	}
	unitLoops := 0
	ast.Inspect(function.Body, func(node ast.Node) bool {
		loop, ok := node.(*ast.RangeStmt)
		if !ok || !fixedLocalLeaseIdent(loop.X, "units") {
			return true
		}
		unitLoops++
		calls := fixedLocalLeaseCalls(loop.Body)
		if calls["x86CMOVFixedLocalFixture"] != 1 || calls["fixedLocalFreshAPIs"] != 1 {
			t.Error("each source unit requires its own typed namespace and fresh three-API lifecycle")
		}
		ast.Inspect(loop.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fixedLocalLeaseCallName(call) {
			case "x86CMOVFixedLocalFixture":
				if len(call.Args) != 5 {
					t.Fatal("source unit changed its complete typed fixture arguments")
				}
				fixedLocalLeaseRequireArguments(t, &ast.CallExpr{Fun: call.Fun, Args: call.Args[:1]}, "t")
				fixedLocalLeaseRequireArguments(t, &ast.CallExpr{Fun: call.Fun, Args: call.Args[3:]}, "target", "triple")
				for index, field := range []string{"assembly", "declarations"} {
					selected, ok := call.Args[index+1].(*ast.SelectorExpr)
					if !ok || !fixedLocalLeaseIdent(selected.X, "unit") || selected.Sel.Name != field {
						t.Error("source unit substituted the complete original payload", field)
					}
				}
			case "fixedLocalFreshAPIs":
				if len(call.Args) != 6 {
					t.Fatal("source unit lost its complete API consumer")
				}
				fixedLocalLeaseRequireArguments(t, &ast.CallExpr{Fun: call.Fun, Args: call.Args[:4]}, "t", "pkg", "request", "options")
				apis, ok := call.Args[4].(*ast.CompositeLit)
				if !ok || len(apis.Elts) != 3 {
					t.Fatal("source unit lost an independent public API")
				}
				for index, want := range []string{"Translate", "Module", "GoModule"} {
					literal, ok := apis.Elts[index].(*ast.BasicLit)
					if !ok || literal.Value != fmt.Sprintf("%q", want) {
						t.Error("source unit changed its complete three-API plan", want)
					}
				}
			}
			return true
		})
		return true
	})
	if unitLoops != 1 {
		t.Error("source units must drive exactly one independent consumer loop", unitLoops)
	}
}
