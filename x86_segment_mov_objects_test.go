package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86SegmentMOVFunction struct {
	name                string
	width, addressSpace int
}

func x86SegmentMOVCompleteSource(t *testing.T, arch string) (string, string, []x86SegmentMOVFunction) {
	t.Helper()
	var source, declarations strings.Builder
	var functions []x86SegmentMOVFunction
	appendFunction := func(assembly, declaration string, width, space int) {
		name := fmt.Sprintf("segment%d", len(functions))
		if strings.Count(assembly, "·view(SB)") != 1 || strings.Count(declaration, "view(") != 1 {
			t.Fatal("complete segment fixture lost its one source/type identity")
		}
		source.WriteString(strings.Replace(assembly, "·view(SB)", "·"+name+"(SB)", 1))
		declarations.WriteString(strings.Replace(declaration, "view(", name+"(", 1) + "\n")
		functions = append(functions, x86SegmentMOVFunction{name, width, space})
	}
	addresses := []string{"fixed", "fixed-zero", "base", "segment-index-scale1", "segment-index-scale2", "segment-index-scale4", "segment-index-scale8"}
	if arch == "386" {
		addresses = append(addresses, "mode32-BP")
	}
	for _, row := range x86SegmentMOVRows(arch) {
		for _, segment := range []string{"FS", "GS"} {
			space := 257
			if segment == "GS" {
				space = 256
			}
			for _, address := range addresses {
				for _, dead := range []bool{false, true} {
					assembly, declaration := x86SegmentMOVFixture(t, arch, row, segment, address, dead)
					appendFunction(assembly, declaration, row.width, space)
				}
			}
			assembly, declaration := x86SegmentMOVVoidFixture(arch, row, segment)
			appendFunction(assembly, declaration, row.width, space)
			for _, address := range []string{"fixed", "base"} {
				assembly, declaration := x86SegmentMOVVoidAddressFixture(arch, row, segment, address)
				appendFunction(assembly, declaration, row.width, space)
			}
		}
	}
	if arch == "amd64" {
		for _, segment := range []string{"FS", "GS"} {
			space := 257
			if segment == "GS" {
				space = 256
			}
			for _, alias := range []string{"DH", "BH"} {
				for _, dead := range []bool{false, true} {
					assembly, declaration := x86SegmentMOVREXFixture(t, segment, alias, dead)
					appendFunction(assembly, declaration, 1, space)
				}
			}
		}
	}
	want := 212
	if arch == "386" {
		want = 114
	}
	if len(functions) != want || strings.Count(source.String(), "TEXT ") != want || strings.Count(declarations.String(), "func ") != want {
		t.Fatal("independent complete segment source denominator changed", len(functions), want)
	}
	return source.String(), declarations.String(), functions
}

func x86SegmentMOVTargetCompleteObjects(t *testing.T, arch, triple string) {
	t.Helper()
	known := false
	for _, target := range x86RawReturnTargets {
		known = known || target.arch == arch && target.triple == triple
	}
	if !known {
		t.Fatal("complete segment object owner requires a registered target", arch, triple)
	}
	producer := x86SegmentMOVObserveSelectedEncoder(t)
	if !producer.schema.indexPrefix386 {
		t.Log("historical selected Go producer objects retain all original TEXTs, but its dynamic 386 FS/GS Index forms have no segment prefix; they do not certify equivalence to current named-source LLVM segment reads")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	t.Run(triple, func(t *testing.T) {
		source, declarations, functions := x86SegmentMOVCompleteSource(t, arch)
		x86LEAActualTargetGoObject(t, arch, triple, source)
		names := make([]string, len(functions))
		for index, function := range functions {
			names[index] = function.name
		}
		axes := 0
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
			if err != nil || ir == "" {
				t.Fatal("complete uncut segment MOV source was rejected", err)
			}
			for _, irLevel := range []string{"0", "2"} {
				input := ir
				if irLevel == "2" {
					input = x86DwordProductIROptimize(t, input)
				}
				if strings.Count(input, "\ndefine ") != len(functions) {
					t.Fatal("whole-file translation added or cropped a function", api, irLevel)
				}
				bodies := x86StringMemoryFunctions(t, input, names)
				for _, function := range functions {
					x86SegmentMOVReadBody(t, bodies[function.name], function.width, function.addressSpace)
				}
				for _, backendLevel := range []string{"0", "2"} {
					axes++
					t.Run(api+"/IR"+irLevel+"/backend"+backendLevel, func(t *testing.T) {
						x86PackedStringCompileObject(t, llc, triple, input, "-O"+backendLevel)
					})
				}
			}
		}
		if axes != 12 {
			t.Fatal("complete three-API/IR/backend object denominator changed", axes)
		}
	})
}

func TestX86SegmentMOVLinux386CompleteObjects(t *testing.T) {
	x86SegmentMOVTargetCompleteObjects(t, "386", "i386-unknown-linux-gnu")
}

func TestX86SegmentMOVWindows386CompleteObjects(t *testing.T) {
	x86SegmentMOVTargetCompleteObjects(t, "386", "i686-pc-windows-msvc")
}

func TestX86SegmentMOVDarwinAMD64CompleteObjects(t *testing.T) {
	x86SegmentMOVTargetCompleteObjects(t, "amd64", "x86_64-apple-darwin")
}

func TestX86SegmentMOVLinuxAMD64CompleteObjects(t *testing.T) {
	x86SegmentMOVTargetCompleteObjects(t, "amd64", "x86_64-unknown-linux-gnu")
}

func TestX86SegmentMOVWindowsAMD64CompleteObjects(t *testing.T) {
	x86SegmentMOVTargetCompleteObjects(t, "amd64", "x86_64-pc-windows-msvc")
}
