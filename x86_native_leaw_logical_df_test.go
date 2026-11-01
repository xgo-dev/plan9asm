package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

const (
	x86NativeLEAWSTDCall = `call void asm sideeffect "std", "~{dirflag}"()`
	x86NativeLEAWCLDCall = `call void asm sideeffect "cld", "~{dirflag}"()`
)

// This fixture-only observer is not a source proof or an IR interpreter.
// Native DF side effects and the logical DF slot are independent outputs of
// the existing lowerer. Check their complete straight-line lifecycle before
// isolating the former for the non-x86 companion; never project DF out of the
// original source, packed FLAGS observation or independent C expectation.
func x86NativeLEAWCheckLogicalDFBody(body string) error {
	return x86NativeLEAWCheckTargetDFBody(body, true)
}

func x86NativeLEAWCheckTargetDFBody(body string, native bool) error {
	initial := "store i1 false, ptr %direction_backward"
	backward := "store i1 true, ptr %direction_backward"
	load := "load i1, ptr %direction_backward"
	nativeCount := 0
	if native {
		nativeCount = 1
	}
	for text, count := range map[string]int{
		"%direction_backward = alloca i1": 1,
		initial:                           2,
		backward:                          1,
		load:                              1,
		x86NativeLEAWSTDCall:              nativeCount,
		x86NativeLEAWCLDCall:              nativeCount,
		"asm sideeffect":                  2 * nativeCount,
	} {
		if actual := strings.Count(body, text); actual != count {
			return fmt.Errorf("DF observation %q count=%d, want %d", text, actual, count)
		}
	}
	previous := -1
	markers := []string{initial, backward}
	if native {
		markers = append(markers, x86NativeLEAWSTDCall)
	}
	for _, marker := range append(markers, load) {
		position := strings.Index(body, marker)
		if position <= previous {
			return fmt.Errorf("DF initial/STD/packed observation reordered at %q", marker)
		}
		previous = position
	}
	clear := strings.LastIndex(body, initial)
	if clear <= previous || native && strings.Index(body, x86NativeLEAWCLDCall) <= clear {
		return fmt.Errorf("DF clear is not after its packed observation")
	}
	return nil
}

func x86NativeLEAWRetainedPointerLogicalDF(t *testing.T, ir string, isolateNative bool) string {
	t.Helper()
	for _, variant := range []string{"Direct", "Copied", "Alias"} {
		body := x86StringMemoryFunction(t, ir, "Retain"+variant)
		if err := x86NativeLEAWCheckLogicalDFBody(body); err != nil {
			t.Fatal("complete retained-pointer logical/native DF lifecycle changed", variant, err)
		}
	}
	if strings.Count(ir, x86NativeLEAWSTDCall) != 3 || strings.Count(ir, x86NativeLEAWCLDCall) != 3 ||
		strings.Count(ir, "asm sideeffect") != 6 {
		t.Fatal("module contains missing, extra or unclassified native direction calls")
	}
	if !isolateNative {
		return ir
	}
	// Keep every logical store/load and all numerical/output effects intact.
	// Required native execution retains the six original sideeffect calls.
	for call, marker := range map[string]string{
		x86NativeLEAWSTDCall: "; logical DF companion: native STD isolated",
		x86NativeLEAWCLDCall: "; logical DF companion: native CLD isolated",
	} {
		ir = strings.ReplaceAll(ir, call, marker)
	}
	return ir
}

func TestX86NativeLEAWRetainedPointerLogicalDFInstrumentationIsExact(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		source, declarations := x86NativeLEAWRetainedPointerBatch(arch, "")
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, x86AddressMemoryTargets(arch)[0], api)
				if err != nil {
					t.Fatal("original initialized DF program rejected before driver observation", err)
				}
				if native := x86NativeLEAWRetainedPointerLogicalDF(t, ir, false); native != ir {
					t.Fatal("native driver changed the original LLVM program")
				}
				companion := x86NativeLEAWRetainedPointerLogicalDF(t, ir, true)
				restored := strings.NewReplacer(
					"; logical DF companion: native STD isolated", x86NativeLEAWSTDCall,
					"; logical DF companion: native CLD isolated", x86NativeLEAWCLDCall,
				).Replace(companion)
				if companion == ir || strings.Contains(companion, "asm sideeffect") || restored != ir {
					t.Fatal("portable driver did not isolate exactly the checked native calls")
				}
				for _, variant := range []string{"Direct", "Copied", "Alias"} {
					body := x86StringMemoryFunction(t, ir, "Retain"+variant)
					clear := "store i1 false, ptr %direction_backward"
					position := strings.LastIndex(body, clear)
					reordered := body[:position] + strings.Replace(body[position:], clear, "", 1)
					reordered = strings.Replace(reordered, "load i1, ptr %direction_backward", clear+"\nload i1, ptr %direction_backward", 1)
					for name, changed := range map[string]string{
						"backward missing":  strings.Replace(body, "store i1 true, ptr %direction_backward", "", 1),
						"backward foreign":  strings.Replace(body, "store i1 true, ptr %direction_backward", "store i1 true, ptr %foreign", 1),
						"packed missing":    strings.Replace(body, "load i1, ptr %direction_backward", "load i1, ptr %foreign", 1),
						"clear missing":     strings.Replace(body, "store i1 false, ptr %direction_backward", "", 1),
						"STD missing":       strings.Replace(body, x86NativeLEAWSTDCall, "", 1),
						"CLD missing":       strings.Replace(body, x86NativeLEAWCLDCall, "", 1),
						"native reordered":  strings.NewReplacer(x86NativeLEAWSTDCall, x86NativeLEAWCLDCall, x86NativeLEAWCLDCall, x86NativeLEAWSTDCall).Replace(body),
						"clear before pack": reordered,
						"native foreign":    body + "\ncall void asm sideeffect \"nop\", \"\"()",
					} {
						if changed == body || x86NativeLEAWCheckLogicalDFBody(changed) == nil {
							t.Fatal("driver accepted incomplete or foreign native/logical DF observation", variant, name)
						}
					}
				}
			})
		}
	}
}
