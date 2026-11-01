package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func arm64ABI0BoundFixture(t *testing.T) (GoPackage, *File, map[string]FuncSig) {
	t.Helper()
	declaration, source := arm64ABI0TailResultFixture(false, "B")
	pkg, sig := arm64ABI0TailResultSignature(t, declaration)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(symbol string) string { return strings.TrimPrefix(goTextSymbolForResolution(symbol), "·") }
	sigs, err := BindGoARM64ABI0TailDeclarations(pkg, file, resolve, map[string]FuncSig{"Slots": sig})
	if err != nil {
		t.Fatal(err)
	}
	if sigs["Slots"].arm64ABI0TailDeclaration == nil {
		t.Fatalf("actual typed declaration was not consumed: root=%#v", file.Funcs[0])
	}
	return pkg, file, sigs
}

func TestARM64ABI0TailResultBindingAndPreparedSeal(t *testing.T) {
	_, file, sigs := arm64ABI0BoundFixture(t)
	original := arm64ABI0FileSnapshot(file)
	resolve := func(symbol string) string { return strings.TrimPrefix(goTextSymbolForResolution(symbol), "·") }
	prepared, err := PrepareGoARM64ABI0TailContinuations(file, sigs, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Funcs) != 1 || prepared.Funcs[0].arm64ABI0TailSource == nil || !reflect.DeepEqual(original, arm64ABI0FileSnapshot(file)) {
		t.Fatalf("complete declaration source was not independently sealed: funcs=%d proof=%t", len(prepared.Funcs), prepared.Funcs[0].arm64ABI0TailSource != nil)
	}
	normalized, err := normalizeARM64ScalarMemoryFrame(prepared.Funcs[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := validateARM64ABI0TailSource(normalized, sigs["Slots"]); err != nil {
		t.Fatalf("actual FP frame normalization lost the sealed prepared source: %v", err)
	}
	if !reflect.DeepEqual(arm64PrivateTailSnapshot(normalized), arm64PrivateTailSnapshot(prepared.Funcs[0])) {
		t.Fatal("sealed FP normalization is not idempotent")
	}
	t.Run("physical-FP-marker", func(t *testing.T) {
		_, file, sigs := arm64ABI0BoundFixture(t)
		prepared, err := PrepareGoARM64ABI0TailContinuations(file, sigs, resolve)
		if err != nil {
			t.Fatal(err)
		}
		marker := prepared.Funcs[0].Instrs[1].arm64ScalarMemoryFrameOffset
		if marker == nil {
			t.Fatal("actual FP load has no bound physical offset")
		}
		*marker = *marker + 1
		if err := validateARM64ABI0TailSource(prepared.Funcs[0], sigs["Slots"]); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("changed physical FP marker retained its result capability: %v", err)
		}
	})
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "original"}[changed], func(t *testing.T) {
			_, file, sigs := arm64ABI0BoundFixture(t)
			prepared, err := PrepareGoARM64ABI0TailContinuations(file, sigs, resolve)
			if err != nil {
				t.Fatal(err)
			}
			if changed {
				file.Funcs[0].ArgSize++
			} else {
				prepared.Funcs[0].Instrs[len(prepared.Funcs[0].Instrs)-2].Args[0].Reg = "R7"
			}
			if err := validateARM64ABI0TailSource(prepared.Funcs[0], sigs["Slots"]); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("changed source/prepared retained its result capability: %v", err)
			}
		})
	}
}
