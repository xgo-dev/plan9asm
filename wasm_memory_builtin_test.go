package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestWASMMemoryBuiltinsRejectWrongStackWidth(t *testing.T) {
	for _, tc := range []struct {
		op    string
		arity int
	}{
		{"GrowMemory", 1},
		{"MemoryCopy", 3},
		{"MemoryFill", 3},
	} {
		for bad := 0; bad < tc.arity; bad++ {
			t.Run(fmt.Sprintf("%s/operand-%d", tc.op, bad+1), func(t *testing.T) {
				var source strings.Builder
				source.WriteString("TEXT f(SB),4,$0-0\n")
				for index := 0; index < tc.arity; index++ {
					if index == bad {
						source.WriteString("I64Const $4294967296\n")
					} else {
						source.WriteString("I32Const $0\n")
					}
				}
				source.WriteString(tc.op + "\n")
				if tc.op == "GrowMemory" {
					source.WriteString("Drop\n")
				}
				source.WriteString("RET\n")
				file, err := Parse(ArchWASM, source.String())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "f"); err == nil {
					t.Error("inference accepted a wrong-width stack value")
				}
				sigs := map[string]FuncSig{"f": {Name: "f", Ret: Void}}
				for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
					ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIDirect), route)
					if err == nil || ir != "" || !strings.Contains(err.Error(), "requires an i32 stack value") {
						t.Errorf("%s: expected wrong-width diagnostic, got %v", route, err)
					}
				}
			})
		}
	}
}

func TestWASMMemoryBuiltinSourceFormats(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for _, tc := range []struct {
		op        string
		arity     int
		returns32 bool
	}{
		{"CurrentMemory", 0, true},
		{"GrowMemory", 1, true},
		{"MemoryCopy", 3, false},
		{"MemoryFill", 3, false},
	} {
		for index, spelling := range []string{"", " $7", " R0,R1"} {
			name := fmt.Sprintf("%s%d", tc.op, index)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n", name)
			source.WriteString(strings.Repeat("I32Const $0\n", tc.arity))
			fmt.Fprintf(&source, "%s%s\nReturn\n", tc.op, spelling)
			ret := Void
			if tc.returns32 {
				ret = I32
			}
			sigs[name] = FuncSig{Name: name, Ret: ret}
		}
		for _, spelling := range []string{".INVALID", " R0,R1,R2"} {
			file, err := Parse(ArchWASM, "TEXT f(SB),4,$0-0\nRET\n"+tc.op+spelling+"\n")
			if err != nil {
				continue // The parser can reject the spelling before instruction validation.
			}
			if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "f"); err == nil {
				t.Errorf("inference accepted dead %s%s", tc.op, spelling)
			}
			sigs := map[string]FuncSig{"f": {Name: "f", Ret: Void}}
			if _, err := Translate(file, wasmPackedOptions(sigs, WASMABIDirect)); err == nil {
				t.Errorf("translation accepted dead %s%s", tc.op, spelling)
			}
		}
	}
	for _, goos := range wasmPackedGoPlatforms {
		wasmDataGoObject(t, source.String(), goos)
	}
	file, err := Parse(ArchWASM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range file.Funcs {
		got, err := InferWASMAssemblyFuncSig(fn, fn.Sym)
		if err != nil || len(got.Args) != 0 || got.Ret != sigs[fn.Sym].Ret {
			t.Errorf("%s: inference returned %+v, %v", fn.Sym, got, err)
		}
	}
	if _, err := Translate(file, wasmPackedOptions(sigs, WASMABIDirect)); err != nil {
		t.Fatal(err)
	}
}
