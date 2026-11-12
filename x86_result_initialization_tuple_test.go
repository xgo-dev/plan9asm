package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// Independent gc scalar sizes/alignment, not the proof's layout helpers.
// A zero width denotes a machine word on the selected target.
var x86ResultTupleKinds = []struct {
	name  string
	width int
	move  string
}{
	{"bool", 1, "MOVB"},
	{"int8", 1, "MOVB"}, {"uint8", 1, "MOVB"},
	{"int16", 2, "MOVW"}, {"uint16", 2, "MOVW"},
	{"int32", 4, "MOVL"}, {"uint32", 4, "MOVL"},
	{"int64", 8, "MOVQ"}, {"uint64", 8, "MOVQ"},
	{"int", 0, ""}, {"uint", 0, ""}, {"uintptr", 0, ""},
	{"float32", 4, "MOVSS"}, {"float64", 8, "MOVSD"},
}

func x86ResultTupleFixture(t *testing.T, arch string, kinds []int) (*File, FuncSig, string, string) {
	t.Helper()
	word := 8
	if arch == "386" {
		word = 4
	}
	var params, results []string
	var offsets []int
	position := 0
	for _, index := range append(append([]int(nil), kinds...), kinds...) {
		if len(offsets) == len(kinds) {
			position = (position + word - 1) & -word
		}
		width := x86ResultTupleKinds[index].width
		if width == 0 {
			width = word
		}
		align := width
		if align > word {
			align = word
		}
		position = (position + align - 1) & -align
		offsets = append(offsets, position)
		position += width
	}
	var body strings.Builder
	for i, index := range kinds {
		kind := x86ResultTupleKinds[index]
		params = append(params, fmt.Sprintf("x%d %s", i, kind.name))
		results = append(results, kind.name)
		op, reg := kind.move, "AX"
		if kind.width == 0 {
			op = "MOVQ"
			if word == 4 {
				op = "MOVL"
			}
		}
		if strings.HasPrefix(kind.name, "float") {
			reg = "X0"
		}
		parts, step := 1, 0
		if arch == "386" && op == "MOVQ" {
			op, parts, step = "MOVL", 2, 4
		}
		for part := 0; part < parts; part++ {
			fmt.Fprintf(&body, "%s x%d+%d(FP),%s\n%s %s,ret+%d(FP)\n",
				op, i, offsets[i]+part*step, reg, op, reg, offsets[len(kinds)+i]+part*step)
		}
	}
	body.WriteString("RET")
	declaration := "func Value(" + strings.Join(params, ",") + ") (" + strings.Join(results, ",") + ")"
	_, file, sig, source := x86ResultInitializationFixture(t, arch, declaration, body.String())
	if len(sig.Frame.Params) != len(kinds) || len(sig.Frame.Results) != len(kinds) || file.Funcs[0].ArgSize != int64(position) {
		t.Fatal("typed declaration disagrees with independent scalar layout", sig, position)
	}
	for i := range kinds {
		if sig.Frame.Params[i].Offset != int64(offsets[i]) || sig.Frame.Results[i].Offset != int64(offsets[len(kinds)+i]) {
			t.Fatal("typed offsets disagree with independent scalar layout", i, offsets, sig)
		}
	}
	return file, sig, source, declaration
}

func TestX86ABI0ResultTupleScalarTypesAndObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			var all []int
			var selections [][]int
			for i := range x86ResultTupleKinds {
				all = append(all, i)
				selections = append(selections, []int{i, (i + 1) % len(x86ResultTupleKinds)})
			}
			selections = append(selections, all)
			for i, kinds := range selections {
				file, sig, asm, decl := x86ResultTupleFixture(t, target.arch, kinds)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, target.arch); err != nil {
					t.Fatalf("scalar tuple %v: %v", kinds, err)
				}
				name := fmt.Sprintf("Tuple%d", i)
				source.WriteString(strings.ReplaceAll(asm, "Value", name))
				declarations.WriteString(strings.ReplaceAll(decl, "Value", name) + "\n")
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				for _, optimized := range []bool{false, true} {
					text := ir
					if optimized {
						text = x86MulDivRoundOptimize(t, ir)
					}
					compileLLVMToObject(t, llc, target.triple, "tuple.ll", "tuple.o", text)
				}
			}
		})
	}
}

func TestX86ABI0ResultTupleEveryByteAndPath(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			const declaration = "func Value() (uint8, uint32, uint16)"
			// Padding [1,4) is not a result. Every byte of all three actual
			// fields is required, including bytes after the first result.
			owned := []int{0, 4, 5, 6, 7, 8, 9}
			for missing := -1; missing < len(owned); missing++ {
				var body strings.Builder
				for i, offset := range owned {
					if i != missing {
						fmt.Fprintf(&body, "MOVB $1,ret+%d(FP)\n", offset)
					}
				}
				body.WriteString("RET")
				_, file, sig, _ := x86ResultInitializationFixture(t, arch, declaration, body.String())
				err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch)
				if missing < 0 && err != nil || missing >= 0 && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("missing byte index %d: %v", missing, err)
				}
			}
			const stores = "MOVL $1,ret+0(FP)\nMOVL $2,ret+4(FP)\n"
			for name, body := range map[string]string{
				"two returns":         "MOVL $1,AX\nCMPL AX,$0\nJE other\n" + stores + "RET\nother:\n" + stores + "RET",
				"joined returns":      "MOVL $1,AX\nCMPL AX,$0\nJE other\n" + stores + "JMP end\nother:\n" + stores + "end:\nRET",
				"initialized loop":    stores + "MOVL $3,AX\nloop:\nSUBL $1,AX\nJNE loop\nRET",
				"read written second": stores + "MOVL ret+4(FP),AX\nMOVL AX,ret+0(FP)\nRET",
			} {
				t.Run(name, func(t *testing.T) {
					_, file, sig, _ := x86ResultInitializationFixture(t, arch, "func Value() (uint32, uint32)", body)
					if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); err != nil {
						t.Fatal(err)
					}
				})
			}
			for name, body := range map[string]string{
				"missing first":            "MOVL $2,ret+4(FP)\nRET",
				"missing second":           "MOVL $1,ret+0(FP)\nRET",
				"join revocation":          "MOVL $1,AX\nCMPL AX,$0\nJE other\n" + stores + "JMP end\nother:\nMOVL $1,ret+0(FP)\nend:\nRET",
				"read second before write": "MOVL ret+4(FP),AX\n" + stores + "RET",
				"late unknown overwrite":   stores + "MOVL CX,ret+4(FP)\nRET",
				"unknown flags":            "JE end\n" + stores + "end:\nRET",
				"call":                     stores + "CALL ·other(SB)\nRET",
				"dead call":                stores + "JMP end\nCALL ·other(SB)\nend:\nRET",
				"native read":              stores + "MOVL (AX),CX\nRET",
				"native write":             stores + "MOVL $1,(AX)\nRET",
				"raw":                      stores + "BYTE $0x90\nRET",
				"tail":                     stores + "JMP ·other(SB)",
				"source padding":           "MOVB $1,ret+0(FP)\nMOVL $2,ret+1(FP)\nMOVL $3,ret+4(FP)\nMOVW $4,ret+8(FP)\nRET",
			} {
				t.Run(name, func(t *testing.T) {
					decl := "func Value() (uint32, uint32)"
					if name == "source padding" {
						decl = declaration
					}
					_, file, sig, _ := x86ResultInitializationFixture(t, arch, decl, body)
					if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("unproved tuple acquired initialized results: %v", err)
					}
				})
			}
		})
	}
}

func TestX86ABI0ResultTupleFlattenedNumericalAggregates(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			for i, row := range []struct{ declaration, body string }{
				{"func Value() (uint32, [2]uint32)", "MOVL $1,ret+0(FP)\nMOVL $2,ret+4(FP)\nMOVL $3,ret+8(FP)\nRET"},
				{"func Value() (uint32, struct { A uint8; B uint32 })", "MOVL $1,ret+0(FP)\nMOVB $2,ret+4(FP)\nMOVL $3,ret+8(FP)\nRET"},
			} {
				_, file, sig, asm := x86ResultInitializationFixture(t, target.arch, row.declaration, row.body)
				// DeriveGoFuncABI0Signature already flattens numerical results.
				// Check all three scalar fields, not just the two Go results.
				if len(sig.Frame.Results) != 3 {
					t.Fatal("missing flattened numerical result fields", sig)
				}
				for index, field := range sig.Frame.Results {
					if field.Offset != int64(index*4) || field.Index != index || field.Field != -1 || len(field.Fields) != 0 {
						t.Fatal("unexpected flattened result layout", sig)
					}
				}
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, target.arch); err != nil {
					t.Fatal(err)
				}
				name := fmt.Sprintf("Aggregate%d", i)
				source.WriteString(strings.ReplaceAll(asm, "Value", name))
				declarations.WriteString(strings.ReplaceAll(row.declaration, "Value", name) + "\n")
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				compileLLVMToObject(t, llc, target.triple, "tuple-aggregate.ll", "tuple-aggregate.o", ir)
				compileLLVMToObject(t, llc, target.triple, "tuple-aggregate-opt.ll", "tuple-aggregate-opt.o", x86MulDivRoundOptimize(t, ir))
			}
		})
	}
}

func TestX86ABI0ResultTupleLayoutAndAuthorityBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		file, sig, _, _ := x86ResultTupleFixture(t, arch, []int{6, 6})
		before := fmt.Sprintf("%#v %#v", file.Funcs[0], sig)
		if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); err != nil {
			t.Fatal(err)
		}
		if after := fmt.Sprintf("%#v %#v", file.Funcs[0], sig); before != after {
			t.Fatal("tuple proof mutated original source or signature")
		}
		for name, mutate := range map[string]func(*Func, *FuncSig){
			"tuple arity": func(_ *Func, s *FuncSig) { s.Ret = "{ i32, i32, i32 }" },
			"tuple type":  func(_ *Func, s *FuncSig) { s.Ret = "{ i32, float }" },
			"scalar type": func(_ *Func, s *FuncSig) { s.Ret = I64 },
			"index":       func(_ *Func, s *FuncSig) { s.Frame.Results[1].Index = 0 },
			"overlap":     func(_ *Func, s *FuncSig) { s.Frame.Results[1].Offset = s.Frame.Results[0].Offset },
			"reordered": func(_ *Func, s *FuncSig) {
				s.Frame.Results[0].Offset, s.Frame.Results[1].Offset = s.Frame.Results[1].Offset, s.Frame.Results[0].Offset
			},
			"aggregate field":    func(_ *Func, s *FuncSig) { s.Frame.Results[1].Field = 0 },
			"nested aggregate":   func(_ *Func, s *FuncSig) { s.Frame.Results[1].Fields = []int{0} },
			"parameter overlap":  func(_ *Func, s *FuncSig) { s.Frame.Params[1].Offset = s.Frame.Results[0].Offset },
			"unbounded result":   func(_ *Func, s *FuncSig) { s.Frame.Results[1].Offset = 4096 },
			"short TEXT":         func(f *Func, _ *FuncSig) { f.ArgSize-- },
			"pointer result":     func(_ *Func, s *FuncSig) { s.Ret, s.Frame.Results[1].Type = "{ i32, ptr }", Ptr },
			"ABIInternal":        func(f *Func, _ *FuncSig) { f.Sym += "<ABIInternal>" },
			"incoming registers": func(_ *Func, s *FuncSig) { s.ArgRegs = []Reg{AX} },
			"void":               func(_ *Func, s *FuncSig) { s.Ret, s.Frame.Results = Void, nil },
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				fn, changed := file.Funcs[0], sig
				changed.Frame.Results = append([]FrameSlot(nil), sig.Frame.Results...)
				changed.Frame.Params = append([]FrameSlot(nil), sig.Frame.Params...)
				mutate(&fn, &changed)
				if reflect.DeepEqual(sig, changed) && reflect.DeepEqual(fn, file.Funcs[0]) {
					t.Fatal("mutation did not change the fixture")
				}
				if err := CheckX86ABI0ResultInitialization(fn, changed, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("changed authority acquired tuple proof: %v", err)
				}
			})
		}
	}
}
