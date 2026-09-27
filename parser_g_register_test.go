package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestParseAMD64GRegisterAlias(t *testing.T) {
	for _, tc := range []struct {
		source string
		want   Operand
	}{
		{"g", Operand{Kind: OpReg, Reg: "R14"}},
		{"*g", Operand{Kind: OpReg, Reg: "R14"}},
		{"0x30(g)", Operand{Kind: OpMem, Mem: MemRef{Base: "R14", Off: 48}}},
		{"*(g)", Operand{Kind: OpMem, Mem: MemRef{Base: "R14"}}},
		{"8(BX)(g*4)", Operand{Kind: OpMem, Mem: MemRef{Base: BX, Index: "R14", Scale: 4, Off: 8}}},
		{"g<>(SB)(g*8)", Operand{Kind: OpMem, Mem: MemRef{Sym: "g<>(SB)", Index: "R14", Scale: 8}}},
		{"$8(g)", Operand{Kind: OpSym, Sym: "$8(R14)"}},
		{"g(SB)", Operand{Kind: OpSym, Sym: "g(SB)"}},
		{"$g(SB)", Operand{Kind: OpSym, Sym: "$g(SB)"}},
	} {
		t.Run(tc.source, func(t *testing.T) {
			got, err := parseOperandForArch(ArchAMD64, tc.source)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseOperandForArch(%q) = %#v, %v; want %#v", tc.source, got, err, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		arch Arch
		want Reg
	}{{ArchARM, "R10"}, {ArchARM64, "R28"}, {ArchWASM, "G"}} {
		got, err := parseOperandForArch(tc.arch, "g")
		if err != nil || got.Reg != tc.want {
			t.Errorf("%s g = %#v, %v; want %s", tc.arch, got, err, tc.want)
		}
	}
}

func TestTranslateAMD64GRegisterAcrossTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	const source = "TEXT gforms(SB),$0-0\n\tMOVQ 0x30(g), AX\n\tMOVQ g, CX\n\tMOVQ AX, g\n\tMOVQ 8(BX)(g*4), AX\n\tPUSHQ g\n\tPOPQ g\n\tRET\n"
	requireX86GoAssemblerResult(t, "amd64", source, true)
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: map[string]FuncSig{"gforms": {Name: "gforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(ir, "R28") {
				t.Fatal("amd64 g used ARM64's R28")
			}
			compileLLVMToObject(t, llc, triple, "g-alias.ll", "g-alias.o", ir)
		})
	}
	bad := "TEXT bad(SB),$0-0\n\tPUSHL g\n\tRET\n"
	requireX86GoAssemblerResult(t, "386", bad, false)
	file, err := Parse(ArchAMD64, bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "386", Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}}}); err == nil {
		t.Fatal("386 accepted amd64 g")
	}
}

func TestAMD64GRegisterRuntime(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT galias(SB),$0-16
	MOVQ input+0(FP), g
	PUSHQ g
	MOVQ $0, g
	POPQ g
	MOVQ 8(g), AX
	MOVQ AX, ret+8(FP)
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple, runPrefix = "x86_64-apple-macosx", []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: map[string]FuncSig{
		"galias": {Name: "galias", Args: []LLVMType{Ptr}, Ret: I64, Frame: FrameLayout{
			Params:  []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}},
			Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = "#include <stdint.h>\nextern uint64_t galias(uint64_t *);\nint main(void) { uint64_t v[2] = {9, 0x12345678}; return galias(v) == v[1] ? 0 : 1; }\n"
	compileAndRunRuntimeTestForTarget(t, llc, clang, "g_alias", triple, ir, mainC, runPrefix)
}

func TestTranslateARMGRegisterAcrossTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	const source = "TEXT gforms(SB),$0-0\n\tMOVW g, R0\n\tMOVW 8(g), R1\n\tMOVW R0, g\n\tRET\n"
	requireARMGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	if got := file.Funcs[0].Instrs[2].Args[0]; got.Kind != OpMem || got.Mem.Base != "R10" {
		t.Fatalf("ARM g memory = %#v; want R10 base", got)
	}
	for _, triple := range []string{"armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: map[string]FuncSig{"gforms": {Name: "gforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "arm-g.ll", "arm-g.o", ir)
		})
	}
}

func TestParseARMGRegisterInCompositeOperands(t *testing.T) {
	for _, shift := range []ShiftOp{ShiftLeft, ShiftRight, ShiftArith, ShiftRotate} {
		for _, tc := range []struct {
			source string
			want   Operand
		}{
			{"g" + string(shift) + "2", Operand{Kind: OpRegShift, Reg: "R10", ShiftOp: shift, ShiftAmount: 2}},
			{"R1" + string(shift) + "g", Operand{Kind: OpRegShift, Reg: "R1", ShiftOp: shift, ShiftReg: "R10"}},
			{"g" + string(shift) + "g", Operand{Kind: OpRegShift, Reg: "R10", ShiftOp: shift, ShiftReg: "R10"}},
		} {
			t.Run(tc.source, func(t *testing.T) {
				got, err := parseOperandForArch(ArchARM, tc.source)
				if err != nil || !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("parse(%q) = %#v, %v; want %#v", tc.source, got, err, tc.want)
				}
			})
		}
	}
	for _, tc := range []struct {
		source string
		want   Operand
	}{
		{"[R8,g,R11]", Operand{Kind: OpRegList, RegList: []Reg{"R8", "R10", "R11"}}},
		{"[g-R12]", Operand{Kind: OpRegList, RegList: []Reg{"R10", "R11", "R12"}, RegListRange: true}},
		{"[R8-g]", Operand{Kind: OpRegList, RegList: []Reg{"R8", "R9", "R10"}, RegListRange: true}},
		{"(g,R12)", Operand{Kind: OpRegList, RegList: []Reg{"R10", "R12"}}},
		{"g<<2(R1)", Operand{Kind: OpMem, Mem: MemRef{Base: "R1", OffRaw: "R10<<2"}}},
		{"$g<<2(R1)", Operand{Kind: OpSym, Sym: "$R10<<2(R1)"}},
		{"g(SB)", Operand{Kind: OpSym, Sym: "g(SB)"}},
		{"$g(SB)", Operand{Kind: OpSym, Sym: "$g(SB)"}},
		{"R28<<2", Operand{Kind: OpRegShift, Reg: "R28", ShiftOp: ShiftLeft, ShiftAmount: 2}},
	} {
		t.Run(tc.source, func(t *testing.T) {
			got, err := parseOperandForArch(ArchARM, tc.source)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parse(%q) = %#v, %v; want %#v", tc.source, got, err, tc.want)
			}
		})
	}
}

func TestTranslateARMCompositeGRegisterAcrossTargets(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT compositeG(SB),$0-0\n")
	for _, shift := range []ShiftOp{ShiftLeft, ShiftRight, ShiftArith, ShiftRotate} {
		fmt.Fprintf(&source, "\tMOVW g%s2, R0\n\tMOVW R1%sg, R2\n\tMOVW g%sg, R3\n", shift, shift, shift)
	}
	source.WriteString("\tMOVM [R8,g,R11], (R0)\n\tMOVM (R0), [g-R12]\n\tMOVM [R8-g], (R0)\n\tMOVW g<<2(R1), R0\n\tRET\n")
	requireARMGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: map[string]FuncSig{"compositeG": {Name: "compositeG", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(ir, "%reg_R28") {
				t.Fatal("composite ARM g operand used ARM64's R28")
			}
			compileLLVMToObject(t, llc, triple, "composite-g.ll", "composite-g.o", ir)
		})
	}
}

func TestParseARM64GRegisterExpressions(t *testing.T) {
	for _, tc := range []struct {
		source string
		want   Operand
	}{
		{"g.UXTW", Operand{Kind: OpRegExtend, Reg: "R28", Ext: ExtendUXTW}},
		{"g.SXTW<<2", Operand{Kind: OpRegExtend, Reg: "R28", Ext: ExtendSXTW, ShiftOp: ShiftLeft, ShiftAmount: 2}},
		{"(R0)(g.SXTW<<2)", Operand{Kind: OpMem, Mem: MemRef{Base: "R0", Index: "R28", IndexExt: ExtendSXTW, Scale: 4}}},
		{"$8(R0)(g.UXTW<<2)", Operand{Kind: OpSym, Sym: "$8(R0)(R28.UXTW<<2)"}},
	} {
		t.Run(tc.source, func(t *testing.T) {
			got, err := parseOperandForArch(ArchARM64, tc.source)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parse(%q) = %#v, %v; want %#v", tc.source, got, err, tc.want)
			}
		})
	}
	for _, source := range []string{"g(SB)", "$g(SB)", "g<>(SB)", "$g+8(SB)", "g+8(FP)", "$g+8(FP)", "runtime·g(SB)", "gopher(SB)", "R1<<'g'", "R28<<2"} {
		if got := normalizeGoGRegister(ArchARM, source); got != source {
			t.Errorf("changed non-alias spelling %q to %q", source, got)
		}
	}
}
