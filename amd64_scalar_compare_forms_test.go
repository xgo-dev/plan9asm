package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestX86ScalarCompareCompleteActualGoTables(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for table, body := range map[string]string{
		"ycmpb": `{Z_ib, 1, argList{Yal, Yi32}}, {Zm_ibo, 2, argList{Ymb, Yi32}},
{Zm_r, 1, argList{Ymb, Yrb}}, {Zr_m, 1, argList{Yrb, Ymb}},`,
		"ycmpl": `{Zm_ibo, 2, argList{Yml, Yi8}}, {Z_il, 1, argList{Yax, Yi32}},
{Zm_ilo, 2, argList{Yml, Yi32}}, {Zm_r, 1, argList{Yml, Yrl}}, {Zr_m, 1, argList{Yrl, Yml}},`,
		"yxorb": `{Zib_, 1, argList{Yi32, Yal}}, {Zibo_m, 2, argList{Yi32, Ymb}},
{Zr_m, 1, argList{Yrb, Ymb}}, {Zm_r, 1, argList{Ymb, Yrb}},`,
		"ytestl": `{Zil_, 1, argList{Yi32, Yax}}, {Zilo_m, 2, argList{Yi32, Yml}},
{Zr_m, 1, argList{Yrl, Yml}}, {Zm_r, 1, argList{Yml, Yrl}},`,
	} {
		start := strings.Index(string(data), "var "+table+" = []ytab{")
		if start < 0 {
			t.Fatal("actual Go omitted complete comparison table", table)
		}
		actual := strings.SplitN(strings.SplitN(string(data)[start:], "\n}", 2)[0], "[]ytab{", 2)[1]
		got, err := x86SignedPackedFloatGoOpcodeTokens(actual)
		want, wantErr := x86SignedPackedFloatGoOpcodeTokens(body)
		if err != nil || wantErr != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("actual Go comparison table changed", table)
		}
	}
}

// Independent rows for ycmpb/ycmpl/yxorb/ytestl. Accumulator, general register,
// both register/memory directions and all immediate encoding transitions.
func x86ScalarCompareOracleRows(op, arch string) []string {
	rows := []string{"AX,CX", "CX,AX", "AX,8(DX)", "8(DX),AX", "AX,data-3(SB)", "data+3(SB),AX",
		"8(FS),AX", "AX,8(GS)", "-7(DX)(CX*2),AX", "0,AX"}
	for _, immediate := range []string{"0", "1", "127", "128", "255", "256", "-128", "-129", "32768", "65535", "2147483647", "2147483648", "4294967295", "-2147483648"} {
		for _, value := range []string{"AX", "CX", "8(DX)", "data(SB)"} {
			operands := value + ",$" + immediate
			if strings.HasPrefix(op, "TEST") {
				operands = "$" + immediate + "," + value
			}
			rows = append(rows, operands)
		}
	}
	if strings.HasSuffix(op, "B") {
		rows = append(rows, "AH,BL", "CH,DH", "BP,SI", "DI,AX")
		if arch == "amd64" {
			rows = append(rows, "CH,R8B", "R9B,BH", "DIB,8(R12)")
		}
	} else {
		rows = append(rows, "SP,BP", "DI,SI")
		if arch == "amd64" {
			rows = append(rows, "R8,R15", "16(R12)(R9*8),R11")
		}
	}
	if arch == "386" {
		rows = append(rows, "data(SB)(SP),AX", "AX,data(SB)(CX*4)")
		if strings.HasSuffix(op, "L") {
			rows = append(rows, strings.TrimPrefix(x86ScalarCompareInstruction(op, "AX", "$data(SB)"), op+" "))
		}
	}
	return rows
}

func TestX86ScalarCompareCompleteGoForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, deadRegisters, deadDeclarations strings.Builder
			var initialized, unknownMemory []x86OriginalGPInitializedFormat
			privateOnly := 0
			index := 0
			for _, op := range x86ScalarCompareNames(target.arch) {
				for _, row := range x86ScalarCompareOracleRows(op, target.arch) {
					body := op + " " + row
					ins := x86PureGPUnknownInstruction(t, body)
					form, known, err := x86ScalarCompareProperties(ins.Op, ins, target.arch)
					if !known || err != nil {
						t.Fatalf("typed shape %s: %v", body, err)
					}
					name := fmt.Sprintf("form%d", index)
					original := fmt.Sprintf("TEXT ·%s(SB),4,$0-0\n%s\nRET\n", name, body)
					source.WriteString(original)
					if form.memory >= 0 {
						memory, partner := form.args[form.memory], form.args[1-form.memory]
						hardwareOnly := memory.Kind == OpMem && memory.Mem.Segment != "" &&
							memory.Mem.Base == "" && memory.Mem.Index == "" && partner.Kind == OpImm
						if !hardwareOnly {
							unknownMemory = append(unknownMemory, x86OriginalGPInitializedFormat{
								source: original, declaration: "func " + name + "()",
							})
						}
					} else if x86ScalarCompareOrdinaryDeadRegisters(form, target.arch) {
						deadRegisters.WriteString(original)
						fmt.Fprintf(&deadDeclarations, "func %s()\n", name)
					}
					fixture, reason := x86ScalarCompareOriginalInitializedFormat(target.arch, name, body, form)
					if reason == "" {
						initialized = append(initialized, fixture)
					} else {
						privateOnly++
						t.Logf("original compare row %d keeps its independent role: %s: %s", index, body, reason)
					}
					index++
				}
			}
			want := map[string]int{"amd64": 566, "386": 426}[target.arch]
			if index != want {
				t.Fatal("complete original compare inventory changed", index, want)
			}
			wantInitialized := map[string]int{"amd64": 420, "386": 306}[target.arch]
			if len(initialized) != wantInitialized || privateOnly != want-wantInitialized {
				t.Fatal("original compare input partition changed", len(initialized), privateOnly, wantInitialized)
			}
			file, signatures := x86UnboundVoidFormatSources(t, source.String(), target.arch, target.triple)
			ir := x86SingleInstructionFormatObjectUnits(t, file, signatures, target.arch, target.triple,
				func(c *amd64Ctx, instruction Instr) (bool, bool, error) {
					return c.lowerCmpBt(instruction.Op, instruction)
				})
			for _, level := range []string{"-O0", "-O2"} {
				x86PackedStringCompileObject(t, llc, target.triple, ir, level)
			}
			for row, fixture := range unknownMemory {
				t.Run(fmt.Sprintf("unbound-memory/row%d", row), func(t *testing.T) {
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, fixture.source, fixture.declaration, target.arch, target.triple, api)
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatal("unbound original comparison acquired numerical inputs", api, err)
						}
					}
				})
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run("dead-registers/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, deadRegisters.String(), deadDeclarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("ordinary dead comparison registers changed domain", err)
					}
				})
			}
			x86OriginalGPInitializedFormatObjects(t, initialized, target.arch, target.triple)
			t.Logf("%d unchanged Go/private LLVM comparison formats; %d initialized counterparts; %d independent physical/static/address roles",
				index, len(initialized), privateOnly)
		})
	}
}

func x86ScalarCompareOrdinaryDeadRegisters(form x86ScalarCompareForm, arch string) bool {
	for _, operand := range form.args {
		if operand.Kind == OpImm {
			continue
		}
		if operand.Kind != OpReg || x86OriginalGPPhysicalRegister(operand.Reg, arch) {
			return false
		}
	}
	return true
}

func x86ScalarCompareOriginalInitializedFormat(arch, name, body string, form x86ScalarCompareForm) (x86OriginalGPInitializedFormat, string) {
	// Both compare operands are reads. Reuse the test's ordinary two-input
	// producer builder; this does not project a compare into a product BT form.
	first, second := form.args[0], form.args[1]
	if form.memory == 0 || second.Kind == OpImm {
		first, second = second, first
	}
	for _, operand := range []Operand{first, second} {
		if operand.Kind == OpSym && strings.HasPrefix(operand.Sym, "$") {
			return x86OriginalGPInitializedFormat{}, "relocated immediate retains its source-bound numerical role"
		}
	}
	for _, operand := range []*Operand{&first, &second} {
		if operand.Kind == OpReg {
			if base, _, alias := amd64ByteAlias(operand.Reg); alias {
				operand.Reg = base
			}
		}
	}
	return x86BitTestOriginalInitializedFormat(arch, name, body, x86BitTestForm{index: first, destination: second})
}

func TestX86ScalarCompareMalformedForms(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range x86ScalarCompareNames(arch) {
			bad := []string{"(AX),(CX)", "$1,$2", "X0,AX", "AX", "AX,CX,DX", "AX,K1"}
			if strings.HasPrefix(op, "CMP") {
				bad = append(bad, "$1,AX")
			} else {
				bad = append(bad, "AX,$1")
			}
			if strings.HasSuffix(op, "B") && arch == "386" {
				bad = append(bad, "SP,AX")
			} else if !strings.HasSuffix(op, "B") {
				bad = append(bad, "AL,AX")
			}
			if arch == "amd64" {
				bad = append(bad, strings.TrimPrefix(x86ScalarCompareInstruction(op, "AX", "$4294967296"), op+" "))
			}
			for _, row := range bad {
				body := op + " " + row
				goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+body+"\nRET\n", "", false)
				ins := x86PureGPUnknownInstruction(t, body)
				if _, known, err := x86ScalarCompareProperties(ins.Op, ins, arch); !known || err == nil {
					t.Errorf("invalid Go form admitted: %s %s", arch, body)
				}
			}
		}
	}
}

func TestX86ScalarCompareShortRelocationBackendDefect(t *testing.T) {
	for _, op := range []string{"CMPB", "CMPW", "TESTB", "TESTW"} {
		t.Run(op, func(t *testing.T) {
			body := x86ScalarCompareInstruction(op, "AX", "$data(SB)")
			original := "TEXT f(SB),4,$0-0\n" + body + "\nRET\n"
			dir := t.TempDir()
			source, object := filepath.Join(dir, "forms.s"), filepath.Join(dir, "forms.o")
			if err := os.WriteFile(source, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin/go"), "tool", "asm", "-o", object, source)
			command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=386", "GOTOOLCHAIN=local")
			output, err := runtimeOracleCombinedOutput(ctx, command)
			exit, exited := err.(*exec.ExitError)
			if ctx.Err() != nil || !exited || exit.ProcessState == nil || !exit.ProcessState.Exited() ||
				exit.ExitCode() != 1 || string(output) != "asm: need reloc for $data(SB)\nasm: reloc\n" {
				t.Fatalf("unknown short relocation backend observation: %v; context %v\n%s", err, ctx.Err(), output)
			}
			if goAssemblerOracleOutcome(source, object, output, err, ctx.Err(), false, "386") == nil {
				t.Fatal("backend defect became an illegal-source certificate")
			}
			if data, err := os.ReadFile(source); err != nil || string(data) != original {
				t.Fatal("original source changed during backend observation", err)
			}
			ins := x86PureGPUnknownInstruction(t, body)
			if _, known, err := x86ScalarCompareProperties(ins.Op, ins, "386"); !known || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("missing original bytes became an ordinary numerical form: %v", err)
			}
			t.Log("GO_ASSEMBLER_DEFECT_OBSERVATION: short immediate relocation has no sink; not source rejection or a compiled Go object")
		})
	}
}

func TestX86ScalarCompareConditionalReadBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		ctx := &amd64Ctx{goarch: arch, resolve: func(s string) string { return s }}
		for _, op := range x86ScalarCompareNames(arch) {
			ins := x86PureGPUnknownInstruction(t, x86ScalarCompareInstruction(op, "-7(DX)", "AX"))
			form, _, err := x86ScalarCompareProperties(ins.Op, ins, arch)
			if err != nil {
				t.Fatal(err)
			}
			full := x86ResultState{flags: x86ByteFlagsAll}
			full.gp[0] = 0xff
			full.pointerGP[2] = true
			before := full.clone()
			if accepted, known := ctx.scalarCompareNativeResultTransfer(ins, &full, nil, arch); !known || !accepted {
				t.Fatal("bounded-free external read rejected", arch, op)
			}
			before.flags = x86ByteFlagsAll
			if form.test {
				before.flags &^= x86ByteFlagAF
			}
			if !reflect.DeepEqual(full, before) {
				t.Fatal("compare acquired more than its defined flags", arch, op)
			}
			for b := 0; b < form.bits/8; b++ {
				state := before.clone()
				state.gp[0] &^= 1 << uint(b)
				original := state.clone()
				if accepted, _ := ctx.scalarCompareNativeResultTransfer(ins, &state, nil, arch); accepted || !reflect.DeepEqual(state, original) {
					t.Fatal("uninitialized register byte gained flags", arch, op, b)
				}
			}
			for name, mutate := range map[string]func(*Instr){
				"address-size": func(i *Instr) { i.x86AddressBits = 32 },
				"unbound-size": func(i *Instr) { i.x86UnboundAddressOverride = true },
				"raw":          func(i *Instr) { i.x86Encoded = true },
				"float":        func(i *Instr) { i.Args[1-form.memory] = Operand{Kind: OpImm, ImmIsFloat: true} },
				"unresolved":   func(i *Instr) { i.Args[1-form.memory] = Operand{Kind: OpImm, ImmRaw: "not_defined"} },
			} {
				changed := ins
				changed.Args = append([]Operand(nil), ins.Args...)
				mutate(&changed)
				state := before.clone()
				if accepted, _ := ctx.scalarCompareNativeResultTransfer(changed, &state, nil, arch); accepted {
					t.Fatal("unbound read accepted", arch, op, name)
				}
			}
		}
	}
}

func TestX86ScalarCompareNativeSourceAddressRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		ctx := &amd64Ctx{resolve: func(s string) string { return s }, sigs: map[string]FuncSig{"function": {Name: "aliasedFunction"}},
			continuations: map[string]x86Continuation{"continuation": {}}}
		state := x86ResultState{}
		state.pointerGP[0], state.gp[1] = true, 0xff
		for _, address := range []string{"-7(AX)", "8(AX)(CX*2)"} {
			operand := x86PureGPUnknownInstruction(t, "CMPL "+address+",$1").Args[0]
			if !ctx.scalarCompareNativeAddress(operand, &state, arch) {
				t.Fatal("valid address role rejected", arch, address)
			}
		}
		for _, address := range []string{"external-7(SB)", "external+7(SB)", "function(SB)", "aliasedFunction(SB)", "continuation(SB)", "$external(SB)", "(FS)", "(GS)", "(DX)", "(AX)(DX*4)", "0", "(SP)"} {
			operand := x86PureGPUnknownInstruction(t, "CMPL "+address+",$1").Args[0]
			if ctx.scalarCompareNativeAddress(operand, &state, arch) {
				t.Fatal("unbound address role accepted", arch, address)
			}
		}
		if arch == "386" {
			for _, address := range []string{"external(SB)(SP)", "external(SB)(FS)", "external(SB)(X15)", "external(SB)(CX*4)"} {
				operand := x86PureGPUnknownInstruction(t, "CMPL "+address+",$1").Args[0]
				if ctx.scalarCompareNativeAddress(operand, &state, arch) {
					t.Fatal("named address acquired source-layout authority", address)
				}
				if !x86ScalarCompareMemoryValid(operand, arch) {
					t.Fatal("Go ignored base or active index lost its syntax", address)
				}
			}
			operand := x86PureGPUnknownInstruction(t, "CMPL external(SB)(DX*4),$1").Args[0]
			if ctx.scalarCompareNativeAddress(operand, &state, arch) {
				t.Fatal("active unknown named index treated as ignored base")
			}
		}
	}
	ins := x86PureGPUnknownInstruction(t, "CMPB AH,R8B")
	var ir strings.Builder
	ctx := &amd64Ctx{goarch: "amd64", b: &ir}
	if _, _, err := ctx.lowerCmpBt(ins.Op, ins); !errors.Is(err, ErrProbeNeedsContext) || ir.Len() != 0 {
		t.Fatalf("unbound REX SP alias emitted code: %v", err)
	}
}
