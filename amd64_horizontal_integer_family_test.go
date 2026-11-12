package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

var x86HorizontalIntegerOpcodes = []string{"PHADDW", "PHADDD", "PHADDSW", "PHSUBW", "PHSUBD", "PHSUBSW"}

// Independent encoder inventory: each opcode keeps all bytes, zcase, advance,
// operand classes and offset. A shared ytab or instruction count is insufficient.
func x86OfficialHorizontalIntegerRows(t *testing.T) []string {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	opcodes := map[string]string{"PHADDW": "0x01", "PHADDD": "0x02", "PHADDSW": "0x03", "PHSUBW": "0x05", "PHSUBD": "0x06", "PHSUBSW": "0x07"}
	legacy := regexp.MustCompile(`\{A(PHADDW|PHADDD|PHADDSW|PHSUBW|PHSUBD|PHSUBSW), (\w+), (\w+), opBytes\{([^}]+)\}\}`).FindAllStringSubmatch(string(source), -1)
	if len(legacy) != 6 || len(amd64HorizontalIntegerSpecs) != 12 {
		t.Fatalf("complete original horizontal opcode denominator changed: %d/%d", len(legacy), len(amd64HorizontalIntegerSpecs))
	}
	for _, rule := range legacy {
		table, prefix, bytes := "yxm_q4", "Pq4", opcodes[rule[1]]
		classes := "{Zm_r,1,argList{Yxm,Yxr}},"
		if rule[1] == "PHADDD" {
			table, prefix, bytes = "ymmxmm0f38", "Px", "0x0F,0x38,0x02,0,0x66,0x0F,0x38,0x02,0"
			// Zlitm_r consumes zoffset+xo, with initial 0x0f giving xo=1:
			// complete offsets are 0 and 4, advances 3 and 5.
			classes = "{Zlitm_r,3,argList{Ymm,Ymr}},{Zlitm_r,5,argList{Yxm,Yxr}},"
			rows = append(rows, "PHADDD M0,M7", "PHADDD (AX),M7")
		}
		definition := regexp.MustCompile(`(?s)var ` + table + ` = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(string(source))
		if len(definition) != 2 || strings.Join(strings.Fields(definition[1]), "") != classes || rule[2] != table || rule[3] != prefix || strings.ReplaceAll(rule[4], " ", "") != bytes {
			t.Fatalf("unmodeled complete horizontal legacy row: %v", rule)
		}
		rows = append(rows, rule[1]+" X0,X7", rule[1]+" -7(BX)(CX*4),X7")
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, rule := range rules {
		original := strings.TrimPrefix(rule.Opcode, "V")
		opcode, selected := opcodes[original]
		if !selected || rule.Opcode == original {
			continue
		}
		index := rule.RowIndex
		classes := [][]string{{"Yxm", "Yxr", "Yxr"}, {"Yym", "Yyr", "Yyr"}}
		bytes := []string{"avxEscape | vex128 | vex66 | vex0F38 | vexW0", opcode, "avxEscape | vex256 | vex66 | vex0F38 | vexW0", opcode}
		if index < 0 || index > 1 || rule.Ytab != "_yvaddsubpd" || rule.Prefix != "Pavx" || rule.ZCase != "Zvex_rm_v_r" || rule.ZOffset != 2 || rule.EncodingOffset != 2*index || !reflect.DeepEqual(rule.Classes, classes[index]) || !reflect.DeepEqual(rule.OpBytes, bytes) {
			t.Fatalf("unmodeled complete horizontal VEX row: %+v", rule)
		}
		bank := []string{"X", "Y"}[index]
		rows = append(rows, rule.Opcode+" "+bank+"0,"+bank+"1,"+bank+"7", rule.Opcode+" -7(BX)(CX*4),"+bank+"1,"+bank+"7")
		counts[rule.Opcode]++
	}
	for _, op := range x86HorizontalIntegerOpcodes {
		if counts["V"+op] != 2 {
			t.Fatalf("missing complete original encoding rows for %s: %v", op, counts)
		}
		bits := 16
		if op == "PHADDD" || op == "PHSUBD" {
			bits = 32
		}
		for _, name := range []string{op, "V" + op} {
			spec := amd64HorizontalIntegerSpecs[Op(name)]
			if spec.laneBits != bits || spec.subtract != strings.Contains(name, "SUB") || spec.saturate != strings.HasSuffix(name, "SW") || spec.vector != strings.HasPrefix(name, "V") || spec.allowMMX != (name == "PHADDD") {
				t.Fatalf("independent horizontal arithmetic attributes differ: %s %+v", name, spec)
			}
		}
	}
	return rows
}

func TestX86HorizontalIntegerCompleteEncoderRowsThreeAPIsFiveTargets(t *testing.T) {
	rows := x86OfficialHorizontalIntegerRows(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			arch := "amd64"
			if strings.HasPrefix(triple, "i") {
				arch = "386"
			}
			source := "TEXT horizontal(SB),4,$0-0\n" + strings.Join(rows, "\n") + "\nRET\n"
			if arch == "386" {
				source = strings.Replace(source, "\nRET\n", "\nVPHSUBD 2147483648(AX),X1,X2\nRET\n", 1)
			}
			goAssemblerOracleOutput(t, arch, source, "", true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"horizontal": {Name: "horizontal", Ret: Void}}}
			if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("uninitialized original formats acquired numerical/MMX inputs", err)
			}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, options)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("module API invented original inputs", err)
			}
			translated, err := translateGoModuleInContext(ctx, x86SADGoPackage(t, arch, "()"), []byte(strings.Replace(source, "horizontal(SB)", "·sad(SB)", 1)), GoModuleOptions{GOARCH: arch, TargetTriple: triple})
			if translated != nil && !translated.Module.IsNil() {
				defer translated.Module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("Go API invented original inputs", err)
			}
			ir := x86InstructionFormatObjectUnit(t, file, options.Sigs, arch, triple, 0,
				func(c *amd64Ctx, ins Instr) (bool, bool, error) {
					return c.lowerHorizontalInteger(ins.Op, ins)
				})
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, text, level)
				}
			}
		})
	}
}

func TestX86HorizontalIntegerGrammarRejectsBeforeEveryConsumer(t *testing.T) {
	for _, row := range []string{
		"PHADDW M0,M1", "PHADDSW X0,M1", "PHSUBD Y0,Y1", "PHADDD.Z X0,X1", "PHADDW X0,X16",
		"VPHADDD X0,X1", "VPHADDW X0,Y1,Y2", "VPHSUBD Z0,Z1,Z2", "VPHSUBSW X0,X1,K1,X2", "VPHSUBW.Z X0,X1,X2",
		"VPHADDD.BCST (AX),X1,X2", "VPHADDW.SAE X0,X1,X2", "VPHSUBW.RN_SAE Y0,Y1,Y2", "VPHADDD (AX)(SP*2),X1,X2", "VPHSUBD 4294967296(AX),X1,X2", "PHADDW $table(SB),X1",
	} {
		t.Run(row, func(t *testing.T) {
			source := "TEXT sad(SB),4,$0-0\n" + row + "\nRET\n"
			goAssemblerOracleOutput(t, "amd64", source, "", false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			ins := file.Funcs[0].Instrs[1]
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := output.String()
			known, term, err := ctx.lowerHorizontalInteger(ins.Op, ins)
			if !known || term || err == nil || output.String() != before || x86CallerVectorMoveKnown(ins) {
				t.Fatal("invalid horizontal grammar emitted or registered", known, term, err)
			}
			state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": ^uint64(0), "Z1": ^uint64(0), "Z2": ^uint64(0)}}
			state = x86CloneCallerState(state)
			original := x86CloneCallerState(state)
			if x86CallerVectorMoveStep(&ins, &state, nil) || !reflect.DeepEqual(state, original) {
				t.Fatal("invalid grammar mutated caller state")
			}
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					arch := "amd64"
					if strings.HasPrefix(triple, "i") {
						arch = "386"
					}
					goAssemblerOracleOutput(t, arch, source, "", false)
					options := Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"sad": {Ret: Void}}}
					if ir, err := Translate(file, options); err == nil || ir != "" {
						t.Fatal("invalid text API form accepted")
					}
					llvmCtx := llvm.NewContext()
					defer llvmCtx.Dispose()
					module, err := TranslateModuleInContext(llvmCtx, file, options)
					if !module.IsNil() {
						defer module.Dispose()
					}
					if err == nil {
						t.Fatal("invalid module API form accepted")
					}
					translated, err := translateGoModuleInContext(llvmCtx, x86SADGoPackage(t, arch, "()"), []byte(strings.Replace(source, "sad(SB)", "·sad(SB)", 1)), GoModuleOptions{GOARCH: arch, TargetTriple: triple})
					if translated != nil && !translated.Module.IsNil() {
						defer translated.Module.Dispose()
					}
					if err == nil {
						t.Fatal("invalid Go API form accepted")
					}
				})
			}
		})
	}
}

func TestX86HorizontalIntegerDispatchAndCompleteFPSpanBeforeEmission(t *testing.T) {
	for _, row := range x86OfficialHorizontalIntegerRows(t) {
		ins := x86YMMReadSource(t, row)
		for _, identity := range []Op{"", ins.Op, Op(strings.ToLower(string(ins.Op))), "UNKNOWN", "VPHADDD.Z"} {
			local := ins
			local.Op = identity
			ctx, output := newAMD64CtxWithFuncForTest(t, Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, nil)
			before := output.String()
			_, _, err := ctx.lowerHorizontalInteger(ins.Op, local)
			if identity == "UNKNOWN" || identity == "VPHADDD.Z" {
				if err == nil || output.String() != before {
					t.Fatal("dispatch conflict emitted", row, identity)
				}
			} else if err != nil {
				t.Fatal(row, identity, err)
			}
		}
		form, _, err := x86HorizontalIntegerProperties(ins, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		features := inferFuncTargetFeaturesForGOARCH(ArchAMD64, "amd64", Func{Instrs: []Instr{ins}})
		wantFeatures := ""
		if form.memory >= 0 && !form.spec.vector && !form.mmx {
			wantFeatures = "+sse2,+ssse3"
		}
		if features != wantFeatures {
			t.Fatalf("%s native carrier features %s != %s", row, features, wantFeatures)
		}
		if !strings.Contains(row, "(AX)") && !strings.Contains(row, "(BX)") {
			continue
		}
		row = regexp.MustCompile(`(?:-7\(BX\)\(CX\*4\)|\(AX\))`).ReplaceAllString(row, "a+0(FP)")
		ins = x86YMMReadSource(t, row)
		form, _, err = x86HorizontalIntegerProperties(ins, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		for hole := -1; hole < form.byteWidth; hole++ {
			file, _ := Parse(ArchAMD64, "TEXT f(SB),4,$0-32\n"+row+"\nRET\n")
			sig := FuncSig{Ret: Void}
			for at := 0; at < form.byteWidth; at++ {
				if at == hole {
					continue
				}
				sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: int64(at), Type: I8, Index: len(sig.Args), Field: -1})
				sig.Args = append(sig.Args, I8)
			}
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], sig, nil)
			before := output.String()
			_, _, err := ctx.lowerHorizontalInteger(ins.Op, ins)
			wantContext := !form.spec.vector && !form.mmx
			if (err != nil) != (hole >= 0 || wantContext) || err != nil && output.String() != before || wantContext && hole < 0 && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s byte hole %d: %v", row, hole, err)
			}
		}
	}
}

func TestX86HorizontalIntegerEveryInputByteAndAliasEffect(t *testing.T) {
	for _, op := range x86HorizontalIntegerOpcodes {
		for _, bank := range []string{"legacy", "X", "Y"} {
			for destination := 0; destination < 3; destination++ {
				row := op + " X0,X1"
				if bank != "legacy" {
					row = fmt.Sprintf("V%s %s0,%s1,%s%d", op, bank, bank, bank, destination)
				}
				ins := x86YMMReadSource(t, row)
				form, known, err := x86HorizontalIntegerProperties(ins, "amd64")
				if !known || err != nil || !x86CallerVectorMoveKnown(ins) {
					t.Fatal("missing whole-family registration", row, err)
				}
				for operand := 0; operand < 2; operand++ {
					for hole := -1; hole < form.byteWidth; hole++ {
						state := x86SourceStackState{bp: x86SourceStackAddress{original: true}, gOriginal: true, numericFlags: true,
							known: map[Reg]uint8{AX: 0xff}, masks: map[Reg]bool{"K1": true},
							vectors: map[Reg]uint64{"Z0": ^uint64(0), "Z1": ^uint64(0), "Z2": 0x55, "Z31": 0x1234}}
						if hole >= 0 {
							state.vectors[x86CallerVectorRoot(ins.Args[operand].Reg)] &^= uint64(1) << uint(hole)
						}
						state = x86CloneCallerState(state)
						before := x86CloneCallerState(state)
						accepted := x86CallerVectorMoveStep(&ins, &state, nil)
						if accepted != (hole < 0) || !accepted && !reflect.DeepEqual(state, before) {
							t.Fatalf("%s input %d byte hole %d invented input/changed state", row, operand, hole)
						}
						if accepted {
							want := x86CloneCallerState(before)
							root := x86CallerVectorRoot(ins.Args[form.destination].Reg)
							want.vectors[root] = ^uint64(0)
							if !form.spec.vector {
								want.vectors[root] = before.vectors[root] | x86CallerVectorByteMask(int64(form.byteWidth))
							}
							if !reflect.DeepEqual(state, want) {
								t.Fatal("horizontal effect altered unrelated state", row)
							}
						}
					}
				}
				for _, upper := range []uint64{0, 0xff00000000000000, ^x86CallerVectorByteMask(int64(form.byteWidth))} {
					mask := x86CallerVectorByteMask(int64(form.byteWidth))
					state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": mask | upper, "Z1": mask | upper, "Z2": upper}}
					if !x86CallerVectorMoveStep(&ins, &state, nil) {
						t.Fatal("initialized complete input failed", row)
					}
					want := ^uint64(0)
					if !form.spec.vector {
						want = mask | upper
					}
					if state.vectors[x86CallerVectorRoot(ins.Args[form.destination].Reg)] != want {
						t.Fatal("legacy preservation/VEX upper clearing diverged", row)
					}
				}
			}
		}
	}
}
