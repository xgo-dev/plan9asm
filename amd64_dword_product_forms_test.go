package plan9asm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

var x86DwordProductOracleNames = []string{"PMULDQ", "PMULULQ", "VPMULDQ", "VPMULUDQ"}

func x86DwordProductOracleRows(t *testing.T, arch string) []string {
	t.Helper()
	var rows []string
	for _, name := range x86DwordProductOracleNames[:2] {
		for _, source := range []string{"X0", "X7", "(AX)", "16(AX)(CX*2)", "value+0(FP)", "local-64(SP)", "·data(SB)", "(FS)", "(GS)"} {
			rows = append(rows, name+" "+source+",X1")
		}
		if arch == "amd64" {
			rows = append(rows, name+" X15,X1")
		}
	}
	if arch == "amd64" {
		for _, source := range []string{"M0", "M7", "(AX)", "value+0(FP)", "AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
			rows = append(rows, "PMULULQ "+source+",M1")
		}
	}
	official := x86OfficialPackedBinaryWitnesses(t)
	for _, name := range x86DwordProductOracleNames[2:] {
		if len(official[name]) == 0 {
			t.Fatal("independent complete Go rules omitted", name)
		}
		for _, row := range official[name] {
			if arch != "386" || strings.Count(row, ",") != 3 {
				rows = append(rows, row)
			}
		}
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, source := range []string{"value+0(FP)", "local-64(SP)", "·data(SB)", "(FS)", "(GS)"} {
				rows = append(rows, name+" "+source+","+bank+"1,"+bank+"2",
					name+".BCST "+source+","+bank+"1,"+bank+"2")
			}
			if arch != "386" || bank != "Z" {
				rows = append(rows, name+" "+bank+"20,"+bank+"21,"+bank+"22")
			}
		}
	}
	return rows
}

func TestX86DwordProductCompleteIndependentEncoderRows(t *testing.T) {
	root := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	legacy, err := os.ReadFile(filepath.Join(root, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []struct{ name, body string }{
		{"ymm", "{Zm_r_xm, 1, argList{Ymm, Ymr}},\n{Zm_r_xm, 2, argList{Yxm, Yxr}},"},
		{"yxm_q4", "{Zm_r, 1, argList{Yxm, Yxr}},"},
	} {
		start := strings.Index(string(legacy), "var "+table.name+" = []ytab{")
		if start < 0 {
			t.Fatal("actual Go omitted table", table.name)
		}
		actual := strings.SplitN(string(legacy)[start:], "\n}", 2)[0]
		actual = strings.SplitN(actual, "[]ytab{", 2)[1]
		actualTokens, err := x86SignedPackedFloatGoOpcodeTokens(actual)
		if err != nil {
			t.Fatal(err)
		}
		wantTokens, err := x86SignedPackedFloatGoOpcodeTokens(table.body)
		if err != nil || !reflect.DeepEqual(actualTokens, wantTokens) {
			t.Fatal("actual Go complete legacy zcase/zoffset/classes changed", table.name, actual)
		}
	}
	for _, row := range []string{"{APMULDQ, yxm_q4, Pq4, opBytes{0x28}}", "{APMULULQ, ymm, Py1, opBytes{0xf4, Pe, 0xf4}}"} {
		if !strings.Contains(string(legacy), row) {
			t.Fatal("actual Go legacy prefix/opbytes changed", row)
		}
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	classes := []string{"Yxm,Yxr,Yxr", "Yym,Yyr,Yyr", "YxmEvex,YxrEvex,YxrEvex", "YxmEvex,YxrEvex,Yknot0,YxrEvex", "YymEvex,YyrEvex,YyrEvex", "YymEvex,YyrEvex,Yknot0,YyrEvex", "Yzm,Yzr,Yzr", "Yzm,Yzr,Yknot0,Yzr"}
	counts := map[string]int{}
	for _, rule := range rules {
		if rule.Opcode != "VPMULDQ" && rule.Opcode != "VPMULUDQ" {
			continue
		}
		mapName, opcode := "0F", "0xF4"
		if rule.Opcode == "VPMULDQ" {
			mapName, opcode = "0F38", "0x28"
		}
		var opbytes []string
		for _, width := range []int{128, 256} {
			opbytes = append(opbytes, fmt.Sprintf("avxEscape | vex%d | vex66 | vex%s | vexW0", width, mapName), opcode)
		}
		for _, width := range []int{128, 256, 512} {
			opbytes = append(opbytes, fmt.Sprintf("avxEscape | evex%d | evex66 | evex%s | evexW1", width, mapName), fmt.Sprintf("evexN%d | evexBcstN8 | evexZeroingEnabled", width/8), opcode)
		}
		index := counts[rule.Opcode]
		zcase := "Zevex_rm_v_r"
		if index < 2 {
			zcase = "Zvex_rm_v_r"
		} else if index%2 == 1 {
			zcase = "Zevex_rm_v_k_r"
		}
		if index >= 8 || rule.RowIndex != index || rule.Ytab != "_yvandnpd" || rule.Prefix != "Pavx" ||
			rule.ZCase != zcase || rule.ZOffset != []int{2, 2, 0, 3, 0, 3, 0, 3}[index] ||
			rule.EncodingOffset != []int{0, 2, 4, 4, 7, 7, 10, 10}[index] ||
			strings.Join(rule.Classes, ",") != classes[index] || !reflect.DeepEqual(rule.OpBytes, opbytes) {
			t.Fatal("independent whole Go encoder row changed", rule)
		}
		counts[rule.Opcode]++
	}
	if len(x86DwordProductSpecs) != 4 || counts["VPMULDQ"] != 8 || counts["VPMULUDQ"] != 8 {
		t.Fatal("entire signed/unsigned family is not closed", counts)
	}
	for _, name := range x86DwordProductOracleNames {
		if _, exists := x86DwordProductSpecs[Op(name)]; !exists {
			t.Fatal("production omitted independent family member", name)
		}
	}
	// PMULUDQ is a decoder alias, never another accepted Go source mnemonic.
	arch, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/arch/arch.go"))
	if err != nil || strings.Contains(string(arch), "instructions[\"PMULUDQ\"]") {
		t.Fatal("actual Go alias inventory changed", err)
	}
}

func TestX86DwordProductWholeFormatsEffectsAndMemoryShapes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		rows := x86DwordProductOracleRows(t, arch)
		var source strings.Builder
		for i, row := range rows {
			fmt.Fprintf(&source, "TEXT f%d(SB),4,$64-64\n%s\nRET\n", i, row)
		}
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
		file, err := Parse(ArchAMD64, source.String())
		if err != nil {
			t.Fatal(err)
		}
		for index, fn := range file.Funcs {
			ins := fn.Instrs[1]
			before := fmt.Sprintf("%#v", ins)
			form, known, err := x86DwordProductProperties(ins.Op, ins, arch)
			high := arch == "386" && strings.Contains(rows[index], "20")
			if !known || high && !errors.Is(err, ErrProbeNeedsContext) || !high && err != nil {
				t.Fatal("Go-accepted source lost syntax/context classification", arch, rows[index], err)
			}
			if high {
				continue
			}
			for i, operand := range ins.Args {
				width, write, valid := x86InstructionMemoryShape(ins, i, arch)
				if valid != (i == form.memory && !form.mmx) || valid && (write || width != int64(form.memoryBytes)) {
					t.Fatal("native tuple shape changed", rows[index], width, write, valid)
				}
				if operand.Kind == OpFP {
					width, write, valid = X86FPAccessBytes(ins, i, arch)
					if !valid || write || width != int64(form.memoryBytes) {
						t.Fatal("FP observation lost native memory span", rows[index], width, write, valid)
					}
				}
			}
			if form.legacy {
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || len(effect.operands) != 2 || effect.flagsDefined != 0 || effect.flagsKilled != 0 || effect.flagsRead != 0 ||
					!effect.operands[0].read || effect.operands[0].write || !effect.operands[1].read || !effect.operands[1].write ||
					effect.operands[0].width != int64(form.byteWidth) || effect.operands[1].width != int64(form.byteWidth) || !reflect.DeepEqual(effect.operands[0].operand, form.source) {
					t.Fatal("legacy typed read/modify/write/flags/bank mismatch", effect, err)
				}
			}
			if before != fmt.Sprintf("%#v", ins) || x86CallerVectorMoveKnown(ins) != !form.mmx {
				t.Fatal("form modified source or borrowed MMX input permission", ins)
			}
		}
		t.Logf("%s: %d independently Go-accepted complete-family forms; syntax/context/effects distinct", arch, len(rows))
	}
}

func TestX86DwordProductThreeAPIsFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		arch := "amd64"
		if strings.HasPrefix(triple, "i") {
			arch = "386"
		}
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/raw=%t", triple, raw), func(t *testing.T) {
				rows := x86DwordProductOracleRows(t, arch)
				if raw {
					rows = nil
					for _, name := range x86DwordProductOracleNames[2:] {
						for _, row := range x86OfficialPackedBinaryWitnesses(t)[name] {
							code := x86OrderingHintGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
							var directives strings.Builder
							for _, value := range code[:len(code)-1] {
								fmt.Fprintf(&directives, "BYTE $%d\n", value)
							}
							rows = append(rows, directives.String())
						}
					}
				}
				var source, declarations strings.Builder
				declarations.WriteString("package product\n")
				count := 0
				for _, row := range rows {
					if !raw {
						parsed, err := Parse(ArchAMD64, "TEXT f(SB),4,$64-64\n"+row+"\nRET\n")
						if err != nil {
							t.Fatal(err)
						}
						ins := parsed.Funcs[0].Instrs[1]
						form, _, err := x86DwordProductProperties(ins.Op, ins, arch)
						if errors.Is(err, ErrProbeNeedsContext) || form.mmx || form.legacy && form.memory >= 0 && (form.source.Kind == OpFP || form.source.Kind == OpMem && form.source.Mem.Base == SP) {
							continue
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					fmt.Fprintf(&source, "TEXT ·F%d(SB),4,$64-64\n%s\nRET\n", count, row)
					fmt.Fprintf(&declarations, "func F%d(value [64]byte)\n", count)
					count++
				}
				goAssemblerOracleOutput(t, arch, source.String(), "", true)
				ir := x86DwordProductOriginalFormatObject(t, source.String(), declarations.String(), arch, triple, 64)
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, ir, level)
				}
				t.Logf("%d original formats: three public Context checks and emitter objects, not initialized public entries", count)
			})
		}
	}
}

func x86DwordProductReservedZeroObservation(t *testing.T, name string) {
	t.Helper()
	source := "TEXT f(SB),4,$0-0\n" + name + ".Z (AX),X1,X2\nRET\n"
	dir := t.TempDir()
	asm, object := filepath.Join(dir, "reserved.s"), filepath.Join(dir, "reserved.o")
	if err := os.WriteFile(asm, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-o", object, asm)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=amd64")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(asm, object, output, err, ctx.Err(), err == nil, "amd64"); failure != nil {
		t.Fatal(failure)
	}
	if err != nil {
		if !bytes.Contains(output, []byte("mask register must be specified for .Z instructions")) {
			t.Fatal("unknown Go rejection", string(output))
		}
		return
	}
	// Historical Go1.20 emits reserved EVEX.z=1,aaa=0. It is not a legal
	// format and remains rejected by every translation API and raw decoder.
	mapByte, opcode := byte(0xf1), byte(0xf4)
	if name == "VPMULDQ" {
		mapByte, opcode = 0xf2, 0x28
	}
	code := []byte{0x62, mapByte, 0xf5, 0x88, opcode, 0x10, 0xc3}
	var listing []string
	for _, value := range code {
		listing = append(listing, fmt.Sprintf("%02x", value))
	}
	if !bytes.Contains(output, []byte(strings.Join(listing, " "))) {
		t.Fatal("historical reserved encoding changed", string(output))
	}
	if _, _, known, err := decodedX86DwordToQwordMultiplyInstruction(code[:len(code)-1], 64); !known || err == nil {
		t.Fatal("historical maskless zero encoding gained physical permission", known, err)
	}
}

func TestX86DwordProductDispatchIdentityBeforeEmission(t *testing.T) {
	for _, name := range x86DwordProductOracleNames {
		opcode := Op(name)
		row := name + " X0,X1"
		if strings.HasPrefix(name, "V") {
			row += ",X2"
		}
		for _, sourceOp := range []Op{"", opcode, Op(strings.ToLower(name)), "UNKNOWN", "MOVQ"} {
			file, err := Parse(ArchAMD64, "TEXT one(SB),$0-0\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			ins.Op = sourceOp
			ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := out.String()
			known, term, err := ctx.lowerDwordToQwordMultiply(opcode, ins)
			if sourceOp == "UNKNOWN" || sourceOp == "MOVQ" {
				if !known || term || err == nil || before != out.String() {
					t.Fatal("conflicting dispatch/source identity emitted IR", opcode, sourceOp, err)
				}
			} else if !known || term || err != nil {
				t.Fatal("compatible helper identity rejected", opcode, sourceOp, err)
			}
			if ins.Op != sourceOp {
				t.Fatal("helper mutated input identity")
			}
		}
	}
}

func TestX86DwordProductMalformedAndContextThreeAPIsBeforeIR(t *testing.T) {
	for _, name := range x86DwordProductOracleNames {
		vector := strings.HasPrefix(name, "V")
		rows := []string{name + " $1,X1", name + " Y0,Y1", name + " X16,X0", name + " X0,(AX)", name + " (AX)(SP*2),X1"}
		if vector {
			rows = []string{name + " $1,X1,X2", name + " X0,Y1,X2", name + " X0,X1,K0,X2", name + " X0,X1,(AX)", name + ".BCST X0,X1,X2", name + ".SAE X0,X1,X2", name + ".RN_SAE X0,X1,X2", name + ".Z.BCST (AX),X1,K1,X2", name + " (AX)(SP*2),X1,X2"}
			x86DwordProductReservedZeroObservation(t, name)
			rows = append(rows, name+".Z (AX),X1,X2")
		}
		for _, row := range rows {
			if !strings.Contains(row, ".Z (") {
				goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
			}
			for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
				t.Run(row+"/"+triple, func(t *testing.T) {
					arch := "amd64"
					if strings.HasPrefix(triple, "i") {
						arch = "386"
					}
					file, err := Parse(ArchAMD64, "TEXT ·F(SB),4,$0-0\n"+row+"\nRET\n")
					if err != nil {
						return
					}
					options := Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"F": {Name: "F", Ret: Void}}, ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }}
					if ir, err := Translate(file, options); err == nil || ir != "" {
						t.Fatal("malformed text emitted IR", err)
					}
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					module, err := TranslateModuleInContext(ctx, file, options)
					if !module.IsNil() {
						defer module.Dispose()
					}
					if err == nil || !module.IsNil() {
						t.Fatal("malformed direct module accepted", err)
					}
					pkg := mustGoPackage(t, "product", "package product\nfunc F()\n")
					result, err := translateGoModuleInContext(ctx, pkg, []byte("TEXT ·F(SB),4,$0-0\n"+row+"\nRET\n"), GoModuleOptions{GOARCH: arch, TargetTriple: triple, ResolveSym: options.ResolveSym})
					if result != nil && !result.Module.IsNil() {
						defer result.Module.Dispose()
					}
					if err == nil || result != nil {
						t.Fatal("malformed Go module accepted", err)
					}
				})
			}
		}
	}
}

func TestX86DwordProductMode32PhysicalMarkerAndMMXBank(t *testing.T) {
	for _, name := range x86DwordProductOracleNames[2:] {
		for _, row := range x86OfficialPackedBinaryWitnesses(t)[name] {
			if strings.Count(row, ",") != 3 {
				continue
			}
			goAssemblerOracleOutput(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
			code := x86OrderingHintGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			ins, length, known, err := decodedX86DwordToQwordMultiplyInstruction(code[:len(code)-1], 32)
			if !known || err != nil || length != len(code)-1 || !ins.x86Encoded {
				t.Fatal("actual physical low-bank mode32 decode missing", row, ins, err)
			}
			if _, _, err := x86DwordProductProperties(ins.Op, ins, "386"); err != nil {
				t.Fatal("physical mask inherited named frontend limit", row, err)
			}
			data, err := json.Marshal(ins)
			if err != nil {
				t.Fatal(err)
			}
			var restored Instr
			if err := json.Unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			restored.Raw = "BYTE genuine-looking decoder text"
			if _, _, err := x86DwordProductProperties(restored.Op, restored, "386"); err == nil {
				t.Fatal("JSON/raw text fabricated private physical marker")
			}
		}
	}
	for _, source := range []string{"AX", "SP", "BP", "R14", "R15"} {
		row := "PMULULQ " + source + ",M1"
		goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
		before := out.String()
		if known, _, err := ctx.lowerDwordToQwordMultiply(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1]); !known || !errors.Is(err, ErrProbeNeedsContext) || out.String() != before {
			t.Fatal("GP spelling became initialized MMX transport", row, err)
		}
	}
}
