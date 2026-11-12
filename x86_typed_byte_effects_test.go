package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86TypedByteEffectsBindCompleteExplicitMultiplyTables(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for table, rows := range map[string]string{
		"yimul":  `{Zm_o,2,argList{Yml}},{Zib_rr,1,argList{Yi8,Yrl}},{Zil_rr,1,argList{Yi32,Yrl}},{Zm_r,2,argList{Yml,Yrl}},`,
		"yimul3": `{Zibm_r,2,argList{Yi8,Yml,Yrl}},{Zibm_r,2,argList{Yi32,Yml,Yrl}},`,
	} {
		match := regexp.MustCompile(`(?s)var ` + table + ` = \[\]ytab\{(.*?)\n\}`).FindSubmatch(data)
		if len(match) != 2 || regexp.MustCompile(`\s+`).ReplaceAllString(string(match[1]), "") != rows {
			t.Fatalf("complete actual Go %s rows changed", table)
		}
	}
	rows := regexp.MustCompile(`\{A(IMUL3?[WLQ]), (yimul3?), (P[ewx]),`).FindAllStringSubmatch(string(data), -1)
	if len(rows) != 6 {
		t.Fatalf("explicit multiplication opcode directory changed: %v", rows)
	}
	for _, row := range rows {
		wantTable, wantPrefix := "yimul", map[byte]string{'W': "Pe", 'L': "Px", 'Q': "Pw"}[row[1][len(row[1])-1]]
		if strings.HasPrefix(row[1], "IMUL3") {
			wantTable = "yimul3"
		}
		if row[2] != wantTable || row[3] != wantPrefix {
			t.Fatalf("Go width/class row changed: %v", row)
		}
	}
}

func TestX86TypedByteEffectsExplicitMultiplyRolesWidthAndIdentity(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, suffix := range []string{"W", "L", "Q"} {
			if suffix == "Q" && arch == "386" {
				continue // Actual rejection rows are retained in the full form directory.
			}
			for _, body := range []string{
				"IMUL" + suffix + " AX,BX", "IMUL" + suffix + " $-128,BX",
				"IMUL" + suffix + " $4294967295,BX", "IMUL" + suffix + " x+0(FP),BX",
				"IMUL3" + suffix + " $127,AX,BX", "IMUL3" + suffix + " $2147483648,x+0(FP),BX",
			} {
				t.Run(arch+"/"+body, func(t *testing.T) {
					file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+body+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					ins := file.Funcs[0].Instrs[1]
					before := fmt.Sprintf("%#v", ins)
					form, recognized, err := x86TypedGPByteEffect(ins.Op, ins, arch)
					if !recognized || err != nil || form.flagsDefined != x86ByteFlagCF|x86ByteFlagOF || form.flagsKilled != x86ByteFlagsAll {
						t.Fatalf("explicit typed effect missing or flags inherited: %#v %v", form, err)
					}
					last := form.operands[len(form.operands)-1]
					if last.width != map[string]int64{"W": 2, "L": 4, "Q": 8}[suffix] || !last.write || last.read == strings.HasPrefix(body, "IMUL3") {
						t.Fatalf("wrong old-destination dependency: %#v", last)
					}
					for index, operand := range ins.Args {
						if operand.Kind != OpFP {
							continue
						}
						width, write, known := X86FPAccessBytes(ins, index, arch)
						if !known || write || width != last.width {
							t.Fatalf("descriptor/native width disagreement: %d %t %t", width, write, known)
						}
						mutated := ins
						for _, invalid := range []Op{Op(strings.ToLower(string(ins.Op))), ins.Op + ".BAD"} {
							mutated.Op = invalid
							if _, _, known := X86FPAccessBytes(mutated, index, arch); known {
								t.Fatal("constructed opcode acquired original FP width")
							}
						}
					}
					if after := fmt.Sprintf("%#v", ins); before != after {
						t.Fatal("descriptor rewrote caller-owned instruction")
					}
				})
			}
		}
	}
	for _, body := range []string{
		"IMULL $1.0,AX", "IMUL3L $MISSING,AX,BX", "IMUL3L AX,BX,CX", "IMULL X0,AX",
		"IMUL3L $1,AX,(BX)", "IMULQ $4294967296,AX", "IMUL3Q $-2147483649,AX,BX",
	} {
		file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+body+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		if _, recognized, err := x86TypedGPByteEffect(ins.Op, ins, "amd64"); !recognized || err == nil {
			t.Fatalf("invalid explicit form acquired effects: %s %v", body, err)
		}
	}
	file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\nIMUL3L $7,AX,BX\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	ins := file.Funcs[0].Instrs[1]
	for _, identity := range []Op{"", "imul3l", "IMUL3L"} {
		copy := ins
		copy.Op = identity
		if _, recognized, err := x86TypedGPByteEffect("IMUL3L", copy, "amd64"); !recognized || err != nil {
			t.Fatalf("matching/legacy helper dispatch regressed: %s %v", identity, err)
		}
	}
	ins.Op = "IMULL"
	if _, recognized, err := x86TypedGPByteEffect("IMUL3L", ins, "amd64"); !recognized || err == nil {
		t.Fatal("contradictory dispatch identity acquired effects")
	}
}

func TestX86TypedByteEffectsMultiplyBranchAliasesRevokeUndefinedFlags(t *testing.T) {
	for _, branch := range []string{
		"JE", "JEQ", "JZ", "JNE", "JNZ", "JL", "JLT", "JNGE", "JGE", "JNL", "JLE", "JNG", "JG", "JGT", "JNLE",
		"JS", "JMI", "JNS", "JPL", "JA", "JHI", "JNBE", "JBE", "JLS", "JNA", "JP", "JPE", "JPS", "JNP", "JPO", "JPC",
		"JAE", "JHS", "JNB", "JB", "JLO", "JNAE", "JC", "JCS", "JNC", "JCC", "JO", "JOS", "JNO", "JOC",
	} {
		t.Run(branch, func(t *testing.T) {
			body := "MOVL $1,AX\nCMPL AX,$0\nIMUL3L $7,AX,BX\n" + branch + " other\nMOVB $1,ret0+0(FP)\nRET\nother:\nMOVB $2,ret0+0(FP)\nRET"
			_, file, sig, source := x86ResultInitializationFixture(t, "amd64", "func Value() uint8", body)
			goAssemblerOracleOutput(t, "amd64", source, "", true)
			err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, "amd64")
			required := x86ByteBranchFlags(Op(branch))
			defined := required != 0 && required&^(x86ByteFlagCF|x86ByteFlagOF) == 0
			if defined != (err == nil) {
				t.Fatalf("branch reused undefined flags: %s %v", branch, err)
			}
		})
	}
}

func TestX86TypedByteEffectsThreeAPIFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range []struct{ arch, triple string }{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"}, {"amd64", "x86_64-pc-windows-msvc"},
		{"386", "i386-unknown-linux-gnu"}, {"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			word, move, typ := 8, "MOVQ", "uint64"
			if target.arch == "386" {
				word, move, typ = 4, "MOVL", "uint32"
			}
			var body strings.Builder
			fmt.Fprintf(&body, "%s x+0(FP),AX\n%s $0,BX\n%s AX,spill-16(SP)\n", move, move, move)
			for _, op := range x86ExtensionTestOperations {
				if target.arch == "386" && (op == "MOVBQSX" || op == "MOVBQZX" || op == "MOVWQSX" || op == "MOVWQZX" || op == "MOVLQSX") {
					continue // Five exact current/old 386 rejected rows are tested independently.
				}
				fmt.Fprintf(&body, "%s spill-16(SP),BX\n", op)
			}
			for _, width := range []string{"W", "L", "Q"} {
				if target.arch == "386" && width == "Q" {
					continue
				}
				fmt.Fprintf(&body, "IMUL%s AX,BX\nIMUL%s $-7,BX\nIMUL3%s $65537,spill-16(SP),BX\n", width, width, width)
			}
			fmt.Fprintf(&body, "%s BX,ret0+%d(FP)\nRET", move, word)
			pkg, _, sig, source := x86ResultInitializationFixture(t, target.arch, "func Value(x "+typ+") "+typ, body.String())
			source = strings.Replace(source, ",$0-", ",$32-", 1)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, target.arch); err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: target.arch, TargetTriple: target.triple, Sigs: map[string]FuncSig{"Value": sig},
				ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }}
			before := fmt.Sprintf("%#v %#v", file, sig)
			ir, err := Translate(file, options)
			if err != nil {
				t.Fatal(err)
			}
			x86ResultInitializationObject(t, llc, target.triple, ir, "text")
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, options)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil {
				t.Fatal(err)
			}
			x86ResultInitializationObject(t, llc, target.triple, module.String(), "module")
			translated, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
				GOARCH: target.arch, TargetTriple: target.triple, ResolveSym: options.ResolveSym,
			})
			if translated != nil && !translated.Module.IsNil() {
				defer translated.Module.Dispose()
			}
			if err != nil {
				t.Fatal(err)
			}
			x86ResultInitializationObject(t, llc, target.triple, translated.Module.String(), "typed-go")
			if !reflect.DeepEqual(before, fmt.Sprintf("%#v %#v", file, sig)) {
				t.Fatal("effect observation or API rewrote original input")
			}
		})
	}
}
