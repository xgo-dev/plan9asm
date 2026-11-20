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
)

// Independent directory: no production spec map supplies the denominator.
var x86ScalarShiftTestStems = []string{"RCL", "RCR", "ROL", "ROR", "SAL", "SAR", "SHL", "SHR"}

func x86ScalarShiftTestRows(arch string) []string {
	regs := []string{"AX", "CX", "DX", "BX", "SI", "DI"}
	widths := []string{"B", "W", "L"}
	if arch == "amd64" {
		regs = append(regs, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
		widths = append(widths, "Q")
	}
	var rows []string
	for _, stem := range x86ScalarShiftTestStems {
		for _, width := range widths {
			destinations := regs
			if width == "B" {
				destinations = []string{"AX", "AL", "AH", "BX", "BL", "BH", "CX", "CL", "CH", "DX", "DL", "DH"}
				if arch == "386" {
					destinations = append(destinations, "SI", "DI") // Go's bounded BX swap expansion.
				}
				if arch == "amd64" {
					destinations = append(destinations, "SI", "SIB", "DI", "DIB", "R8", "R8B", "R15", "R15B")
				}
			}
			for _, dst := range destinations {
				for _, count := range []string{"$0", "$1", "$7", "$255", "CL", "CX"} {
					rows = append(rows, stem+width+" "+count+","+dst)
				}
			}
		}
	}
	for _, stem := range []string{"SHL", "SHR"} {
		for _, width := range widths[1:] {
			for _, count := range []string{"$0", "$1", "$16", "$-1", "CL", "CX"} {
				for _, pair := range []string{"AX,BX", "AX,AX", "CX,CX", "AX,CX", "CX,AX"} {
					rows = append(rows, stem+width+" "+count+","+pair)
				}
			}
		}
	}
	for _, op := range []string{"SARXL", "SARXQ", "SHLXL", "SHLXQ", "SHRXL", "SHRXQ", "RORXL", "RORXQ"} {
		for _, dst := range regs {
			if strings.HasPrefix(op, "RORX") {
				for _, count := range []string{"$0", "$1", "$-128", "$255"} {
					rows = append(rows, op+" "+count+","+dst+","+dst)
				}
			} else {
				for _, pair := range []string{"AX,BX", "AX,AX", "BX,AX"} {
					rows = append(rows, op+" "+pair+","+dst)
				}
			}
		}
	}
	return rows
}

func TestX86ScalarShiftDefinedFlagAvailability(t *testing.T) {
	cf, pf, af, zf, sf, of := x86ByteFlagCF, x86ByteFlagPF, x86ByteFlagAF, x86ByteFlagZF, x86ByteFlagSF, x86ByteFlagOF
	for _, test := range []struct {
		row                   string
		read, defined, killed uint8
	}{
		{"SHRL $0,AX", 0, 0, 0}, {"SHRQ $64,AX", 0, 0, 0},
		{"SHLB $1,AH", 0, cf | pf | zf | sf | of, x86ByteFlagsAll},
		{"SHRW $16,AX", 0, pf | zf | sf, x86ByteFlagsAll},
		{"SARB $31,AL", 0, cf | pf | zf | sf, x86ByteFlagsAll},
		{"SHLQ CL,AX", 0, 0, af | of}, {"SHLW CX,AX", 0, 0, cf | af | of},
		{"SARW CL,AX", 0, 0, af | of},
		{"RORB $8,AL", 0, cf, of}, {"ROLW $1,AX", 0, cf | of, of},
		{"RCLB $0,AL", 0, 0, 0}, {"RCLB $9,AL", 0, 0, of},
		{"RCRW $17,AX", 0, 0, of}, {"RCLB $10,AL", cf, cf, of},
		{"RCRQ $1,AX", cf, cf | of, of}, {"RCLL CX,AX", cf, 0, of},
		{"SHLW $16,BX,AX", 0, cf | pf | zf | sf, x86ByteFlagsAll},
		{"SHRL CX,BX,AX", 0, 0, af | of},
		{"SHLXQ CX,BX,AX", 0, 0, 0}, {"RORXQ $255,BX,AX", 0, 0, 0},
	} {
		t.Run(test.row, func(t *testing.T) {
			ins := x86YMMReadSource(t, test.row)
			effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
			if !known || err != nil || effect.flagsRead != test.read || effect.flagsDefined != test.defined || effect.flagsKilled != test.killed {
				t.Fatalf("read/defined/killed=%x/%x/%x want%x/%x/%x known=%t err=%v", effect.flagsRead, effect.flagsDefined, effect.flagsKilled, test.read, test.defined, test.killed, known, err)
			}
			for _, initial := range []uint8{0, cf, pf | zf | sf, x86ByteFlagsAll} {
				for _, consumer := range x86ResultGPSIMDConsumers {
					state := x86ResultState{flags: initial}
					for index := range state.gp {
						state.gp[index] = 0xff
					}
					before := state.clone()
					valid := initial&test.read == test.read
					if got := consumer.step(ins, &state, nil, 0, "amd64"); got != valid {
						t.Fatalf("%s admitted unavailable input flags: %x", consumer.name, initial)
					}
					if valid && state.flags != initial&^test.killed|test.defined || !valid && !reflect.DeepEqual(state, before) {
						t.Fatalf("%s changed defined/undefined flags or failed state", consumer.name)
					}
				}
			}
		})
	}
}

func TestX86ScalarShiftIndependentPhysicalInputGuards(t *testing.T) {
	for _, test := range []struct {
		row    string
		reads  [16]uint8
		result int
		width  uint8
	}{
		{row: "SHLB $0,AH", reads: [16]uint8{2}, width: 2},
		{row: "SHLW CL,AX", reads: [16]uint8{3, 1}, width: 3},
		{row: "SHRL CX,AX", reads: [16]uint8{15, 1}, width: 255},
		{row: "SHRQ CL,R8", reads: [16]uint8{1: 1, 8: 255}, result: 8, width: 255},
		{row: "SHLL $0,BX,AX", reads: [16]uint8{15}, width: 255},
		{row: "SHLW $16,BX,AX", reads: [16]uint8{0: 3, 3: 3}, width: 3},
		{row: "SHLXQ AX,BX,AX", reads: [16]uint8{0: 1, 3: 255}, width: 255},
		{row: "RORXL $0,BX,AX", reads: [16]uint8{3: 15}, width: 255},
	} {
		t.Run(test.row, func(t *testing.T) {
			ins := x86YMMReadSource(t, test.row)
			for register := 0; register < 16; register++ {
				for missing := 0; missing < 8; missing++ {
					for _, consumer := range x86ResultGPSIMDConsumers {
						state := x86ResultState{flags: x86ByteFlagsAll}
						state.gp = test.reads
						state.gp[register] &^= 1 << uint(missing)
						before := state.clone()
						valid := test.reads[register]&(1<<uint(missing)) == 0
						if got := consumer.step(ins, &state, nil, 0, "amd64"); got != valid {
							t.Fatalf("%s register%d missing%d accepted%t want%t", consumer.name, register, missing, got, valid)
						}
						if valid && state.gp[test.result]&test.width != test.width || !valid && !reflect.DeepEqual(state, before) {
							t.Fatal("missing byte or alias extent was manufactured")
						}
					}
				}
			}
		})
	}
}

func TestX86ScalarShiftGrammarAndMemoryAuthorityControls(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []string{
			"SHLB $-1,AX", "SHRW $256,AX", "SHLL AX,BX", "RCLQ $1,X0", "RORB $1,SPB",
			"SHLW $128,AX,BX", "SHRW $-129,AX,BX", "SHLB $1,AX,BX", "SALW $1,AX,BX",
			"RORXQ $256,AX,BX", "RORXL $-129,AX,BX", "SHLXQ $1,AX,BX", "SHRXL CL,AX,BX",
			"SARXL AX,X0,BX", "SHLL.Z $1,AX",
		} {
			t.Run(arch+"/"+row, func(t *testing.T) {
				goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
				ins := x86YMMReadSource(t, row)
				if _, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); !known || err == nil {
					t.Fatal("typed grammar acquired Go-rejected form")
				}
			})
		}
		for _, row := range []string{"SHLL $1,AX", "SHLW CL,AX", "RORXL $1,AX,BX"} {
			ins := x86YMMReadSource(t, row)
			if ins.Args[0].Kind == OpImm {
				for _, raw := range []bool{false, true} {
					changed := ins
					changed.Args = append([]Operand(nil), ins.Args...)
					changed.Args[0].ImmRaw = "UNKNOWN"
					if raw {
						changed.Args[0].ImmRaw = ""
						changed.Args[0].ImmIsFloat = true
					}
					if _, known, err := x86TypedInstructionByteEffect(changed.Op, changed, arch); !known || err == nil {
						t.Fatal("unresolved or floating count promoted to integer")
					}
				}
			}
			for _, consumer := range x86ResultGPSIMDConsumers {
				state := x86ResultState{flags: x86ByteFlagsAll, pointerGP: [16]bool{true}}
				if consumer.step(ins, &state, nil, 0, arch) {
					t.Fatal("opaque pointer bytes promoted to numerical shift data")
				}
			}
		}
		for _, row := range []string{"SHLL $1,(AX)", "SHRL CL,tmp-4(SP)", "ROLW $1,data(SB)", "SHRXL AX,(BX),CX"} {
			ins := x86YMMReadSource(t, row)
			if effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); !known || err != nil || !effect.requiresResultProof {
				t.Fatal("memory shape lost its mandatory numerical obligation", err)
			}
			for _, consumer := range x86ResultGPSIMDConsumers {
				state := x86ResultState{flags: x86ByteFlagsAll}
				if consumer.step(ins, &state, nil, 0, arch) {
					t.Fatal("a memory byte shape supplied unproved storage")
				}
			}
		}
	}
}

func TestX86ScalarShiftIndependentCompleteGoEncoderRows(t *testing.T) {
	compact := func(s string) string { return strings.Join(strings.Fields(s), "") }
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := compact(string(data))
	rows := 0
	for _, stem := range x86ScalarShiftTestStems {
		digit := "0" + map[string]string{"ROL": "0", "ROR": "1", "RCL": "2", "RCR": "3", "SAL": "4", "SHL": "4", "SHR": "5", "SAR": "7"}[stem]
		for _, width := range []string{"B", "W", "L", "Q"} {
			tab, prefix, bytes := "yshl", map[string]string{"W": "Pe", "L": "Px", "Q": "Pw"}[width], "0xd1,"+digit+",0xc1,"+digit+",0xd3,"+digit+",0xd3,"+digit
			if width == "B" {
				tab, prefix, bytes = "yshb", "Pb", "0xd0,"+digit+",0xc0,"+digit+",0xd2,"+digit
				rows += 3
			} else {
				rows += 4
			}
			want := "{A" + stem + width + "," + tab + "," + prefix + ",opBytes{" + bytes + "}}"
			if !strings.Contains(text, want) {
				t.Fatalf("missing complete prefix/opcode row %s", want)
			}
		}
	}
	for tab, want := range map[string]string{
		"yshb": "{Zo_m,2,argList{Yi1,Ymb}},{Zibo_m,2,argList{Yu8,Ymb}},{Zo_m,2,argList{Ycx,Ymb}},",
		"yshl": "{Zo_m,2,argList{Yi1,Yml}},{Zibo_m,2,argList{Yu8,Yml}},{Zo_m,2,argList{Ycl,Yml}},{Zo_m,2,argList{Ycx,Yml}},",
	} {
		capture := regexp.MustCompile(`(?s)var ` + tab + ` = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(string(data))
		if len(capture) != 2 || compact(capture[1]) != want {
			t.Fatalf("complete %s zcase/advance/classes changed", tab)
		}
	}
	for _, stem := range []string{"SHL", "SHR"} {
		for _, width := range []string{"W", "L", "Q"} {
			opcodes := map[string]string{"SHL": "0xa4,0xa5", "SHR": "0xac,0xad"}[stem]
			prefix := map[string]string{"W": "Pe,", "L": "", "Q": "Pw,"}[width]
			padding := ",0"
			if width == "L" {
				padding += ",0"
			}
			for _, count := range []string{"Yi8", "Ycl", "Ycx"} {
				want := "{A" + stem + width + "," + count + ",Yrl,Yml,movDoubleShift,[4]uint8{" + prefix + opcodes + padding + "}}"
				if !strings.Contains(text, want) {
					t.Fatalf("missing full movtab row %s", want)
				}
				rows++
			}
		}
	}
	avx, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	text = compact(string(avx))
	for _, stem := range []string{"SARX", "SHLX", "SHRX", "RORX"} {
		for _, width := range []string{"L", "Q"} {
			tab, escape, opcode := "_ybextrl", "vex0F38", "0xF7"
			if stem == "RORX" {
				tab, escape, opcode = "_yrorxl", "vex0F3A", "0xF0"
				rows += 2
			} else {
				rows++
			}
			prefix := map[string]string{"SARX": "vexF3", "SHLX": "vex66", "SHRX": "vexF2", "RORX": "vexF2"}[stem]
			w := map[string]string{"L": "vexW0", "Q": "vexW1"}[width]
			want := "{as:A" + stem + width + ",ytab:" + tab + ",prefix:Pavx,op:opBytes{avxEscape|vex128|" + prefix + "|" + escape + "|" + w + "," + opcode + ",}}"
			if !strings.Contains(text, want) {
				t.Fatal("missing complete AVX attributes/opbytes", want)
			}
		}
	}
	for tab, want := range map[string]string{
		"_ybextrl": "{zcase:Zvex_v_rm_r,zoffset:2,args:argList{Yrl,Yml,Yrl}},",
		"_yrorxl":  "{zcase:Zvex_i_rm_r,zoffset:0,args:argList{Yu8,Yml,Yrl}},{zcase:Zvex_i_rm_r,zoffset:2,args:argList{Yi8,Yml,Yrl}},",
	} {
		capture := regexp.MustCompile(`(?s)var ` + tab + ` = \[\]ytab\{(.*?)\n\}`).FindStringSubmatch(string(avx))
		if len(capture) != 2 || compact(capture[1]) != want {
			t.Fatal("complete AVX zcase/advance/classes changed", tab)
		}
	}
	if rows != 148 {
		t.Fatalf("complete independent row denominator %d", rows)
	}
	t.Log("148 complete independent rows: 120 Group2, 18 double-shift, 10 BMI2; all attributes and opcode bytes")
}

func TestX86ScalarShiftCompleteRegisterEffects(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		rows := x86ScalarShiftTestRows(arch)
		// Actual Go object producer is independent of the effect implementation.
		goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+strings.Join(rows, "\n")+"\nRET\n", "", true)
		for _, row := range rows {
			t.Run(arch+"/"+row, func(t *testing.T) {
				ins := x86YMMReadSource(t, row)
				before := fmt.Sprintf("%#v", ins)
				undefined := (ins.Op == "SHLW" || ins.Op == "SHRW") && len(ins.Args) == 3 && (ins.Args[0].Kind == OpReg || ins.Args[0].Imm&31 > 16)
				for _, consumer := range x86ResultGPSIMDConsumers {
					state := x86ResultState{flags: x86ByteFlagsAll}
					for index := range state.gp {
						state.gp[index] = 0xff
					}
					if got := consumer.step(ins, &state, nil, 0, arch); got == undefined {
						t.Errorf("%s: effect accepted=%t undefined=%t", consumer.name, got, undefined)
					}
				}
				if before != fmt.Sprintf("%#v", ins) {
					t.Fatal("observer rewrote original source/operand metadata")
				}
			})
		}
	}
}

func TestX86ScalarShiftEveryRequiredInputByteAndAliasExtent(t *testing.T) {
	for _, row := range []string{"SHLB $5,AH", "RORW $1,BX", "RCLL $0,AX", "SHRL CX,BX", "SHRQ CL,R8", "SHLL $1,AX,BX", "SHRW $16,AX,BX", "SHLXQ AX,BX,AX", "SARXQ AX,AX,AX", "RORXQ $255,AX,BX"} {
		t.Run(row, func(t *testing.T) {
			ins := x86YMMReadSource(t, row)
			effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, "amd64")
			if !known || err != nil {
				t.Fatalf("missing typed effect: known=%t err=%v", known, err)
			}
			for _, operand := range effect.operands {
				if !operand.read || operand.operand.Kind != OpReg {
					continue
				}
				index, mask, valid := x86ResultGP(operand.operand.Reg, operand.width, "amd64")
				if !valid {
					t.Fatal("invalid expected register read")
				}
				for missing := 0; missing < 8; missing++ {
					if mask&(1<<uint(missing)) == 0 {
						continue
					}
					for _, consumer := range x86ResultGPSIMDConsumers {
						state := x86ResultState{flags: x86ByteFlagsAll}
						for i := range state.gp {
							state.gp[i] = 0xff
						}
						state.gp[index] &^= 1 << uint(missing)
						before := state.clone()
						if consumer.step(ins, &state, nil, 0, "amd64") || !reflect.DeepEqual(state, before) {
							t.Fatalf("%s acquired missing physical byte%d or changed failed state", consumer.name, missing)
						}
					}
				}
			}
		})
	}
	for _, row := range []string{"SHLL $0,AX", "ROLL $32,AX", "RCRL $0,AX", "SHLL $0,BX,AX", "RORXL $0,AX,AX", "SHLXQ CX,AX,AX"} {
		ins := x86YMMReadSource(t, row)
		for _, consumer := range x86ResultGPSIMDConsumers {
			state := x86ResultState{flags: x86ByteFlagsAll}
			state.gp[0], state.gp[1] = 0x0f, 1
			if strings.HasPrefix(row, "SHLXQ") {
				state.gp[0] = 0xff
			}
			if !consumer.step(ins, &state, nil, 0, "amd64") || state.gp[0] != 0xff {
				t.Fatalf("%s failed physical zero-count r32 upper overwrite / count low byte: %s %#v", consumer.name, row, state)
			}
		}
	}
}

func TestX86ScalarShiftBothResultObserversAndAuthority(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, move, reg, extract := 8, "MOVQ", "R8", "VPEXTRQ"
		if arch == "386" {
			word, move, reg, extract = 4, "MOVL", "AX", "VPEXTRD"
		}
		finish := fmt.Sprintf("%s %s,X0\n%s $0,X0,BX\n%s BX,ret0+%d(FP)\nRET", move, reg, extract, move, word)
		load := fmt.Sprintf("%s x+0(FP),%s\n", move, reg)
		for name, test := range map[string]struct {
			body string
			pass bool
		}{
			"exact CI class":              {load + "SHR" + map[string]string{"amd64": "Q", "386": "L"}[arch] + " $5," + reg + "\n" + finish, true},
			"both paths":                  {load + "CMPL " + reg + ",$0\nJE other\nSHRL $1," + reg + "\nJMP done\nother:\nROLL $1," + reg + "\ndone:\n" + finish, true},
			"missing initial destination": {"SHRL $5," + reg + "\n" + finish, false},
			"unknown count":               {load + "SHRL CL," + reg + "\n" + finish, false},
			"partial count sufficient":    {load + "MOVB $7,CL\nSHRL CX," + reg + "\n" + finish, true},
			"opaque input":                {fmt.Sprintf("%s p+0(FP),%s\nSHRL $5,%s\n", move, reg, reg) + finish, false},
			"native memory":               {load + "SHRL $5,(AX)\n" + finish, false},
			"SP numeric":                  {load + "SHRL $5,SP\n" + finish, false},
			"SB memory":                   {load + "SHRL $5,data(SB)\n" + finish, false},
			"undefined OF":                {load + "SHRL $2," + reg + "\nSETOS CL\n" + finish, false},
			"defined OF":                  {load + "SHRL $1," + reg + "\nSETOS CL\n" + finish, true},
			"unknown carry":               {load + "RCRL $1," + reg + "\n" + finish, false},
			"zero carry not read":         {load + "RCRL $0," + reg + "\n" + finish, true},
		} {
			t.Run(arch+"/"+name, func(t *testing.T) {
				declaration := "func Value(x uint64) uint64"
				if arch == "386" {
					declaration = "func Value(x uint32) uint32"
				}
				if name == "opaque input" {
					declaration = strings.Replace(declaration, "x uint64", "p *byte", 1)
					declaration = strings.Replace(declaration, "x uint32", "p *byte", 1)
				}
				_, file, sig, source := x86ResultInitializationFixture(t, arch, declaration, test.body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					err := check(file.Funcs[0], sig, arch)
					if test.pass && err != nil || !test.pass && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("pass=%t error=%v", test.pass, err)
					}
				}
			})
		}
	}
}
