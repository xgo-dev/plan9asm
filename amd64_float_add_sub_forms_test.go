package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func x86FloatAddSubOpcodes() []string {
	return []string{"ADDPS", "ADDPD", "ADDSS", "ADDSD", "SUBPS", "SUBPD", "SUBSS", "SUBSD", "VADDPS", "VADDPD", "VADDSS", "VADDSD", "VSUBPS", "VSUBPD", "VSUBSS", "VSUBSD"}
}

func x86FloatArithmeticFamilyCount(family x86FloatArithmeticFamily) int {
	count := 0
	for _, spec := range x86FloatArithmeticSpecs {
		if spec.family() == family {
			count++
		}
	}
	return count
}

func TestX86FloatAddSubEveryGoOpcodeAttribute(t *testing.T) {
	if x86FloatArithmeticFamilyCount(x86FloatAddSubtract) != 16 {
		t.Fatal("incomplete floating add/sub family")
	}
	if !goToolchainAtLeast(runtime.Version(), 1, 27) {
		return // historical source builds still execute grammar/LLVM tests
	}
	dir := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	for _, filename := range []string{"asm6.go", "avx_optabs.go"} {
		data, err := os.ReadFile(filepath.Join(dir, filename))
		if err != nil {
			t.Fatal(err)
		}
		for _, opcode := range x86FloatAddSubOpcodes() {
			scalar := strings.HasSuffix(opcode, "SS") || strings.HasSuffix(opcode, "SD")
			bits := 32
			if strings.HasSuffix(opcode, "PD") || strings.HasSuffix(opcode, "SD") {
				bits = 64
			}
			legacy := !strings.HasPrefix(opcode, "V")
			if filename == "asm6.go" != legacy {
				continue
			}
			mode := amd64BinaryFloatingAdd
			if strings.Contains(opcode, "SUB") {
				mode = amd64BinaryFloatingSub
			}
			want := x86FloatArithmeticSpec{bits, legacy, scalar, mode}
			if got := x86FloatArithmeticSpecs[Op(opcode)]; got != want {
				t.Fatalf("%s spec differs from independent mnemonic: %+v/%+v", opcode, got, want)
			}
			if legacy {
				if !strings.Contains(string(data), "{A"+opcode+", yxm,") {
					t.Fatalf("Go legacy yxm changed: %s", opcode)
				}
				continue
			}
			prefix := "{as: A" + opcode + ", ytab: "
			start := strings.Index(string(data), prefix)
			if start < 0 {
				t.Fatalf("Go omits %s", opcode)
			}
			row := strings.SplitN(string(data)[start:], "\n\t}},", 2)[0]
			table := "_yvaddpd"
			if scalar {
				table = "_yvaddsd"
			}
			if !strings.HasPrefix(row, prefix+table+",") {
				t.Fatalf("Go grammar changed: %s", row)
			}
			seen := 0
			for _, line := range strings.Split(row, "\n") {
				if !strings.Contains(line, "avxEscape | evex") {
					continue
				}
				seen++
				if !strings.Contains(line, "evexZeroingEnabled") || strings.Contains(line, "evexSaeEnabled") ||
					strings.Contains(line, "evexRoundingEnabled") != (scalar || strings.Contains(line, "evex512")) ||
					strings.Contains(line, fmt.Sprintf("evexBcstN%d", bits/8)) != !scalar {
					t.Fatalf("%s opcode attribute changed: %s", opcode, line)
				}
			}
			if scalar && seen != 1 || !scalar && seen != 3 {
				t.Fatalf("%s incomplete EVEX row count %d", opcode, seen)
			}
		}
	}
}

func x86FloatAddSubFormats(arch string) []string {
	var rows []string
	for _, opcode := range x86FloatAddSubOpcodes() {
		scalar := strings.HasSuffix(opcode, "SS") || strings.HasSuffix(opcode, "SD")
		if !strings.HasPrefix(opcode, "V") {
			rows = append(rows, opcode+" X0,X1", opcode+" 8(AX),X1")
			continue
		}
		banks := []string{"X", "Y", "Z"}
		if scalar {
			banks = banks[:1]
		}
		for _, bank := range banks {
			for _, mode := range []string{"", "merge", "zero"} {
				if arch == "386" && mode != "" {
					continue
				}
				mask, zero := "", ""
				if mode != "" {
					mask = "K1,"
				}
				if mode == "zero" {
					zero = ".Z"
				}
				args := bank + "0," + bank + "1," + mask + bank + "2"
				memory := "(AX)," + bank + "1," + mask + bank + "2"
				rows = append(rows, opcode+zero+" "+args, opcode+zero+" "+memory)
				if !scalar {
					rows = append(rows, opcode+".BCST"+zero+" "+memory)
				}
				if scalar || bank == "Z" {
					for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
						rows = append(rows, opcode+"."+rounding+zero+" "+args)
					}
				}
			}
		}
	}
	return rows
}

func TestX86FloatAddSubCompleteGoGrammarAndFiveLLVMTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc missing")
	}
	for _, arch := range []string{"386", "amd64"} {
		var source strings.Builder
		sigs := map[string]FuncSig{}
		for index, row := range x86FloatAddSubFormats(arch) {
			name := fmt.Sprintf("addsub%d", index)
			entry := fmt.Sprintf("TEXT %s(SB),4,$0-0\n%s\nRET\n", name, row)
			file, err := Parse(ArchAMD64, entry)
			if err != nil {
				t.Fatal(err)
			}
			form, recognized, err := x86FloatAddSubProperties(file.Funcs[0].Instrs[1], arch)
			if !recognized || err != nil || form.byteWidth == 0 {
				t.Fatalf("%s/%s: %v", arch, row, err)
			}
			source.WriteString(entry)
			sigs[name] = FuncSig{Name: name, Ret: Void}
		}
		requireX86GoAssemblerResult(t, arch, source.String(), true)
		file, err := Parse(ArchAMD64, source.String())
		if err != nil {
			t.Fatal(err)
		}
		triples := []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"}
		if arch == "386" {
			triples = []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
		}
		for _, triple := range triples {
			ir, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "addsub-formats.ll", "addsub-formats.o", ir)
		}
		t.Logf("%s: %d independent Go add/sub formats", arch, len(sigs))
	}
}

func TestX86FloatAddSubRejectsMalformedBeforeEmission(t *testing.T) {
	for _, row := range []string{
		"ADDPS X0,Y1", "ADDSD X0,AX", "SUBSS X0,X16", "SUBPD.SAE X0,X1",
		"VADDPS X0,X1", "VADDPD X0,Y1,Y2", "VADDSS Y0,Y1,Y2", "VSUBSD X0,X1,K0,X2",
		"VADDPS.Z X0,X1,X2", "VADDPS.BCST X0,X1,X2", "VADDSS.BCST (AX),X1,X2",
		"VSUBPS.SAE Z0,Z1,Z2", "VADDPS.RD_SAE X0,X1,X2", "VSUBSD.RU_SAE (AX),X1,X2",
		"VADDPS. X0,X1,X2", "VSUBPS.Z.BCST (AX),Z1,K1,Z2",
		"VADDPS $data(SB),X1,X2", "VSUBSS (AX)(SP*2),X1,X2", "VADDPD 2147483648(AX),X1,X2",
	} {
		t.Run(row, func(t *testing.T) {
			requireX86GoAssemblerResult(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", false)
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				return // syntax rejection is also pre-emission
			}
			ins := file.Funcs[0].Instrs[1]
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := output.String()
			known, term, err := ctx.lowerFloatAddSub(ins.Op, ins)
			if !known || term || err == nil || output.String() != before {
				t.Fatalf("invalid add/sub emitted IR: %t/%t/%v", known, term, err)
			}
		})
	}
}

func TestX86FloatAddSubDispatchIdentityBeforeEmission(t *testing.T) {
	for _, opcode := range x86FloatAddSubOpcodes() {
		args := "X0,X1"
		if strings.HasPrefix(opcode, "V") {
			args += ",X2"
		}
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+opcode+" "+args+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		for _, identity := range []Op{"", Op(opcode), Op(strings.ToLower(opcode)), "UNKNOWN", "VADDPS.BCST"} {
			ins := file.Funcs[0].Instrs[1]
			ins.Op = identity
			original := ins
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := output.String()
			known, term, err := ctx.lowerFloatAddSub(Op(opcode), ins)
			conflict := identity == "UNKNOWN" || identity == "VADDPS.BCST"
			if !known || term || (err != nil) != conflict || conflict && output.String() != before || !reflect.DeepEqual(ins, original) {
				t.Fatalf("%s/%s source identity changed: %t/%t/%v", opcode, identity, known, term, err)
			}
		}
	}
}

func TestX86FloatAddSubDefaultAMD64ArchitectureHelperEmission(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc missing")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		for _, row := range []string{"ADDSS X0,X1", "VSUBPS Y0,Y1,Y2", "VADDSD.RD_SAE X0,X1,X2"} {
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{TargetTriple: triple, Sigs: map[string]FuncSig{"f": {Name: "f", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "addsub-default-target.ll", "addsub-default-target.o", ir)
		}
	}
}
