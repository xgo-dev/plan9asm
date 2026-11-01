package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

var x86WrappingAddOpcodes = []string{"PADDB", "PADDW", "PADDL", "PADDQ", "VPADDB", "VPADDW", "VPADDD", "VPADDQ"}

func x86WrappingAddFormats(arch string) []string {
	var rows []string
	for _, opcode := range append(append([]string(nil), x86WrappingAddOpcodes...), "PADDD") {
		spec := x86PackedWrappingAddSpecs[Op(opcode)]
		if !strings.HasPrefix(opcode, "V") {
			rows = append(rows, opcode+" X0,X7", opcode+" 16(AX)(BX*2),X7")
			if arch == "amd64" {
				rows = append(rows, opcode+" X15,X0", opcode+" data(SB),X0", opcode+" (FS),X0", opcode+" (GS),X0")
				if opcode != "PADDQ" {
					rows = append(rows, opcode+" M0,M7", opcode+" (AX),M7", opcode+" source+0(FP),M7")
				}
			}
			continue
		}
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, source := range []string{bank + "0", "16(AX)(BX*2)", "source+0(FP)"} {
				rows = append(rows, fmt.Sprintf("%s %s,%s1,%s7", opcode, source, bank, bank))
				if arch == "amd64" {
					rows = append(rows, fmt.Sprintf("%s %s,%s31,K1,%s30", opcode, source, bank, bank), fmt.Sprintf("%s.Z %s,%s31,K7,%s30", opcode, source, bank, bank))
				}
			}
			if spec.broadcastBytes != 0 {
				rows = append(rows, fmt.Sprintf("%s.BCST (AX),%s1,%s7", opcode, bank, bank))
				if arch == "amd64" {
					rows = append(rows, fmt.Sprintf("%s.BCST.Z source+0(FP),%s31,K7,%s30", opcode, bank, bank))
				}
			}
			if arch == "amd64" {
				rows = append(rows, fmt.Sprintf("%s %s31,%s30,%s29", opcode, bank, bank, bank))
			}
		}
	}
	return rows
}

func TestX86PackedWrappingAddActualGoCompleteAttributes(t *testing.T) {
	if len(x86PackedWrappingAddSpecs) != 9 {
		t.Fatal("eight wrapping operations and the actual Go PADDD alias required")
	}
	for index, opcode := range x86WrappingAddOpcodes {
		spec := x86PackedWrappingAddSpecs[Op(opcode)]
		bits := 8 << uint(index%4)
		broadcast := 0
		if index >= 6 {
			broadcast = bits / 8
		}
		if spec.laneBits != bits || spec.broadcastBytes != broadcast || spec.zeroing != (index >= 4) {
			t.Fatalf("%s has wrong independent arithmetic/tuple attributes: %+v", opcode, spec)
		}
	}
	if x86PackedWrappingAddSpecs["PADDD"] != x86PackedWrappingAddSpecs["PADDL"] {
		t.Fatal("actual Go alias must retain the exact canonical operation")
	}
	root := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86")
	legacy, err := os.ReadFile(filepath.Join(root, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	avx, err := os.ReadFile(filepath.Join(root, "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	aliases, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/arch/arch.go"))
	if err != nil || !strings.Contains(string(aliases), `instructions["PADDD"] = x86.APADDL`) {
		t.Fatalf("actual Go PADDD alias registration: %v", err)
	}
	for index, opcode := range []string{"PADDB", "PADDW", "PADDL", "PADDQ"} {
		byteOp := []int{0xfc, 0xfd, 0xfe, 0xd4}[index]
		registration := fmt.Sprintf("{A%s, ymm, Py1, opBytes{0x%x, Pe, 0x%x}}", opcode, byteOp, byteOp)
		if opcode == "PADDQ" {
			registration = "{APADDQ, yxm, Pe, opBytes{0xd4}}"
		}
		if !strings.Contains(string(legacy), registration) {
			t.Fatalf("actual Go legacy registration changed: %s", registration)
		}
		opcode = []string{"VPADDB", "VPADDW", "VPADDD", "VPADDQ"}[index]
		start := strings.Index(string(avx), "{as: A"+opcode+",")
		if start < 0 {
			t.Fatal("actual Go missing " + opcode)
		}
		row := strings.SplitN(string(avx)[start:], "\n\t}},", 2)[0]
		if !strings.Contains(row, "ytab: _yvandnpd") || strings.Contains(row, "Sae") || strings.Contains(row, "Rounding") {
			t.Fatalf("actual Go operand attributes changed: %s", row)
		}
		for _, width := range []string{"vex128", "vex256"} {
			if !strings.Contains(row, fmt.Sprintf("avxEscape | %s | vex66 | vex0F | vexW0, 0x%X", width, byteOp)) {
				t.Fatal("missing actual VEX registration " + opcode)
			}
		}
		for i, width := range []string{"evex128", "evex256", "evex512"} {
			w, broadcast := 0, ""
			if index >= 2 {
				broadcast = fmt.Sprintf(" | evexBcstN%d", 4<<(index-2))
			}
			if index == 3 {
				w = 1
			}
			want := fmt.Sprintf("avxEscape | %s | evex66 | evex0F | evexW%d, evexN%d%s | evexZeroingEnabled, 0x%X", width, w, 16<<i, broadcast, byteOp)
			if !strings.Contains(row, want) {
				t.Fatal("missing actual EVEX registration " + want)
			}
		}
	}
}

func TestX86PackedWrappingAddCompleteFormsFiveTargetsThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 required")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			arch := "amd64"
			if strings.HasPrefix(triple, "i") {
				arch = "386"
			}
			var source, declarations strings.Builder
			sigs := map[string]FuncSig{}
			for i, row := range x86WrappingAddFormats(arch) {
				name := fmt.Sprintf("padd%d", i)
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-64\n%s\nRET\n", name, row)
				fmt.Fprintf(&declarations, "func %s(source [64]byte)\n", name)
				sig := x86WordMaddFPType(t)
				sig.Name = name
				sigs[name] = sig
			}
			x86LEAActualTargetGoObject(t, arch, triple, source.String())
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			// A byte-array parameter does not initialize vector registers,
			// masks, native addresses or a physical MMX region. Keep these
			// exact original format rows, with independent initialized programs
			// in the arithmetic/native-read and closed-MMX family tests.
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("unbound wrapping-add formats acquired source inputs", api, err)
				}
			}
			before := fmt.Sprintf("%#v %#v", file, sigs)
			ir := x86ScalarFormatObjectUnit(t, file, sigs, arch, triple, 0)
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, text, level)
				}
			}
			if before != fmt.Sprintf("%#v %#v", file, sigs) {
				t.Fatal("format emitter mutated the original source or signatures")
			}
		})
	}
}

func TestX86PackedWrappingAddIdentityMalformedAndPhysicalBoundaries(t *testing.T) {
	for _, op := range x86WrappingAddOpcodes {
		row := op + " X0,X1"
		if strings.HasPrefix(op, "V") {
			row = op + " Y0,Y1,Y2"
		}
		file, _ := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		ins := file.Funcs[0].Instrs[1]
		for _, identity := range []Op{"", ins.Op, Op(strings.ToLower(op)), "UNKNOWN", "PADDB", "VPADDD", Op(op + ".SAE")} {
			local := ins
			local.Op = identity
			beforeIns := local
			ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := out.String()
			known, term, err := ctx.lowerPackedIntegerAdd(ins.Op, local)
			bad := identity != "" && strings.ToUpper(string(identity)) != op
			if !known || term || (err != nil) != bad || bad && before != out.String() || !reflect.DeepEqual(beforeIns, local) {
				t.Fatalf("dispatch/source mismatch %s/%s: %v", op, identity, err)
			}
		}
	}
	for _, row := range []string{"PADDQ M0,M1", "PADDB X0,Y1", "PADDW.Z X0,X1", "PADDL $data(SB),X0", "VPADDB.BCST (AX),Z0,Z1", "VPADDW.SAE Z0,Z1,Z2", "VPADDD.Z Z0,Z1,Z2", "VPADDQ.RN_SAE Z0,Z1,Z2", "VPADDQ.BCST X0,X1,X2", "VPADDD Z0,Z1,K0,Z2", "VPADDW X0,Y1,Y2", "VPADDQ 2147483648(AX),Z0,Z1", "VPADDB (AX)(SP*2),X0,X1"} {
		source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
		requireX86GoAssemblerResult(t, "amd64", source, false)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			continue
		}
		ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
		before := out.String()
		if _, _, err := ctx.lowerPackedIntegerAdd(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1]); err == nil || out.String() != before {
			t.Fatalf("malformed %s emitted IR: %v", row, err)
		}
	}
	for _, op := range []string{"VPADDB", "VPADDW", "VPADDD", "VPADDQ"} {
		for _, bank := range []string{"X", "Y"} {
			for index := 0; index < 3; index++ {
				args := []string{bank + "0", bank + "1", bank + "2"}
				args[index] = bank + "16"
				source := "TEXT f(SB),4,$0-0\n" + op + " " + strings.Join(args, ",") + "\nRET\n"
				requireX86GoAssemblerResult(t, "386", source, true)
				file, _ := Parse(ArchAMD64, source)
				if _, _, err := x86PackedWrappingAddProperties(file.Funcs[0].Instrs[1], "386"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("Go-accepted high mode32 encoded bank became permission: %v", err)
				}
			}
		}
	}
}

func TestX86PackedWrappingAddIndependentFPFieldsEveryByteAndMaskZero(t *testing.T) {
	for _, op := range []string{"VPADDB", "VPADDW", "VPADDD", "VPADDQ"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, broadcast := range []bool{false, true} {
				if broadcast && x86PackedWrappingAddSpecs[Op(op)].broadcastBytes == 0 {
					continue
				}
				opcode := op + ".Z"
				if broadcast {
					opcode = op + ".BCST.Z"
				}
				file, _ := Parse(ArchAMD64, "TEXT f(SB),4,$0-64\n"+opcode+" source+0(FP),"+bank+"1,K1,"+bank+"2\nRET\n")
				ins := file.Funcs[0].Instrs[1]
				form, _, err := x86PackedWrappingAddProperties(ins, "amd64")
				if err != nil {
					t.Fatal(err)
				}
				for missing := -1; missing < form.memoryBytes; missing++ {
					sig := x86WordMaddFPType(t)
					if missing >= 0 {
						sig.Frame.Params = append(sig.Frame.Params[:missing], sig.Frame.Params[missing+1:]...)
					}
					ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], sig, nil)
					before := out.String()
					_, _, err := ctx.lowerPackedIntegerAdd(ins.Op, ins)
					if missing < 0 && err != nil || missing >= 0 && (err == nil || out.String() != before) {
						t.Fatalf("%s/%s missing FP byte%d: %v", op, bank, missing, err)
					}
				}
			}
		}
	}
	for _, opcode := range []string{"PADDB", "PADDW", "PADDL", "PADDD"} {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-64\n"+opcode+" source+0(FP),M1\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		for missing := -1; missing < 8; missing++ {
			sig := x86WordMaddFPType(t)
			if missing >= 0 {
				sig.Frame.Params = append(sig.Frame.Params[:missing], sig.Frame.Params[missing+1:]...)
			}
			ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], sig, nil)
			before := out.String()
			_, _, err := ctx.lowerPackedIntegerAdd(ins.Op, ins)
			if missing < 0 && err != nil || missing >= 0 && (err == nil || out.String() != before) {
				t.Fatalf("%s MMX missing FP byte%d: %v", opcode, missing, err)
			}
		}
	}
}

func TestX86PackedWrappingAdd386HighRegisterActualByteIdentities(t *testing.T) {
	for _, opcode := range []string{"VPADDB", "VPADDW", "VPADDD", "VPADDQ"} {
		for _, bank := range []string{"X", "Y"} {
			for operand := 0; operand < 3; operand++ {
				args := []string{bank + "0", bank + "1", bank + "2"}
				args[operand] = bank + "16"
				row := opcode + " " + strings.Join(args, ",")
				listing, err := x86ExtensionGoListing(t, "386", row)
				if err != nil {
					t.Fatalf("actual Go mode32 object: %v\n%s", err, listing)
				}
				var code []byte
				for _, line := range strings.Split(listing, "\n") {
					fields := strings.Fields(line)
					if len(fields) < 7 || fields[0] != "0x0000" || len(fields[1]) != 2 {
						continue
					}
					for _, field := range fields[1:7] {
						value, err := strconv.ParseUint(field, 16, 8)
						if err != nil {
							t.Fatal(err)
						}
						code = append(code, byte(value))
					}
					break
				}
				ins, length, recognized, err := decodedX86PackedIntegerArithmeticInstruction(code, 64)
				if len(code) != 6 || !recognized || err != nil || length != 6 || ins.Op != Op(opcode) || len(ins.Args) != 3 {
					t.Fatalf("actual EVEX byte identity %s/%x: %+v/%d/%t/%v", row, code, ins, length, recognized, err)
				}
				for index, argument := range args {
					if ins.Args[index].Reg != Reg(argument) {
						t.Fatalf("%s/%x operand%d: %s != %s", row, code, index, ins.Args[index].Reg, argument)
					}
				}
				if _, _, recognized, err := decodedX86PackedIntegerArithmeticInstruction(code, 32); !recognized || err == nil {
					t.Fatalf("raw mode32 high bank obtained false permission: %s/%x", row, code)
				}
				t.Logf("%s actual Go bytes=%x; mode64 identities exact, mode32 rejected", row, code)
			}
		}
	}
}
