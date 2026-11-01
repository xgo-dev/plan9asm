package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func x86UnpackTestLaneBytes(opcode string) int {
	switch {
	case strings.HasSuffix(opcode, "BW"):
		return 1
	case strings.HasSuffix(opcode, "WL"), strings.HasSuffix(opcode, "WD"):
		return 2
	case strings.HasSuffix(opcode, "LQ"), strings.HasSuffix(opcode, "DQ") && !strings.HasSuffix(opcode, "QDQ"), strings.HasSuffix(opcode, "PS"):
		return 4
	default:
		return 8
	}
}

func TestX86PackedUnpack386EVEXHighRegistersActualBytesNeedContext(t *testing.T) {
	for _, opcode := range x86CallerUnpackOpcodes() {
		if !strings.HasPrefix(opcode, "V") {
			continue
		}
		decode := decodedX86FloatingUnpackInstruction
		if strings.HasPrefix(opcode, "VPUNPCK") {
			decode = decodedX86EVEXPackedUnpackInstruction
		}
		for _, bank := range []string{"X", "Y"} {
			for _, high := range []int{16, 31} {
				for index := 0; index < 3; index++ {
					args := []string{bank + "0", bank + "1", bank + "2"}
					args[index] = fmt.Sprintf("%s%d", bank, high)
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
								t.Fatalf("actual Go object byte %q: %v", field, err)
							}
							code = append(code, byte(value))
						}
						break
					}
					if len(code) != 6 || code[0] != 0x62 {
						t.Fatalf("actual Go lost EVEX encoding: %s\n%s", row, listing)
					}
					ins, length, recognized, err := decode(code, 64)
					if !recognized || err != nil || length != len(code) || ins.Op != Op(opcode) || len(ins.Args) != 3 {
						t.Fatalf("mode64 actual byte identity: %s/%x: %+v/%d/%t/%v", row, code, ins, length, recognized, err)
					}
					for index, argument := range args {
						if ins.Args[index].Reg != Reg(argument) {
							t.Fatalf("actual Go %x decoded argument %d as %s want %s", code, index, ins.Args[index].Reg, argument)
						}
					}
					if _, _, recognized, err := decode(code, 32); !recognized || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("%s/%x invented raw mode32 high registers: %t/%v", row, code, recognized, err)
					}
				}
			}
		}
	}
}

func TestX86PackedUnpack386NamedHighRegistersKeepPhysicalContext(t *testing.T) {
	for _, opcode := range x86CallerUnpackOpcodes() {
		if !strings.HasPrefix(opcode, "V") {
			continue
		}
		for _, bank := range []string{"X", "Y"} {
			for _, high := range []int{8, 15, 16, 31} {
				for index := 0; index < 3; index++ {
					args := []string{bank + "0", bank + "1", bank + "2"}
					args[index] = fmt.Sprintf("%s%d", bank, high)
					row := opcode + " " + strings.Join(args, ",")
					// This invokes the actual Go tool on both compatibility
					// versions. Syntax acceptance alone is not a native binding.
					listing, err := x86ExtensionGoListing(t, "386", row)
					if err != nil || !strings.Contains(listing, row[:len(opcode)]) {
						t.Fatalf("actual Go lost accepted mode32 source %s: %v\n%s", row, err, listing)
					}
					file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
						if _, err := Translate(file, Options{Goarch: "386", TargetTriple: triple, Sigs: map[string]FuncSig{"f": {Ret: Void}}}); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("%s named high register acquired a physical mode32 binding: %v", row, err)
						}
					}
				}
			}
		}
	}
}

func x86UnpackTestHasMMX(opcode string) bool {
	return strings.HasPrefix(opcode, "PUNPCK") && !strings.HasSuffix(opcode, "QDQ")
}

func x86UnpackAcceptedForms(opcode, arch string) []string {
	if !strings.HasPrefix(opcode, "V") {
		last := 15
		if arch == "386" {
			last = 7
		}
		rows := []string{fmt.Sprintf("%s X0,X%d", opcode, last), fmt.Sprintf("%s 8(AX),X%d", opcode, last)}
		if arch == "amd64" && x86UnpackTestHasMMX(opcode) {
			rows = append(rows, opcode+" M0,M7", opcode+" 8(AX),M7")
		}
		return rows
	}
	var rows []string
	for _, bank := range []string{"X", "Y", "Z"} {
		last := 31
		if arch == "386" {
			last = 7
		}
		for _, first := range []string{bank + "0", "8(AX)"} {
			rows = append(rows, fmt.Sprintf("%s %s,%s1,%s%d", opcode, first, bank, bank, last))
			if arch == "amd64" {
				rows = append(rows,
					fmt.Sprintf("%s %s,%s1,K7,%s%d", opcode, first, bank, bank, last),
					fmt.Sprintf("%s.Z %s,%s1,K1,%s%d", opcode, first, bank, bank, last))
			}
		}
		if x86UnpackTestLaneBytes(opcode) >= 4 {
			rows = append(rows, fmt.Sprintf("%s.BCST 8(AX),%s1,%s%d", opcode, bank, bank, last))
			if arch == "amd64" {
				rows = append(rows,
					fmt.Sprintf("%s.BCST 8(AX),%s1,K7,%s%d", opcode, bank, bank, last),
					fmt.Sprintf("%s.BCST.Z 8(AX),%s1,K1,%s%d", opcode, bank, bank, last))
			}
		}
	}
	return rows
}

func TestX86PackedUnpackSpecsBindEveryGoOpcodeAttribute(t *testing.T) {
	if len(x86PackedUnpackSpecs) != len(x86CallerUnpackOpcodes()) {
		t.Fatal("incomplete interleave family")
	}
	dir := filepath.Join(runtime.GOROOT(), "src", "cmd", "internal", "obj", "x86")
	legacy, err := os.ReadFile(filepath.Join(dir, "asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	avx, err := os.ReadFile(filepath.Join(dir, "avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, opcode := range x86CallerUnpackOpcodes() {
		spec, ok := x86PackedUnpackSpecs[Op(opcode)]
		if !ok || spec.laneBits != 8*x86UnpackTestLaneBytes(opcode) {
			t.Fatalf("missing or wrong source-defined lane width: %s", opcode)
		}
		if !strings.HasPrefix(opcode, "V") {
			start := strings.Index(string(legacy), "{A"+opcode+", ")
			if start < 0 {
				t.Fatalf("actual Go omits %s", opcode)
			}
			line := strings.SplitN(string(legacy)[start:], "\n", 2)[0]
			table := "yxm"
			if x86UnpackTestHasMMX(opcode) {
				table = "ymm"
			}
			if !strings.Contains(line, ", "+table+",") {
				t.Fatalf("actual Go table differs for %s: %s", opcode, line)
			}
			continue
		}
		prefix := "{as: A" + opcode + ", ytab: _yvandnpd,"
		start := strings.Index(string(avx), prefix)
		if start < 0 {
			t.Fatalf("actual Go omits %s family table", opcode)
		}
		row := strings.SplitN(string(avx)[start:], "\n\t}},", 2)[0]
		if strings.Count(row, "avxEscape | vex") != 2 || strings.Count(row, "avxEscape | evex") != 3 {
			t.Fatalf("actual Go encoding generations changed: %s", row)
		}
		for _, line := range strings.Split(row, "\n") {
			if !strings.Contains(line, "avxEscape | evex") {
				continue
			}
			broadcast := ""
			if x86UnpackTestLaneBytes(opcode) >= 4 {
				broadcast = fmt.Sprintf("evexBcstN%d", x86UnpackTestLaneBytes(opcode))
			}
			if !strings.Contains(line, "evexZeroingEnabled") || strings.Contains(line, "evexSae") || strings.Contains(line, "evexRounding") ||
				broadcast == "" && strings.Contains(line, "evexBcst") || broadcast != "" && !strings.Contains(line, broadcast) {
				t.Fatalf("actual opcode attributes differ: %s", line)
			}
		}
	}
}

func TestX86PackedUnpackCompleteGoRowsAndFiveLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT unpackforms(SB),4,$0-0\n")
			count := 0
			for _, opcode := range x86CallerUnpackOpcodes() {
				for _, row := range x86UnpackAcceptedForms(opcode, target.arch) {
					count++
					fmt.Fprintln(&source, row)
				}
			}
			source.WriteString("RET\n")
			requireX86GoAssemblerResult(t, target.arch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			for _, ins := range file.Funcs[0].Instrs[1 : len(file.Funcs[0].Instrs)-1] {
				if _, recognized, err := x86PackedUnpackProperties(ins, target.arch); !recognized || err != nil {
					t.Fatalf("actual Go accepted %s but grammar rejected: %v", ins.Raw, err)
				}
			}
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewAPI(t, source.String(), "func unpackforms()", target.arch, target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("original unpack formats invented missing numerical/native inputs", api, err)
				}
			}
			ir := x86InstructionFormatObjectUnit(t, file, map[string]FuncSig{"unpackforms": {Name: "unpackforms", Ret: Void}},
				target.arch, target.triple, 0, func(c *amd64Ctx, ins Instr) (bool, bool, error) {
					return c.lowerPackedUnpack(ins.Op, ins)
				})
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, target.triple, text, level)
				}
			}
			t.Logf("all %d original Go forms retain emitter-only LLVM22 objects and three-API Context controls", count)
		})
	}
}

func TestX86PackedUnpackDispatchIdentityBeforeEmission(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\nVPUNPCKLBW X0,X1,X2\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, opcode := range []Op{"VPUNPCKLBW", "vpunpcklbw"} {
		for _, sourceOp := range []Op{"", "VPUNPCKLBW", "vpunpcklbw", "VPUNPCKHBW", "UNKNOWN"} {
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := output.String()
			ins := file.Funcs[0].Instrs[1]
			ins.Op = sourceOp
			_, _, err := ctx.lowerPackedUnpack(opcode, ins)
			wantError := sourceOp == "VPUNPCKHBW" || sourceOp == "UNKNOWN"
			if (err != nil) != wantError || wantError && output.String() != before || !wantError && output.String() == before {
				t.Fatalf("dispatch identity %s/%s: %v, %d emitted bytes", opcode, sourceOp, err, output.Len())
			}
		}
	}
}

func TestX86PackedUnpackRejectsMalformedGoFormsBeforeEmission(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, opcode := range x86CallerUnpackOpcodes() {
			rows := []string{opcode + " X0,(AX)", opcode + ".SAE X0,X1"}
			if strings.HasPrefix(opcode, "V") {
				rows = []string{
					opcode + " X0,X1,(AX)",
					opcode + " X0,Y1,Y2",
					opcode + " X0,X1,K0,X2",
					opcode + ".Z X0,X1,X2",
					opcode + ".SAE X0,X1,X2",
					opcode + ".BCST X0,X1,X2",
				}
				if x86UnpackTestLaneBytes(opcode) < 4 {
					rows = append(rows, opcode+".BCST (AX),X1,X2")
				}
			} else {
				rows = append(rows, opcode+" X0,Y1")
				if arch == "386" {
					rows = append(rows, opcode+" X8,X1")
				}
			}
			for _, row := range rows {
				t.Run(arch+"/"+row, func(t *testing.T) {
					source := "TEXT bad(SB),4,$0-0\n" + row + "\nRET\n"
					requireX86GoAssemblerResult(t, arch, source, false)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						return
					}
					ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
					ctx.goarch = arch
					before := output.String()
					ins := file.Funcs[0].Instrs[1]
					known, _, err := ctx.lowerPackedUnpack(ins.Op, ins)
					if !known || err == nil || output.String() != before {
						t.Fatalf("malformed source emitted IR: known=%t err=%v", known, err)
					}
				})
			}
		}
	}
}

func TestX86PackedUnpackMMXMemoryNativeExtent(t *testing.T) {
	for _, opcode := range x86CallerUnpackOpcodes() {
		if !x86UnpackTestHasMMX(opcode) {
			continue
		}
		source := "TEXT f(SB),4,$0-0\n" + opcode + " (AX),M0\nRET\n"
		requireX86GoAssemblerResult(t, "amd64", source, true)
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		form, recognized, err := x86PackedUnpackProperties(file.Funcs[0].Instrs[1], "amd64")
		want := 4
		if strings.Contains(opcode, "UNPCKH") {
			want = 8
		}
		if !recognized || err != nil || !form.mmx || form.memoryBytes != want {
			t.Fatalf("%s native memory extent=%d want=%d: %v", opcode, form.memoryBytes, want, err)
		}
	}
}

func TestX86PackedUnpackTypedFPMemoryExtentBeforeEmission(t *testing.T) {
	for _, opcode := range x86CallerUnpackOpcodes() {
		for _, row := range x86UnpackAcceptedForms(opcode, "amd64") {
			if !strings.Contains(row, "8(AX)") {
				continue
			}
			row = strings.Replace(row, "8(AX)", "a+0(FP)", 1)
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-64\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			form, _, err := x86PackedUnpackProperties(ins, "amd64")
			if err != nil {
				t.Fatal(err)
			}
			for _, complete := range []bool{false, true} {
				sig := FuncSig{Ret: Void}
				for offset := 0; offset < form.memoryBytes; offset += 4 {
					if !complete && offset+4 == form.memoryBytes {
						break
					}
					index := len(sig.Args)
					sig.Args = append(sig.Args, I32)
					sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: int64(offset), Type: I32, Index: index, Field: -1})
				}
				ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], sig, nil)
				before := output.String()
				known, _, err := ctx.lowerPackedUnpack(ins.Op, ins)
				if form.legacy && !form.mmx {
					if !known || !errors.Is(err, ErrProbeNeedsContext) || output.String() != before {
						t.Fatal("logical FP bytes invented original legacy native alignment", row, err)
					}
					continue
				}
				if !known || complete && err != nil || !complete && (err == nil || output.String() != before) {
					t.Fatalf("%s complete=%t native bytes=%d: %v", row, complete, form.memoryBytes, err)
				}
			}
		}
	}
}
