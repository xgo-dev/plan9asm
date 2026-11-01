package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func x86WordMaddFormats(arch string) []string {
	rows := []string{"PMADDWL X0,X7", "PMADDWL (AX),X7"}
	if arch == "amd64" {
		rows = append(rows, "PMADDWL M0,M7", "PMADDWL (AX),M7", "PMADDWL source+0(FP),M7", "PMADDWL X15,X0", "PMADDWL X7,X7", "PMADDWL (FS),X1", "PMADDWL (GS),X1", "PMADDWL data(SB),X1")
	}
	for _, bank := range []string{"X", "Y", "Z"} {
		for _, source := range []string{bank + "0", "16(AX)(BX*2)", "source+0(FP)"} {
			rows = append(rows, fmt.Sprintf("VPMADDWD %s,%s1,%s7", source, bank, bank))
			if arch == "amd64" {
				rows = append(rows, fmt.Sprintf("VPMADDWD %s,%s31,K1,%s30", source, bank, bank), fmt.Sprintf("VPMADDWD.Z %s,%s31,K7,%s30", source, bank, bank))
			}
		}
		if arch == "amd64" {
			rows = append(rows, fmt.Sprintf("VPMADDWD %s31,%s30,%s29", bank, bank, bank))
		}
	}
	return rows
}

func x86WordMaddFPType(t *testing.T) FuncSig {
	t.Helper()
	pkg := mustGoPackage(t, "oracle", "package oracle\nfunc f(source [64]byte)\n")
	sig, err := DeriveGoFuncABI0Signature("f", pkg.Types.Scope().Lookup("f").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sig.Frame.Params) != 64 {
		t.Fatalf("actual Go 64-byte field layout changed: %+v", sig.Frame)
	}
	return sig
}

func TestX86WordMultiplyAddActualGoCompleteAttributes(t *testing.T) {
	if len(x86WordMultiplyAddSpecs) != 2 {
		t.Fatal("word multiply-add family must contain exactly the two Go spellings")
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
	if !strings.Contains(string(legacy), "{APMADDWL, ymm, Py1, opBytes{0xf5, Pe, 0xf5}}") {
		t.Fatal("actual Go legacy ymm registration changed")
	}
	start := strings.Index(string(avx), "{as: AVPMADDWD,")
	if start < 0 {
		t.Fatal("actual Go omits VPMADDWD")
	}
	row := strings.SplitN(string(avx)[start:], "\n\t}},", 2)[0]
	if !strings.Contains(row, "ytab: _yvandnpd") || strings.Contains(row, "Bcst") || strings.Contains(row, "Sae") {
		t.Fatalf("actual Go operand attributes changed: %s", row)
	}
	for _, width := range []string{"vex128", "vex256"} {
		if !strings.Contains(row, "avxEscape | "+width+" | vex66 | vex0F | vexW0, 0xF5") {
			t.Fatalf("actual Go VEX attribute missing: %s", width)
		}
	}
	for i, width := range []string{"evex128", "evex256", "evex512"} {
		if !strings.Contains(row, fmt.Sprintf("avxEscape | %s | evex66 | evex0F | evexW0, evexN%d | evexZeroingEnabled, 0xF5", width, 16<<i)) {
			t.Fatalf("actual Go EVEX attribute missing: %s", width)
		}
	}
}

func TestX86WordMultiplyAddCompleteFormsFiveTargetsTextModuleAndO2(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		arch := "amd64"
		if strings.HasPrefix(triple, "i") {
			arch = "386"
		}
		var source, declarations strings.Builder
		sigs := map[string]FuncSig{}
		for i, row := range x86WordMaddFormats(arch) {
			name := fmt.Sprintf("wordmadd%d", i)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-64\n%s\nRET\n", name, row)
			fmt.Fprintf(&declarations, "func %s(source [64]byte)\n", name)
			sig := x86WordMaddFPType(t)
			sig.Name = name
			sigs[name] = sig
		}
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
		file, err := Parse(ArchAMD64, source.String())
		if err != nil {
			t.Fatal(err)
		}
		t.Run(triple, func(t *testing.T) {
			// An FP parameter supplies only its actual bytes. It cannot supply
			// untouched vectors, an address, a mask or a closed MMX region.
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), arch, triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("original format source acquired missing inputs or physical state", api, err)
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
				t.Fatal("format object emitter mutated original source or signatures")
			}
			t.Log("original rows retain Go objects, three public Context checks and emitter-only objects; initialized caller/MMX owners are separate")
		})
	}
}

func TestX86WordMultiplyAddIdentityAndMalformedBeforeEmission(t *testing.T) {
	for _, row := range []string{"PMADDWL M0,M1", "PMADDWL X0,X1", "VPMADDWD Y0,Y1,Y2", "VPMADDWD.Z Z0,Z1,K1,Z2"} {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		for _, identity := range []Op{"", ins.Op, Op(strings.ToLower(string(ins.Op))), "UNKNOWN", "PMADDWL.Z", "VPMADDWD.SAE", "PMADDWL", "VPMADDWD"} {
			local := ins
			local.Op = identity
			beforeIns := local
			ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := out.String()
			known, term, err := ctx.lowerPackedWordMultiplyAdd(ins.Op, local)
			bad := identity != "" && strings.ToUpper(string(identity)) != strings.ToUpper(string(ins.Op))
			if !known || term || (err != nil) != bad || bad && out.String() != before || !reflect.DeepEqual(local, beforeIns) {
				t.Fatalf("%s/%s identity: %t/%t/%v", row, identity, known, term, err)
			}
		}
	}
	for _, row := range []string{"PMADDWD X0,X1", "PMADDWL X0", "PMADDWL X0,Y1", "PMADDWL X16,X0", "PMADDWL X0,M0", "PMADDWL.Z X0,X1", "PMADDWL $data(SB),X0", "VPMADDWD X0,X1", "VPMADDWD X0,Y1,Y2", "VPMADDWD Z0,Z1,(AX)", "VPMADDWD.BCST (AX),Z0,Z1", "VPMADDWD.SAE Z0,Z1,Z2", "VPMADDWD.Z X0,X1,X2", "VPMADDWD X0,X1,K0,X2", "VPMADDWD (AX)(SP*2),X0,X1", "VPMADDWD 2147483648(AX),X0,X1"} {
		t.Run(row, func(t *testing.T) {
			source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
			requireX86GoAssemblerResult(t, "amd64", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			ctx, out := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := out.String()
			_, _, err = ctx.lowerPackedWordMultiplyAdd(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1])
			if row != "PMADDWD X0,X1" && (err == nil || out.String() != before) {
				t.Fatalf("malformed form emitted IR: %v", err)
			}
		})
	}
}

func TestX86WordMultiplyAdd386HighRegistersNeedPhysicalContext(t *testing.T) {
	for _, bank := range []string{"X", "Y"} {
		for _, index := range []int{8, 15, 16, 31} {
			for operand := 0; operand < 3; operand++ {
				args := []string{bank + "0", bank + "1", bank + "2"}
				args[operand] = fmt.Sprintf("%s%d", bank, index)
				row := "VPMADDWD " + strings.Join(args, ",")
				requireX86GoAssemblerResult(t, "386", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", true)
				file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := x86WordMultiplyAddProperties(file.Funcs[0].Instrs[1], "386"); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("mode32 high bank became physical permission: %s: %v", row, err)
				}
			}
		}
	}
}

func TestX86WordMultiplyAdd386HighRegisterActualByteIdentities(t *testing.T) {
	for _, bank := range []string{"X", "Y"} {
		for _, high := range []int{16, 31} {
			for operand := 0; operand < 3; operand++ {
				args := []string{bank + "0", bank + "1", bank + "2"}
				args[operand] = fmt.Sprintf("%s%d", bank, high)
				row := "VPMADDWD " + strings.Join(args, ",")
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
				ins, length, recognized, err := decodedX86EVEXPackedMADDInstruction(code, 64)
				if len(code) != 6 || !recognized || err != nil || length != 6 || ins.Op != "VPMADDWD" || len(ins.Args) != 3 {
					t.Fatalf("actual EVEX byte identity %s/%x: %+v/%d/%t/%v", row, code, ins, length, recognized, err)
				}
				for i, argument := range args {
					if ins.Args[i].Reg != Reg(argument) {
						t.Fatalf("%s/%x argument %d = %s != %s", row, code, i, ins.Args[i].Reg, argument)
					}
				}
				if _, _, recognized, err := decodedX86EVEXPackedMADDInstruction(code, 32); !recognized || err == nil {
					t.Fatalf("raw mode32 high bank obtained false permission: %s/%x", row, code)
				}
				t.Logf("%s actual Go bytes=%x; mode64 identities exact, mode32 rejected", row, code)
			}
		}
	}
}

func TestX86WordMultiplyAdd386GoRejectedHighZFormsRemainRejected(t *testing.T) {
	// Unlike the X/Y encoder anomaly, Go rejects high Z in mode32. Keep the
	// actual original source as a negative; do not call it accepted syntax.
	for _, high := range []int{8, 15, 16, 31} {
		for index := 0; index < 3; index++ {
			args := []string{"Z0", "Z1", "Z2"}
			args[index] = fmt.Sprintf("Z%d", high)
			source := "TEXT f(SB),4,$0-0\nVPMADDWD " + strings.Join(args, ",") + "\nRET\n"
			requireX86GoAssemblerResult(t, "386", source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{Goarch: "386", TargetTriple: "i386-unknown-linux-gnu", Sigs: map[string]FuncSig{"f": {Ret: Void}}}); err == nil {
				t.Fatalf("Go-rejected mode32 high Z obtained physical permission: %s", source)
			}
		}
	}
}

func TestX86WordMultiplyAddIndependentFPFieldsAndMissingBytes(t *testing.T) {
	for _, row := range []string{"PMADDWL source+0(FP),M1", "VPMADDWD source+0(FP),X1,X2", "VPMADDWD source+0(FP),Y1,Y2", "VPMADDWD.Z source+0(FP),Z1,K1,Z2"} {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-64\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		form, _, err := x86WordMultiplyAddProperties(ins, "amd64")
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
			_, _, err := ctx.lowerPackedWordMultiplyAdd(ins.Op, ins)
			if missing < 0 {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || out.String() != before {
				t.Fatalf("%s missing FP byte%d emitted or invented backing: %v", row, missing, err)
			}
		}
	}
}
