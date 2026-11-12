package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// Independent full opcode/ytab axes, not a rendering of the production map.
func x86InsertExtractFormats() []string {
	var rows []string
	for _, action := range []string{"EXTRACT", "INSERT"} {
		for _, kind := range []string{"F", "I"} {
			for _, size := range []string{"128", "32X4", "64X2", "32X8", "64X4"} {
				op, small := "V"+action+kind+size, "X"
				widths := []string{"Y", "Z"}
				if size == "128" {
					widths = []string{"Y"}
				}
				if strings.HasSuffix(size, "X8") || strings.HasSuffix(size, "X4") && strings.HasPrefix(size, "64") {
					small, widths = "Y", []string{"Z"}
				}
				for _, wide := range widths {
					for _, memory := range []bool{false, true} {
						for _, masking := range []string{"", "merge", "zero"} {
							if size == "128" && masking != "" || action == "EXTRACT" && memory && masking == "zero" {
								continue
							}
							mnemonic, mask := op, ""
							if masking != "" {
								mask = ",K1"
							}
							if masking == "zero" {
								mnemonic += ".Z"
							}
							transfer := small + "0"
							if memory {
								transfer = "(BX)"
							}
							if action == "INSERT" {
								rows = append(rows, fmt.Sprintf("%s $255,%s,%s1%s,%s2", mnemonic, transfer, wide, mask, wide))
							} else {
								rows = append(rows, fmt.Sprintf("%s $255,%s1%s,%s", mnemonic, wide, mask, transfer))
							}
						}
					}
				}
			}
		}
	}
	return append(rows, "VEXTRACTPS $255,X1,AX", "VEXTRACTPS $255,X1,(BX)", "VINSERTPS $255,X0,X1,X2", "VINSERTPS $255,(BX),X1,X2",
		"EXTRACTPS $3,X1,AX", "EXTRACTPS $3,X1,(BX)", "INSERTPS $255,X0,X1", "INSERTPS $255,(BX),X1")
}

func TestX86InsertExtractEveryGoOpcodeAttribute(t *testing.T) {
	if len(x86InsertExtractSpecs) != 24 {
		t.Fatal("incomplete family")
	}
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{
		"VEXTRACTF128": "vexW0, 0x19", "VEXTRACTI128": "vexW0, 0x39",
		"VEXTRACTF32X4": "evexW0, evexN16", "VEXTRACTI32X4": "evexW0, evexN16",
		"VEXTRACTF64X2": "evexW1, evexN16", "VEXTRACTI64X2": "evexW1, evexN16",
		"VEXTRACTF32X8": "evexW0, evexN32", "VEXTRACTI32X8": "evexW0, evexN32",
		"VEXTRACTF64X4": "evexW1, evexN32", "VEXTRACTI64X4": "evexW1, evexN32",
		"VINSERTF128": "vexW0, 0x18", "VINSERTI128": "vexW0, 0x38",
		"VINSERTF32X4": "evexW0, evexN16", "VINSERTI32X4": "evexW0, evexN16",
		"VINSERTF64X2": "evexW1, evexN16", "VINSERTI64X2": "evexW1, evexN16",
		"VINSERTF32X8": "evexW0, evexN32", "VINSERTI32X8": "evexW0, evexN32",
		"VINSERTF64X4": "evexW1, evexN32", "VINSERTI64X4": "evexW1, evexN32",
		"VEXTRACTPS": "evexW0, evexN4", "VINSERTPS": "evexW0, evexN4",
	}
	var observed []string
	for _, row := range strings.Split(string(data), "{as: A") {
		op := strings.SplitN(row, ",", 2)[0]
		if !strings.HasPrefix(op, "VEXTRACT") && !strings.HasPrefix(op, "VINSERT") {
			continue
		}
		observed = append(observed, op)
		body := strings.SplitN(row, "\n\t}},", 2)[0]
		spec, exists := x86InsertExtractSpecs[Op(op)]
		if !exists {
			t.Fatalf("unregistered actual Go opcode: %s", op)
		}
		if strings.Contains(body, "Bcst") || strings.Contains(body, "Sae") ||
			strings.Contains(body, "evexZeroingEnabled") != (!spec.scalar && !spec.vex) {
			t.Fatalf("per-opcode flags changed: %s", body)
		}
		if spec.vex && strings.Contains(body, "evex") || !spec.vex && !strings.Contains(body, "evex") {
			t.Fatalf("encoding identity changed: %s", body)
		}
		if attribute, exists := expected[op]; !exists || !strings.Contains(body, attribute) ||
			!strings.Contains(body, "0F3A") || spec.allowY != strings.Contains(body, "256") || spec.allowZ != strings.Contains(body, "512") {
			t.Fatalf("per-opcode W/tuple/native width attributes changed: %s", body)
		}
	}
	sort.Strings(observed)
	if len(observed) != 22 {
		t.Fatalf("actual Go family: %v", observed)
	}
	legacy, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{
		"{AEXTRACTPS, yextractps, Pq, opBytes{0x3a, 0x17, 0}}",
		"{AINSERTPS, yxshuf, Pq, opBytes{0x3a, 0x21, 0}}",
		"var yextractps = []ytab{\n\t{Zibr_m, 2, argList{Yu2, Yxr, Yml}}",
		"var yxshuf = []ytab{\n\t{Zibm_r, 2, argList{Yu8, Yxm, Yxr}}",
	} {
		if !strings.Contains(string(legacy), row) {
			t.Fatalf("actual Go legacy PS row changed: %s", row)
		}
	}
}

func TestX86InsertExtractFormatsAndFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc missing")
	}
	for _, arch := range []string{"amd64", "386"} {
		var source strings.Builder
		for index, row := range x86InsertExtractFormats() {
			if arch == "386" && (strings.HasPrefix(row, "VINSERT") || strings.Contains(row, "K1")) {
				goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
				continue
			}
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			_, known, err := x86InsertExtractProperties(file.Funcs[0].Instrs[1], arch)
			if !known || err != nil {
				t.Fatalf("%s/%s: %v", arch, row, err)
			}
			goAssemblerOracleOutput(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", true)
			name := fmt.Sprintf("transfer%d", index)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%s\nRET\n", name, row)
		}
		triples := []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"}
		if arch == "386" {
			triples = []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
		}
		for _, triple := range triples {
			t.Run(triple, func(t *testing.T) {
				// Preserve every original uninitialized row as Go/public-Context
				// and emitter-object coverage. Complete initialized programs have
				// separate public object and executed-byte owners.
				file, signatures := x86UnboundVoidFormatSources(t, source.String(), arch, triple)
				ir := x86InstructionFormatObjectUnit(t, file, signatures, arch, triple, 0,
					func(c *amd64Ctx, ins Instr) (bool, bool, error) {
						return c.lowerInsertExtractFamily(ins.Op, ins)
					})
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, triple, ir, level)
				}
			})
		}
	}
}

func TestX86InsertExtractDispatchIdentityAndGrammarBeforeEmission(t *testing.T) {
	for _, row := range x86InsertExtractFormats() {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		for _, identity := range []Op{"", ins.Op, Op(strings.ToLower(string(ins.Op))), "UNKNOWN", "VEXTRACTPS.Z"} {
			copy := ins
			copy.Op = identity
			original := copy
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := output.String()
			known, term, err := ctx.lowerInsertExtractFamily(ins.Op, copy)
			failure := identity == "UNKNOWN" || identity == "VEXTRACTPS.Z"
			if !known || term || (err != nil) != failure || failure && output.String() != before || !reflect.DeepEqual(copy, original) {
				t.Fatalf("%s/%s: %t/%t/%v", row, identity, known, term, err)
			}
		}
	}
	for _, row := range []string{
		"VEXTRACTF128 $256,Y0,X1", "VEXTRACTF128 $-129,Y0,X1", "VEXTRACTF128 $0,Y16,X1",
		"VEXTRACTF64X4 $-1,Z0,Y1", "VEXTRACTF32X4.Z $0,Z0,X1", "VEXTRACTI32X4 $0,Z0,K0,X1",
		"VEXTRACTPS $-1,X31,AX", "VEXTRACTPS $0,X0,X1", "VINSERTPS $-1,X0,X1,X2",
		"VINSERTI128 $0,X0,Y0,Y16", "VINSERTF32X8.BCST $0,(AX),Z0,Z1",
		"VINSERTF64X2.RN_SAE $0,X0,Z0,Z1", "VINSERTI64X4.Z $0,Y0,Z0,Z1",
		"VINSERTPS $0,(AX)(SP*2),X0,X1", "VINSERTPS $0,2147483648(AX),X0,X1",
		"VEXTRACTF32X4 $0,Z0,$data(SB)",
		"VEXTRACTF128 $selector,Y0,X1", "VINSERTPS $1.5,X0,X1,X2",
		"INSERTPS $selector,X0,X1", "EXTRACTPS $1.5,X0,AX", "EXTRACTPS $4,X0,AX",
		"INSERTPS $0,X16,X0", "EXTRACTPS $0,X16,AX", "INSERTPS.Z $0,X0,X1",
	} {
		source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
		// Go 1.20 emitted the reserved EVEX.z=1/aaa=0 combination for
		// this unchanged negative. Current Go rejects it. Syntax acceptance
		// cannot authorize that physical invalid-opcode form.
		reservedZeroMask := row == "VEXTRACTF32X4.Z $0,Z0,X1" || row == "VINSERTI64X4.Z $0,Y0,Z0,Z1"
		if reservedZeroMask {
			x86InsertExtractReservedZeroMaskGoObservation(t, source)
		} else {
			goAssemblerOracleOutput(t, "amd64", source, "", false)
		}
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			continue
		}
		ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
		before := output.String()
		known, _, err := ctx.lowerInsertExtractFamily(file.Funcs[0].Instrs[1].Op, file.Funcs[0].Instrs[1])
		if !known || err == nil || output.String() != before {
			t.Fatalf("malformed source emitted IR: %s: %v", row, err)
		}
	}
}

func TestX86InsertExtractCompleteTypedFPSpanBeforeEmission(t *testing.T) {
	for _, row := range x86InsertExtractFormats() {
		if !strings.Contains(row, "(BX)") {
			continue
		}
		row = strings.Replace(row, "(BX)", "a+0(FP)", 1)
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-32\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		form, _, err := x86InsertExtractProperties(ins, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		width := form.spec.chunk
		if form.spec.scalar && !form.spec.insert {
			// The PS writer now consumes the full source-byte proof too.
			// Keep this test about complete spans, not unknown X input data.
			file.Funcs[0].Instrs = append([]Instr{
				file.Funcs[0].Instrs[0], x86ScalarLaneInstruction(t, "PXOR X1,X1"),
			}, file.Funcs[0].Instrs[1:]...)
		}
		for _, missing := range []int{-1, 0, width - 1} {
			sig := FuncSig{Name: "f", Ret: Void}
			for index := 0; index < width; index++ {
				if index != missing {
					sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: int64(index), Type: I8, Index: len(sig.Args), Field: -1})
					sig.Args = append(sig.Args, I8)
				}
			}
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], sig, nil)
			before := output.String()
			known, term, err := ctx.lowerInsertExtractFamily(ins.Op, ins)
			// Native E6NF requires a physical contiguous destination. Typed
			// individual ABI0 shadow cells do not supply it, even if every
			// slot is bound. This remains Context, not fabricated memory.
			failure := missing >= 0 || form.memoryWrite && form.mask >= 0
			if !known || term || (err != nil) != failure || failure && output.String() != before {
				t.Fatalf("%s missing FP byte %d: %t/%t/%v", row, missing, known, term, err)
			}
		}
	}
}
