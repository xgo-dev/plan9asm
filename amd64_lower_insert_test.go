package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateX86PackedVectorInsertCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 defines three complete insert tables:
	//   _yvinsertf128: imm8, X/m, Y, Y
	//   _yvinsertf32x4: imm8, X/m, Y|Z, [K1-K7,] Y|Z
	//   _yvinsertf32x8: imm8, Y/m, Z, [K1-K7,] Z
	// Exercise register and memory members of every source class, every
	// destination width, and both merge and zero masking for all ten opcodes.
	for _, target := range []struct {
		name   string
		goarch string
		triple string
		zreg   int
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin", zreg: 21},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu", zreg: 21},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc", zreg: 21},
	} {
		t.Run(target.name, func(t *testing.T) {
			var src strings.Builder
			src.WriteString("TEXT packedvectorinsertforms(SB),NOSPLIT,$0-0\n")
			if target.goarch == "amd64" {
				for _, op := range []string{"VINSERTF128", "VINSERTI128"} {
					fmt.Fprintf(&src, "\t%s $0, X0, Y1, Y2\n", op)
					fmt.Fprintf(&src, "\t%s $255, (AX), Y3, Y4\n", op)
				}
			}
			for _, op := range []string{"VINSERTF32X4", "VINSERTF64X2", "VINSERTI32X4", "VINSERTI64X2"} {
				fmt.Fprintf(&src, "\t%s $0, X0, Y1, Y2\n", op)
				fmt.Fprintf(&src, "\t%s $255, (AX), Y3, Y4\n", op)
				fmt.Fprintf(&src, "\t%s $1, X20, Y20, K1, Y21\n", op)
				fmt.Fprintf(&src, "\t%s.Z $2, (AX), Y20, K2, Y21\n", op)
				fmt.Fprintf(&src, "\t%s $0, X0, Z0, Z%d\n", op, target.zreg)
				fmt.Fprintf(&src, "\t%s $255, (AX), Z0, Z%d\n", op, target.zreg)
				fmt.Fprintf(&src, "\t%s $3, X20, Z0, K3, Z%d\n", op, target.zreg)
				fmt.Fprintf(&src, "\t%s.Z $1, (AX), Z0, K4, Z%d\n", op, target.zreg)
			}
			for _, op := range []string{"VINSERTF32X8", "VINSERTF64X4", "VINSERTI32X8", "VINSERTI64X4"} {
				fmt.Fprintf(&src, "\t%s $0, Y0, Z0, Z%d\n", op, target.zreg)
				fmt.Fprintf(&src, "\t%s $255, (AX), Z0, Z%d\n", op, target.zreg)
				fmt.Fprintf(&src, "\t%s $1, Y20, Z0, K5, Z%d\n", op, target.zreg)
				fmt.Fprintf(&src, "\t%s.Z $1, (AX), Z0, K6, Z%d\n", op, target.zreg)
			}
			src.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, strings.Replace(src.String(), ",NOSPLIT", "", 1), true)

			file, err := Parse(ArchAMD64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"packedvectorinsertforms": {Name: "packedvectorinsertforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-vector-insert-"+target.name+".ll", "packed-vector-insert-"+target.name+".o", ll)
		})
	}
}

func TestTranslateX86PackedVectorInsertRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, instruction := range []string{
		"VINSERTI128 $0, Y0, Y1, Y2",
		"VINSERTF128 $0, X0, Z1, Z2",
		"VINSERTI128 $256, X0, Y1, Y2",
		"VINSERTF128 $-1, X0, Y1, Y2",
		"VINSERTI128.Z $0, X0, Y1, Y2",
		"VINSERTF128 $0, X0, Y1, K1, Y2",
		"VINSERTI32X4 $0, Y0, Y1, Y2",
		"VINSERTF64X2 $0, X0, X1, X2",
		"VINSERTI64X2 $0, X0, Y1, Z2",
		"VINSERTF32X4 $0, X0, Y1, K0, Y2",
		"VINSERTI32X4.Z $0, X0, Y1, Y2",
		"VINSERTF64X2.BCST $0, (AX), Z1, Z2",
		"VINSERTI32X8 $0, X0, Z1, Z2",
		"VINSERTF64X4 $0, Y0, Y1, Y2",
		"VINSERTI64X4 $0, Y0, Z1, K0, Z2",
		"VINSERTF32X8.Z $0, Y0, Z1, Z2",
	} {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			src := "TEXT bad(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, "amd64", strings.Replace(src, ",NOSPLIT", "", 1), false)
			file, err := Parse(ArchAMD64, src)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "x86_64-unknown-linux-gnu",
				Goarch:       "amd64",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's packed insert tables", instruction)
			}
		})
	}

	for _, instruction := range []string{
		"VINSERTI128 $0, X0, Y0, Y1",
		"VINSERTF128 $0, X0, Y0, Y1",
		"VINSERTI128 $0, X16, Y0, Y1",
		"VINSERTF128 $0, X0, Y16, Y1",
		"VINSERTF32X4 $0, X0, Y0, Y1",
		"VINSERTF64X2 $0, X0, Y0, Y1",
		"VINSERTI32X4 $0, X0, Y0, Y1",
		"VINSERTI64X2 $0, X0, Y0, Y1",
		"VINSERTF32X8 $0, Y0, Z0, Z1",
		"VINSERTF64X4 $0, Y0, Z0, Z1",
		"VINSERTI32X8 $0, Y0, Z0, Z1",
		"VINSERTI64X4 $0, Y0, Z0, Z1",
		"VINSERTI32X4 $0, X0, Z8, Z0",
		"VINSERTF64X2 $0, X0, Z0, K1, Z8",
		"VINSERTI32X8 $0, Y0, Z8, Z0",
		"VINSERTI64X4.Z $0, Y0, Z0, K1, Z8",
	} {
		src := "TEXT bad386(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
		requireX86GoAssemblerResult(t, "386", strings.Replace(src, ",NOSPLIT", "", 1), false)
		file, err := Parse(ArchAMD64, src)
		if err != nil {
			return
		}
		if _, err := Translate(file, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			Sigs:         map[string]FuncSig{"bad386": {Name: "bad386", Ret: Void}},
		}); err == nil {
			t.Fatalf("386 Translate accepted architecture-restricted %q", instruction)
		}
	}
}
