package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86ByteShuffleActualCallerThreeAPIs(t *testing.T) {
	var body strings.Builder
	rows := []string{"PSHUFB X0,X1"}
	for _, bank := range []string{"X", "Y", "Z"} {
		for _, control := range []string{bank + "0", "(DI)"} {
			rows = append(rows,
				fmt.Sprintf("VPSHUFB %s,%s1,%s1", control, bank, bank),
				fmt.Sprintf("VPSHUFB %s,%s1,K1,%s1", control, bank, bank),
				fmt.Sprintf("VPSHUFB.Z %s,%s1,K1,%s1", control, bank, bank))
		}
	}
	for _, row := range rows {
		fmt.Fprintf(&body, "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nKMOVQ AX,K1\n%s\nVMOVSS X1,(DX)\n", row)
	}
	assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body.String(), 1)
	goAssemblerOracleOutput(t, "amd64", assembly, "", true)
	pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
	resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			options := Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs, ResolveSym: resolve}
			ir, err := Translate(file, options)
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "shuffle-text.ll", "shuffle-text.o", ir)
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, options)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "shuffle-module.ll", "shuffle-module.o", module.String())
			if err := x86CallerCoreTranslate(t, pkg, assembly, triple); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestX86ByteShuffleCallerMemoryCertificateAndAlignment(t *testing.T) {
	for _, row := range []string{"VPSHUFB (DI),X0,X2", "VPSHUFB.Z (DI),Z0,K1,Z2", "PSHUFB (DI),X0"} {
		result := "X2"
		if strings.HasPrefix(row, "PSHUFB") {
			result = "X0"
		}
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", "VMOVUPS (SI),Z0\nMOVL $0,AX\nKMOVQ AX,K1\n"+row+"\nVMOVSS "+result+",(DX)", 1)
		pkg, file := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
		resolve := func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) }
		sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := normalizeX86RawFile(file, "amd64", Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs})
		if strings.HasPrefix(row, "PSHUFB") {
			if err == nil {
				t.Fatal("caller slice acquired legacy m128 alignment")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, ins := range normalized.Funcs[0].Instrs {
			form, known, err := x86ByteShuffleProperties(ins.Op, ins, "amd64")
			if !known || err != nil || form.memory < 0 {
				continue
			}
			found = true
			index := form.memory
			access, exists := ins.x86CallerMemory[index]
			if !exists || access.write || access.width != int64(form.byteWidth) || !x86CallerMemoryCertified(ins, index) {
				t.Fatal("caller lost full E4NF tuple")
			}
			for _, change := range []string{"opcode", "width", "address", "destination", "direction", "mask"} {
				mutated := ins
				mutated.Args = append([]Operand(nil), ins.Args...)
				updated := access
				switch change {
				case "opcode":
					mutated.Op = "VPANDD"
				case "width":
					updated.width--
				case "address":
					mutated.Args[index].Mem.Off++
				case "destination":
					mutated.Args[form.destination].Reg = "X3"
				case "direction":
					updated.write = true
				case "mask":
					if form.mask >= 0 {
						mutated.Args[form.mask].Reg = "K2"
					} else {
						mutated.Args = append(mutated.Args, Operand{Kind: OpReg, Reg: "K2"})
					}
				}
				mutated.x86CallerMemory = map[int]x86CallerMemoryAccess{index: updated}
				if x86CallerMemoryCertified(mutated, index) {
					t.Fatal("changed shuffle retained caller memory authority", change)
				}
			}
		}
		if !found {
			t.Fatal("no shuffle consumed the caller proof")
		}
	}
}
