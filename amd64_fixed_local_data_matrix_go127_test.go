//go:build go1.27

package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalDataOperations() []string {
	var operations []string
	for _, name := range []string{"MOVB", "MOVW", "MOVL", "MOVQ"} {
		operations = append(operations, name+" literal<>+1(SB),DX\nMOVQ DX,48(SP)\nMOVOU 48(SP),X0")
	}
	for _, name := range []string{"MOVO", "MOVOA", "MOVOU", "MOVAPS", "MOVAPD", "MOVUPS", "MOVUPD"} {
		operations = append(operations, name+" literal<>(SB),X0")
	}
	for _, row := range fixedLocalPackedMoveOracle {
		for _, bank := range []string{"X", "Y", "Z"} {
			aligned := row.name == "VMOVDQA" || row.name == "VMOVAPD" || row.name == "VMOVAPS" ||
				row.name == "VMOVDQA32" || row.name == "VMOVDQA64"
			// Original Go's default assembly DATA alignment is at most 32.
			// A 64-byte aligned memory instruction needs a separate witness.
			if bank == "Z" && (!row.evex || aligned) {
				continue
			}
			operations = append(operations, row.name+" literal<>(SB),"+bank+"0")
			if row.evex {
				operations = append(operations,
					"KMOVQ AX,K1\n"+row.name+" literal<>(SB),K1,"+bank+"0",
					"KMOVQ AX,K1\n"+row.name+".Z literal<>(SB),K1,"+bank+"0")
			}
		}
	}
	for _, name := range []string{"KMOVB", "KMOVW", "KMOVD", "KMOVQ"} {
		operations = append(operations, name+" literal<>+1(SB),K1\nKMOVQ K1,DX\nMOVQ DX,48(SP)\nMOVOU 48(SP),X0")
	}
	for _, operation := range []string{
		"PADDB 16(SP),X0", "PADDW 16(SP),X0", "PADDL 16(SP),X0", "PADDQ 16(SP),X0",
		"PMADDWL 16(SP),X0", "CMPPS 16(SP),X0,$0", "CMPPD 16(SP),X0,$0",
	} {
		operations = append(operations, strings.Replace(operation, "16(SP)", "literal<>(SB)", 1))
	}
	for _, name := range []string{"AESENC", "AESENCLAST", "AESDEC", "AESDECLAST", "AESIMC"} {
		operations = append(operations, name+" literal<>(SB),X0")
	}
	operations = append(operations, "AESKEYGENASSIST $255,literal<>(SB),X0")
	for _, name := range []string{"VAESENC", "VAESENCLAST", "VAESDEC", "VAESDECLAST"} {
		operations = append(operations, name+" literal<>(SB),X0,X0")
	}
	operations = append(operations, "VAESIMC literal<>(SB),X0", "VAESKEYGENASSIST $255,literal<>(SB),X0")
	for _, name := range []string{"CMOVWEQ", "CMOVLEQ", "CMOVQEQ"} {
		operations = append(operations, "CMPQ AX,AX\n"+name+" literal<>+1(SB),DX\nMOVQ DX,48(SP)\nMOVOU 48(SP),X0")
	}
	return operations
}

func TestGoAMD64FixedLocalReadonlyDataLinuxRegisteredConsumers(t *testing.T) {
	fixedLocalDataTargetConsumers(t, "linux/amd64", "x86_64-unknown-linux-gnu")
}

func TestGoAMD64FixedLocalReadonlyDataDarwinRegisteredConsumers(t *testing.T) {
	fixedLocalDataTargetConsumers(t, "darwin/amd64", "x86_64-apple-darwin")
}

func TestGoAMD64FixedLocalReadonlyDataWindowsRegisteredConsumers(t *testing.T) {
	fixedLocalDataTargetConsumers(t, "windows/amd64", "x86_64-pc-windows-msvc")
}

func fixedLocalDataTargetConsumers(t *testing.T, target, triple string) {
	t.Helper()
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	operations := fixedLocalDataOperations()
	if len(operations) != 119 {
		t.Fatal("complete literal consumer denominator changed", len(operations))
	}
	for start := 0; start < len(operations); start += 32 {
		end := start + 32
		if end > len(operations) {
			end = len(operations)
		}
		t.Run(fmt.Sprintf("%s/batch%d", target, start/32), func(t *testing.T) {
			var assembly, declarations strings.Builder
			assembly.WriteString(strings.Replace(fixedLocalLiteralData, "$32", "$64", 1))
			for index := start; index < end; index++ {
				name := fmt.Sprintf("Value%d", index)
				body, _, _ := x86PrivateAlignedFrameAuditFixture(t, operations[index]+"\nPADDQ 16(SP),X0")
				assembly.WriteString(strings.Replace(body, "·Value", "·"+name, 1))
				fmt.Fprintf(&declarations, "func %s(a,b,c,d uint64) uint64\n", name)
			}
			pkg, request, _, options := x86CMOVFixedLocalFixture(t, assembly.String(), declarations.String(), target, triple)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "literal-consumers.ll", "literal-consumers.o", ir)
				compileLLVMToObject(t, llc, triple, "literal-consumers-opt.ll", "literal-consumers-opt.o", x86MulDivRoundOptimize(t, ir))
			})
		})
	}
	t.Logf("independent literal consumer operations=%d; actual Go target=%s, three APIs, O0/O2; at most 32 functions/module", len(operations), target)
}

func TestGoAMD64FixedLocalReadonlyDataRejectsUnownedAccesses(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, row := range []struct{ name, operation, data string }{
		{"past end", "MOVOU literal<>+24(SB),X0", fixedLocalLiteralData},
		{"negative", "MOVQ literal<>-1(SB),DX", fixedLocalLiteralData},
		{"unaligned", "MOVO literal<>+1(SB),X0", fixedLocalLiteralData},
		{"wide alignment", "VMOVDQA64 literal<>(SB),Z0", strings.Replace(fixedLocalLiteralData, "$32", "$64", 1)},
		{"zero mask cannot hide extent", "MOVQ $0,AX\nKMOVQ AX,K1\nVMOVDQU64.Z literal<>(SB),K1,Z0", fixedLocalLiteralData},
		{"write", "MOVOU X0,literal<>(SB)", fixedLocalLiteralData},
		{"address past end", "LEAQ literal<>(SB),DX\nADDQ $40,DX\nMOVQ (DX),DX", fixedLocalLiteralData},
		{"mutable", "MOVOU literal<>(SB),X0", strings.Replace(fixedLocalLiteralData, ",8,$32", ",16,$32", 1)},
		{"nonprivate", "MOVOU literal(SB),X0", strings.ReplaceAll(fixedLocalLiteralData, "literal<>", "literal")},
		{"address initializer", "MOVOU literal<>(SB),X0", fixedLocalLiteralData + "DATA pointer<>(SB)/8,$literal<>(SB)\nGLOBL pointer<>(SB),8,$8\n"},
		{"shortened extent", "MOVQ literal<>(SB),DX", strings.Replace(fixedLocalLiteralData, "$32", "$8", 1)},
	} {
		t.Run(row.name, func(t *testing.T) {
			pkg, request, file, options, assembly := fixedLocalDataFixture(t, row.operation+"\nPADDQ 16(SP),X0", row.data)
			x86LEAActualTargetGoObject(t, "amd64", options.TargetTriple, assembly)
			source := requireGoAMD64FrameCapture(t, pkg, request)
			expanded, err := source.preprocess(request.AssemblyFile, []byte(assembly))
			if err != nil {
				t.Fatal(err)
			}
			file, err = Parse(ArchAMD64, expanded)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			if _, err := source.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unowned literal operation obtained fixed-local permission", err)
			}
		})
	}
}
