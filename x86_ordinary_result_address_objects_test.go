package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func x86OrdinaryResultAddressObjectFixture(arch string) (string, string, int) {
	word, offset := "Q", 8
	if arch == "386" {
		word, offset = "L", 4
	}
	cases := []struct {
		bits int
		body string
	}{
		{8, "MOVB a+0(FP),AL\n MOVB AL,(DI)"},
		{8, "MOVB $7,AH\n MOVB AH,(DI)"},
		{16, "MOVW $17,(DI)"},
		{32, "MOVL $17,AX\n MOVL AX,(DI)"},
		{64, "MOVL $17,(DI)\n MOVL $19,4(DI)"},
		{32, "PXOR X0,X0\n MOVL X0,(DI)"},
		{32, "PXOR X0,X0\n VMOVD X0,(DI)"},
	}
	for _, op := range []string{"MOVQ", "MOVD", "MOVDQ2Q", "VMOVQ"} {
		cases = append(cases, struct {
			bits int
			body string
		}{64,
			"PXOR X0,X0\n " + op + " X0,(DI)\n " + op + " (DI),X1\n " + op + " X1,(DI)"})
	}
	if arch == "amd64" {
		cases = append(cases, struct {
			bits int
			body string
		}{64, "MOVQ $0x123456789,AX\n MOVQ AX,(DI)"})
	}
	var source, declarations strings.Builder
	for index, row := range cases {
		name := fmt.Sprintf("ordinary%d", index)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n LEA%s ret+%d(FP),DI\n %s\n RET\n", name, offset+row.bits/8, word, offset, row.body)
		fmt.Fprintf(&declarations, "func %s(a uint8) uint%d\n", name, row.bits)
	}
	return source.String(), declarations.String(), len(cases)
}

func TestX86OrdinaryResultAddressOriginalGoAndLLVMFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, count := x86OrdinaryResultAddressObjectFixture(target.arch)
			receipt := x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			t.Logf("complete original %s source: %d TEXTs, source=%x object=%x SDK=%s", target.arch, count, receipt.Source, receipt.Object, receipt.GoVersion)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatalf("complete source %s: %v", api, err)
				}
				for _, level := range []string{"0", "2"} {
					t.Run(api+"/O"+level, func(t *testing.T) {
						objectIR := ir
						if level == "2" {
							objectIR = x86DwordProductIROptimize(t, ir)
						}
						dir := t.TempDir()
						input, output := filepath.Join(dir, "ordinary.ll"), filepath.Join(dir, "ordinary.o")
						if err := os.WriteFile(input, []byte(objectIR), 0600); err != nil {
							t.Fatal(err)
						}
						ctx, cancel := runtimeOracleStageContext(t)
						defer cancel()
						command := exec.CommandContext(ctx, llc, "-O"+level, "-mtriple="+target.triple, "-filetype=obj", input, "-o", output)
						if data, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
							t.Fatalf("LLVM22 complete result-address object: %v\n%s", err, data)
						}
						if info, err := os.Stat(output); err != nil || info.Size() == 0 {
							t.Fatalf("LLVM22 complete object absent: %v", err)
						}
					})
				}
			}
		})
	}
}
