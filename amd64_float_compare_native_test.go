package plan9asm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestX86FloatCompareNativeOriginalInstruction(t *testing.T) {
	for _, row := range []string{
		"CMPPS X0,X1,$3", "CMPSD 3(AX),X1,$1",
		"VCMPPS $11,Y0,Y1,Y2", "VCMPPD $15,Z0,Z1,K3,K2",
		"VCMPPS.BCST $31,3(AX),Z1,K3,K2", "VCMPSS.SAE $31,X0,X1,K3,K2",
	} {
		t.Run(row, func(t *testing.T) {
			source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
			ir := x86FloatingCompareUnboundFormatObject(t, source, "amd64", "x86_64-unknown-linux-gnu")
			opcode := strings.ToLower(strings.Split(row, " ")[0])
			opcode = strings.Split(opcode, ".")[0]
			if !strings.Contains(ir, "asm sideeffect") || !strings.Contains(ir, opcode+" $$") || strings.Contains(ir, " = fcmp ") {
				t.Fatalf("original whole instruction/CSR effect missing:\n%s", ir)
			}
		})
	}
}

func TestX86FloatCompareNativeAllPredicatesObjectsAndDeadO2(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	var source strings.Builder
	count := 0
	for _, opcode := range x86FloatCompareOpcodes() {
		for _, row := range x86FloatCompareOracleCases(opcode) {
			name := fmt.Sprintf("native_compare%d", count)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%s\nRET\n", name, row.row)
			count++
		}
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	for _, triple := range []string{"x86_64-apple-macosx", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		ir := x86FloatingCompareUnboundFormatObject(t, source.String(), "amd64", triple)
		if strings.Count(ir, "asm sideeffect") != count {
			t.Fatalf("whole-instruction sideeffects=%d want=%d", strings.Count(ir, "asm sideeffect"), count)
		}
		compileLLVMToObject(t, llc, triple, "native-compare.ll", "native-compare.o", ir)
		path := filepath.Join(t.TempDir(), "dead.ll")
		if err := os.WriteFile(path, []byte(ir), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		command := exec.CommandContext(ctx, llc, "-O2", "-mtriple="+triple, "-filetype=asm", path, "-o", "-")
		output, err := runtimeOracleCombinedOutput(ctx, command)
		cancel()
		if err != nil {
			t.Fatalf("dead native effect object: %v\n%s", err, output)
		}
		// LLVM's assembly printer canonicalizes CMP-immediate mnemonics to
		// predicate aliases (cmpeqps, vcmptrue_uspd, ...). Count those actual
		// instructions, not the source spelling, after optimizing dead results.
		compares := regexp.MustCompile(`(?m)^\s+v?cmp[a-z0-9_]*(ps|pd|ss|sd)\s+`).FindAll(output, -1)
		if len(compares) != count {
			t.Fatalf("dead O2 retained %d native comparisons, want %d", len(compares), count)
		}
	}
	t.Logf("%d independent 8/32-predicate forms: 3 objects plus dead O2 native emission", count)
}

func TestX86FloatCompareNativePhysicalMemoryAndPrefixContract(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"386", "amd64"} {
		var source strings.Builder
		for index, row := range []string{
			"CMPPS 16(AX)(CX*4),X1,$127", "CMPSS 3(FS),X1,$-128",
			"CMPPD 16(GS),X1,$-1", "CMPSD 256,X1,$7",
		} {
			name := fmt.Sprintf("memory%d", index)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%s\nRET\n", name, row)
		}
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
		triples := []string{"x86_64-apple-macosx", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"}
		if arch == "386" {
			triples = []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
		}
		for _, triple := range triples {
			ir := x86FloatingCompareUnboundFormatObject(t, source.String(), arch, triple)
			for _, want := range []string{"%fs:$2", "%gs:$2", "elementtype([16 x i8])", "elementtype([4 x i8])", "elementtype([8 x i8])", "$$127", "$$128", "$$255"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("%s original memory/predicate contract lost %s:\n%s", arch, want, ir)
				}
			}
			compileLLVMToObject(t, llc, triple, "native-memory.ll", "native-memory.o", ir)
		}
	}
	file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\nCMPPS (AX),X1,$0\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
	ctx.goarch = "amd64"
	ins := file.Funcs[0].Instrs[1]
	ins.x86AddressBits = 32
	before := output.Len()
	if _, _, err := ctx.lowerFloatingCompare(ins.Op, ins); !errors.Is(err, ErrProbeNeedsContext) || output.Len() != before {
		t.Fatalf("unbound native address prefix emitted compare IR: %v", err)
	}
}

func TestX86FloatCompareNativeRawMode32HighBanksRemainContext(t *testing.T) {
	for _, code := range [][]byte{
		encodeX86VEXVectorFloatCompare(0, false, 8, 1, 0, 0),
		encodeX86VEXVectorFloatCompare(1, true, 2, 8, 0, 0),
		encodeX86VEXVectorFloatCompare(2, false, 2, 1, 8, 0),
		encodeX86EVEXVectorFloatCompare(0, 2, false, 3, 2, 8, 0, 0),
		encodeX86EVEXVectorFloatCompare(1, 0, false, 3, 2, 1, 8, 0),
		encodeX86EVEXVectorFloatCompare(2, 0, false, 3, 2, 1, 16, 0),
	} {
		if _, _, known, err := decodedX86VectorFloatCompareInstruction(code, 32); !known || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("mode32 high-bank %x gained a native binding: %v", code, err)
		}
	}
	file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\nVCMPPS $0,X0,X1,X2\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "386", Sigs: map[string]FuncSig{"f": {Ret: Void}}}); err == nil {
		t.Fatal("named mode32 source impersonated private raw decoding")
	}
}

func TestX86FloatCompareNativeRawMode32PhysicalForms(t *testing.T) {
	mc, llc := findLLVM22Tool("llvm-mc"), findLLVM22Tool("llc")
	if mc == "" || llc == "" {
		t.Fatal("LLVM22 mc/llc required")
	}
	var source strings.Builder
	count := 0
	for pp := byte(0); pp < 4; pp++ {
		widths := []byte{0, 1, 2}
		if pp >= 2 {
			widths = widths[:1]
		}
		for _, width := range widths {
			for predicate := byte(0); predicate < 32; predicate++ {
				var codes [][]byte
				if width != 2 {
					codes = append(codes, encodeX86VEXVectorFloatCompare(pp, width == 1, 2, 1, 0, predicate))
				}
				codes = append(codes, encodeX86EVEXVectorFloatCompare(pp, width, false, 3, 2, 1, 0, predicate))
				if pp >= 2 || width == 2 {
					codes = append(codes, encodeX86EVEXVectorFloatCompare(pp, width, true, 3, 2, 1, 0, predicate))
				}
				for _, code := range codes {
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					command := exec.CommandContext(ctx, mc, "--disassemble", "--triple=i386-unknown-linux-gnu", "--mattr=+avx,+avx512f,+avx512vl")
					var hex strings.Builder
					for _, b := range code {
						fmt.Fprintf(&hex, "0x%02x ", b)
					}
					command.Stdin = strings.NewReader(hex.String())
					output, err := runtimeOracleCombinedOutput(ctx, command)
					cancel()
					if err != nil || strings.Contains(string(output), "warning:") || !strings.Contains(string(output), "vcmp") {
						t.Fatalf("physical i386 compare %x: %v\n%s", code, err, output)
					}
					name := fmt.Sprintf("raw_native%d", count)
					fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n", name)
					for _, b := range code {
						fmt.Fprintf(&source, "BYTE $%d\n", b)
					}
					source.WriteString("RET\n")
					count++
				}
			}
		}
	}
	goAssemblerOracleOutput(t, "386", source.String(), "", true)
	for _, triple := range []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		ir := x86FloatingCompareUnboundFormatObject(t, source.String(), "386", triple)
		compileLLVMToObject(t, llc, triple, "raw-native-compare.ll", "raw-native-compare.o", ir)
	}
	t.Logf("%d physical low-bank i386 forms independently decoded by LLVM22; 2 objects", count)
}

func TestX86FloatCompareNativePackedVirtualFPNeedsContext(t *testing.T) {
	for _, row := range []string{
		"CMPPS a+0(FP),X1,$0", "VCMPPD $3,a+0(FP),Y1,Y2", "VCMPPS.BCST $3,a+0(FP),Z1,K2",
		"CMPPS 16(SP),X1,$0", "CMPPD 16(BP),X1,$0", "VCMPPS $0,16(SP),Z1,K2", "VCMPPD $0,(AX)(BP*4),Y1,Y2",
	} {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-64\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{Goarch: "amd64", Sigs: map[string]FuncSig{"f": {Ret: Void}}})
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("%s fabricated native backing: %v", row, err)
		}
	}
}

func TestX86FloatCompareNativeScalarFPIndependentByteFields(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, opcode := range []string{"CMPSS", "CMPSD", "VCMPSS", "VCMPSD"} {
		width := 4
		if strings.HasSuffix(opcode, "SD") {
			width = 8
		}
		row := opcode + " a+0(FP),X1,$3"
		if strings.HasPrefix(opcode, "V") {
			row = opcode + " $3,a+0(FP),X1,K3,K2"
		}
		original := "TEXT f(SB),4,$0-8\n" + row + "\nRET\n"
		sig := FuncSig{Ret: Void}
		var names []string
		for index := 0; index < width; index++ {
			sig.Args = append(sig.Args, I8)
			sig.Frame.Params = append(sig.Frame.Params, FrameSlot{Offset: int64(index), Type: I8, Index: index, Field: -1})
			names = append(names, string(rune('a'+index)))
		}
		declaration := "func f(" + strings.Join(names, ",") + " uint8)"
		x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", original)
		prefix := "PXOR X1,X1\n"
		if strings.HasPrefix(opcode, "V") {
			prefix += "MOVL $1,AX\nKMOVW AX,K3\n"
		}
		source := strings.Replace(original, row+"\n", prefix+row+"\n", 1)
		x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
		for _, api := range []string{"text", "module", "Go"} {
			if ir, err := x86ScalarFPBitViewAPI(t, original, declaration, "amd64", "x86_64-unknown-linux-gnu", api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("original FP format invented its vector or mask input", opcode, api, err)
			}
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(ir, "elementtype(") || !strings.Contains(ir, "asm sideeffect") || strings.Count(ir, "load i8, ptr %fp_") != width {
				t.Fatalf("%s invented contiguous native FP backing or omitted field bytes:\n%s", row, ir)
			}
			compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "scalar-fp.ll", "scalar-fp.o", ir)
		}
		// Even an inactive EVEX mask cannot bless an invalid source span.
		sig.Frame.Params = sig.Frame.Params[:width-1]
		file, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{Goarch: "amd64", Sigs: map[string]FuncSig{"f": sig}}); err == nil {
			t.Fatalf("%s missing final FP byte accepted", row)
		}
	}
}

func TestX86FloatCompareNativeMixedISAUsesLowVEXConstraints(t *testing.T) {
	const source = "TEXT f(SB),4,$0-0\nCMPSS X0,X1,$3\nVCMPPS $3,Y0,Y1,Y2\nVCMPPS $3,Z0,Z1,K2\nRET\n"
	ir := x86FloatingCompareUnboundFormatObject(t, source, "amd64", "x86_64-unknown-linux-gnu")
	if !strings.Contains(ir, `"=x,0,x,`) || !strings.Contains(ir, `"=x,x,x,`) || !strings.Contains(ir, `"=r,v,v,`) {
		t.Fatalf("mixed EVEX function widened a legacy/VEX physical register class:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "mixed-isa.ll", "mixed-isa.o", ir)
}

func TestX86FloatCompareNativeValidatedPrivateFeatures(t *testing.T) {
	for _, tc := range []struct{ row, want string }{
		{"CMPPS X0,X1,$0", "+sse"},
		{"CMPSD X0,X1,$0", "+sse2"},
		{"VCMPPS $0,Y0,Y1,Y2", "+avx"},
		{"VCMPPS $0,X0,X1,K2", "+avx512f,+avx512vl"},
		{"VCMPSS $0,X0,X1,K2", "+avx512f"},
		{"VCMPPS $0,Z0,Z1,K2", "+avx512f"},
	} {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+tc.row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, "amd64", file.Funcs[0]); got != tc.want {
			t.Errorf("%s features=%q want=%q", tc.row, got, tc.want)
		}
	}
	for _, row := range []string{"VCMPPS $256,Z0,Z1,K2", "VCMPPS.Z $0,Z0,Z1,K2", "VCMPSS $0,X0,Y1,K2"} {
		file, err := Parse(ArchAMD64, fmt.Sprintf("TEXT f(SB),4,$0-0\n%s\nRET\n", row))
		if err != nil {
			t.Fatal(err)
		}
		if got := inferFuncTargetFeaturesForGOARCH(ArchAMD64, "amd64", file.Funcs[0]); got != "" {
			t.Errorf("malformed source gained ISA permission: %s/%s", row, got)
		}
	}
}
