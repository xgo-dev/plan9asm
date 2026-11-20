package plan9asm

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func x86LegacyFloatMemoryOpcodes() []string {
	return []string{"ADDPS", "ADDPD", "SUBPS", "SUBPD", "MULPS", "MULPD", "DIVPS", "DIVPD"}
}

func TestX86LegacyPackedFloatingMemoryActualGoOpcodeBytes(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for i, opcode := range x86LegacyFloatMemoryOpcodes() {
			listing := x86InsertExtractGoListing(t, arch, "TEXT f(SB),4,$0-0\n"+opcode+" (AX),X1\nRET\n")
			var actual []byte
			for _, line := range strings.Split(string(listing), "\n") {
				actual = append(actual, x86InsertExtractListedBytes(line)...)
			}
			want := []byte{0x0f, []byte{0x58, 0x5c, 0x59, 0x5e}[i/2], 0x08, 0xc3}
			if i%2 != 0 {
				want = append([]byte{0x66}, want...)
			}
			if !bytes.Equal(actual, want) {
				t.Fatalf("%s/%s actual Go bytes=%x independent SSE=%x", arch, opcode, actual, want)
			}
		}
	}
}

func TestX86LegacyPackedFloatingMemoryRetainsOriginalOpcode(t *testing.T) {
	for _, opcode := range x86LegacyFloatMemoryOpcodes() {
		for _, arch := range []string{"386", "amd64"} {
			for _, source := range []string{"(AX)", "16(AX)(BX*2)", "data(SB)", "(FS)", "(GS)"} {
				t.Run(opcode+"/"+arch+"/"+source, func(t *testing.T) {
					assembly := "TEXT f(SB),4,$0-0\n" + opcode + " " + source + ",X1\nRET\n"
					requireX86GoAssemblerResult(t, arch, assembly, true)
					file, err := Parse(ArchAMD64, assembly)
					if err != nil {
						t.Fatal(err)
					}
					ir, err := Translate(file, Options{Goarch: arch, TargetTriple: testTargetTriple("linux", arch),
						Sigs: map[string]FuncSig{"f": {Name: "f", Ret: Void}}})
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(ir, "asm sideeffect \""+strings.ToLower(opcode)+" ") || strings.Contains(ir, "movdqa") {
						t.Fatal("native m128 source lost its exact original observable opcode")
					}
				})
			}
		}
	}
}

func TestX86LegacyPackedFloatingMemoryFiveTargetsKeepNativeOpcodes(t *testing.T) {
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("LLVM22 llc and llvm-objdump required")
	}
	for _, triple := range []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "i386-unknown-linux-gnu", "i686-pc-windows-msvc"} {
		arch := "amd64"
		if strings.HasPrefix(triple, "i") {
			arch = "386"
		}
		var source strings.Builder
		sigs := map[string]FuncSig{}
		for i, opcode := range x86LegacyFloatMemoryOpcodes() {
			for j, operand := range []string{"(AX)", "16(AX)(BX*2)", "data(SB)", "(FS)", "(GS)"} {
				name := fmt.Sprintf("memory_%d_%d", i, j)
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%s %s,X1\nRET\n", name, opcode, operand)
				sigs[name] = FuncSig{Name: name, Ret: Void}
			}
		}
		goAssemblerOracleOutput(t, arch, source.String(), "", true)
		file, err := Parse(ArchAMD64, source.String())
		if err != nil {
			t.Fatal(err)
		}
		for _, optimized := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/O2=%t", triple, optimized), func(t *testing.T) {
				ir, err := Translate(file, Options{Goarch: arch, TargetTriple: triple, Sigs: sigs})
				if err != nil {
					t.Fatal(err)
				}
				if optimized {
					ir = x86MulDivRoundOptimize(t, ir)
				}
				dir := t.TempDir()
				input, object := filepath.Join(dir, "memory.ll"), filepath.Join(dir, "memory.o")
				if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
					t.Fatal(err)
				}
				level := "-O0"
				if optimized {
					level = "-O2"
				}
				ctx, cancel := runtimeOracleStageContext(t)
				output, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, llc, level, "-mtriple="+triple, "-filetype=obj", input, "-o", object))
				cancel()
				if err != nil {
					t.Fatalf("native memory object: %v\n%s", err, output)
				}
				ctx, cancel = runtimeOracleStageContext(t)
				output, err = runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, objdump, "-d", object))
				cancel()
				if err != nil {
					t.Fatalf("native memory disassembly: %v\n%s", err, output)
				}
				for _, opcode := range x86LegacyFloatMemoryOpcodes() {
					pattern := regexp.MustCompile(`(?m)\b` + strings.ToLower(opcode) + `\s+[^\n]*\([^\n]*\),\s*%xmm`)
					if count := len(pattern.FindAll(output, -1)); count != 5 {
						t.Fatalf("%s count=%d, original memory opcode lost:\n%s", opcode, count, output)
					}
				}
				if !strings.Contains(string(output), "%fs:") || !strings.Contains(string(output), "%gs:") {
					t.Fatal("native FS/GS source prefixes lost")
				}
			})
		}
	}
}

func TestX86LegacyPackedFloatingMemoryCallerPermissionsAndNativeWidth(t *testing.T) {
	for _, opcode := range x86LegacyFloatMemoryOpcodes() {
		for _, operand := range []string{"(DI)", "16(DI)", "(BX)", "(SP)", "a+0(FP)", "(R14)", "(CX)"} {
			body := fmt.Sprintf("VMOVUPS (SI),Z1\n%s %s,X1\nVMOVSS X1,(DX)", opcode, operand)
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu")
			want := operand == "(DI)" || operand == "16(DI)"
			if want && err != nil || !want && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("%s/%s actual source permission=%v want admitted=%t", opcode, operand, err, want)
			}
		}
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+opcode+" (DI),X1\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		for _, extent := range []int64{15, 16} {
			ins := file.Funcs[0].Instrs[1]
			proof := &x86GoCallerRegionProof{arguments: []x86CallerArgumentRegion{{kind: x86CallerFreshResult, width: extent}}}
			state := x86SourceStackState{callers: map[Reg]x86CallerPointerValue{DI: {argument: 0}}, vectors: map[Reg]uint64{"Z1": ^uint64(0)}}
			accepted := x86CallerVectorMoveStep(&ins, &state, proof)
			if accepted != (extent == 16) {
				t.Fatalf("%s certified a partial m128 source extent=%d accepted=%t", opcode, extent, accepted)
			}
		}
	}
}

func TestX86LegacyPackedFloatingMemoryIdentityAndMalformedBeforeEmission(t *testing.T) {
	for _, opcode := range x86LegacyFloatMemoryOpcodes() {
		valid, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+opcode+" (AX),X1\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		for _, sourceOp := range []Op{"", Op(opcode), Op(strings.ToLower(opcode)), "UNKNOWN", "ADDPS.Z", "DIVPS"} {
			ins := valid.Funcs[0].Instrs[1]
			ins.Op = sourceOp
			ctx, output := newAMD64CtxWithFuncForTest(t, valid.Funcs[0], FuncSig{Ret: Void}, nil)
			before := output.Len()
			var known, term bool
			if strings.HasPrefix(opcode, "ADD") || strings.HasPrefix(opcode, "SUB") {
				known, term, err = ctx.lowerFloatAddSub(Op(opcode), ins)
			} else {
				known, term, err = ctx.lowerFloatMulDiv(Op(opcode), ins)
			}
			conflict := sourceOp != "" && !strings.EqualFold(string(sourceOp), opcode)
			if !known || term || (err != nil) != conflict || conflict && output.Len() != before || ins.Op != sourceOp {
				t.Fatalf("%s/%s changed identity or emitted before rejection: %t/%t/%v", opcode, sourceOp, known, term, err)
			}
		}
		for _, row := range []string{opcode + " (AX),Y1", opcode + " (AX),X16", opcode + ".Z (AX),X1", opcode + " $data(SB),X1", opcode + " (AX),X1,X2"} {
			goAssemblerOracleOutput(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n", "", false)
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				continue
			}
			ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
			before := output.Len()
			ins := file.Funcs[0].Instrs[1]
			var known bool
			var term bool
			if strings.HasPrefix(opcode, "ADD") || strings.HasPrefix(opcode, "SUB") {
				known, term, err = ctx.lowerFloatAddSub(ins.Op, ins)
			} else {
				known, term, err = ctx.lowerFloatMulDiv(ins.Op, ins)
			}
			if !known || term || err == nil || before != output.Len() {
				t.Fatalf("malformed %s emitted native IR: %t/%t/%v", row, known, term, err)
			}
		}
	}
}

func TestX86LegacyPackedFloatingMemoryMode32FeaturesAreFormBound(t *testing.T) {
	for _, opcode := range x86LegacyFloatMemoryOpcodes() {
		for _, row := range []string{opcode + " (AX),X1", opcode + " (AX),X8", opcode + ".Z (AX),X1", opcode + " value+0(FP),X1"} {
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			bits := x86LegacyPackedFloatingNativeMemoryBits(file.Funcs[0].Instrs[1], "386")
			want := 0
			if row == opcode+" (AX),X1" {
				want = 32
				if strings.HasSuffix(opcode, "PD") {
					want = 64
				}
			}
			if bits != want {
				t.Fatalf("unvalidated source form acquired SSE transport: %s %d/%d", row, bits, want)
			}
		}
	}
}

func TestX86LegacyPackedFloatingMemoryVirtualFPIsNotNativeStorage(t *testing.T) {
	for _, opcode := range x86LegacyFloatMemoryOpcodes() {
		assembly := fmt.Sprintf("TEXT f(SB),4,$0-16\n%s source+0(FP),X1\nRET\n", opcode)
		file, err := Parse(ArchAMD64, assembly)
		if err != nil {
			t.Fatal(err)
		}
		sig := FuncSig{Name: "f", Args: []LLVMType{I64, I64}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: I64, Index: 0, Field: -1}, {Offset: 8, Type: I64, Index: 1, Field: -1},
		}}}
		_, err = Translate(file, Options{Goarch: "amd64", Sigs: map[string]FuncSig{"f": sig}})
		if err == nil || !strings.Contains(err.Error(), "contiguous original FP") {
			t.Fatalf("%s invented native m128 alignment/backing from independent virtual fields: %v", opcode, err)
		}
	}
}
