package plan9asm

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	llvm "github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

func nativeAMD64OriginalObject(t *testing.T, goos, source string) string {
	t.Helper()
	return nativePhysicalOriginalObject(t, goos, "amd64", source)
}

func nativePhysicalOriginalObject(t *testing.T, goos, arch, source string) string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "physical.s")
	if err := os.WriteFile(file, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	listing, err := goasmcmd.Run(ctx, dir, append(os.Environ(),
		"GOROOT="+runtime.GOROOT(), "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off",
		"GOOS="+goos, "GOARCH="+arch), filepath.Join(runtime.GOROOT(), "bin/go"),
		"tool", "asm", "-S", "-p", "probe", "-I", filepath.Join(runtime.GOROOT(), "pkg/include"),
		"-o", filepath.Join(dir, "original.o"), file)
	if err != nil {
		t.Fatalf("original Go physical source rejected: %v\n%s\n%s", err, listing, source)
	}
	if info, err := os.Stat(filepath.Join(dir, "original.o")); err != nil || info.Size() == 0 {
		t.Fatal("missing original Go object", err)
	}
	return string(listing)
}

func nativePhysicalAssemblyObject(t *testing.T, assembly, arch string) {
	t.Helper()
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM22 clang is required")
	}
	dir := t.TempDir()
	input, output := filepath.Join(dir, "native.s"), filepath.Join(dir, "native.o")
	if err := os.WriteFile(input, []byte(assembly), 0o600); err != nil {
		t.Fatal(err)
	}
	triple := "x86_64-unknown-linux-gnu"
	if arch == "arm64" {
		triple = "aarch64-unknown-linux-gnu"
	}
	stage, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bytes, err := goasmcmd.Run(stage, dir, os.Environ(), clang, "-target", triple, "-c", input, "-o", output)
	if err != nil {
		t.Fatalf("physical assembly object: %v\n%s\n%s", err, bytes, assembly)
	}
	if info, err := os.Stat(output); err != nil || info.Size() == 0 {
		t.Fatal("missing native assembly object", err)
	}
}

func nativeAMD64PhysicalObjects(t *testing.T, source string, options NativeOptions) string {
	t.Helper()
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	mod, err := TranslateNativeModule(ctx, []byte(source), options)
	if err != nil {
		t.Fatal("complete physical source rejected", err)
	}
	defer mod.Dispose()
	if err := llvm.VerifyModule(mod, llvm.ReturnStatusAction); err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, level := range []string{"-O0", "-O2"} {
		x86PackedStringCompileObject(t, llc, mod.Target(), mod.String(), level)
	}
	return mod.String()
}

// The SysV runtime owner cannot execute on every host. Its complete original
// assembly and both LLVM object pipelines remain mandatory independently.
func TestNativeAMD64PhysicalABIFixtureObjects(t *testing.T) {
	source, _ := nativeAMD64PhysicalABIFixture()
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			nativeAMD64OriginalObject(t, goos, source)
			nativeAMD64PhysicalObjects(t, source, NativeOptions{GOOS: goos, GOARCH: "amd64", PackagePath: "probe"})
		})
	}
}

// Each row is an independently assemblable function. These are physical
// instructions, never synthetic Go arguments, initial values or call results.
func TestNativeAMD64TypedPhysicalFormatFamilies(t *testing.T) {
	rows := []struct{ name, body string }{
		{"call_register", "CALL AX\nCALL R10"},
		{"call_memory", "CALL (AX)\nCALL 8(R11)"},
		{"global_word", "MOVQ ·word(SB),DI\nMOVQ DI,·word(SB)"},
		{"global_address", "MOVQ $·word(SB),AX\nLEAQ ·word(SB),DX"},
		{"code_address", "MOVQ $physical<>(SB),DX"},
		{"xmm_qword", "MOVQ X0,X1\nMOVQ X1,AX\nMOVQ AX,X2\nMOVQ X2,8(SP)\nMOVQ 8(SP),X3"},
		{"xmm_dword", "MOVL X1,AX\nMOVL AX,X2\nMOVL X2,8(SP)\nMOVL 8(SP),X3"},
		{"scalar_double", "MOVSD X0,X1\nMOVSD X1,8(SP)\nMOVSD 8(SP),X2"},
		{"scalar_single", "MOVSS X0,X1\nMOVSS X1,8(SP)\nMOVSS 8(SP),X2"},
		{"byte_alias", "MOVB AH,BX\nMOVB AX,8(SP)\nMOVB 8(SP),R8\nMOVB AH,(R8)"},
		{"word", "MOVW $65535,AX\nMOVW AX,(DI)\nMOVW (DI),R9\nADDW $1,R9"},
		{"dword", "MOVL $0xffffffff,AX\nMOVL AX,(DI)\nMOVL (DI),R9\nADDL $1,R9"},
		{"qword", "MOVQ $0x123456789abcdef,AX\nMOVQ AX,(DI)\nMOVQ (DI),R9\nADDQ $1,R9"},
		{"arithmetic_bytes", "ADDB AX,BX\nSUBB $1,(DI)\nXORB R8,R9\nANDB $3,AX\nORB CX,DX"},
		{"compare_test", "CMPB AX,$1\nCMPW AX,BX\nCMPQ (DI),AX\nTESTB $3,AX\nTESTW AX,(DI)"},
		{"shift_count", "SHLB CX,AX\nSHLW CL,BX\nSARL CX,(DI)\nRORQ $255,AX\nSHLQ $1,DX,AX"},
		{"push_pop_qword", "PUSHQ AX\nPOPQ BX\nPUSHQ (DI)\nPOPQ (DI)\nPUSHQ $-1\nPOPQ AX"},
		{"push_pop_word", "PUSHW AX\nPOPW BX\nPUSHW (DI)\nPOPW (DI)"},
		{"push_pop_flags", "PUSHFQ\nPOPFQ\nPUSHFW\nPOPFW"},
		{"adjust_stack", "ADJSP $112\nADJSP $-112"},
		{"adjust_explicit_stack", "ADJSP $112,SP\nADJSP $-112,SP"},
		{"divide_byte", "DIVB BX\nIDIVB (DI)"},
		{"divide_word", "DIVW BX\nIDIVW (DI)"},
		{"divide_dword", "DIVL CX\nIDIVL 8(DI)"},
		{"divide_qword", "DIVQ R10\nIDIVQ (DI)"},
		{"indexed_memory", "MOVQ (AX)(CX*4),DX\nMOVSD 8(AX)(R8*2),X0\nMOVQ 8(CX*4),AX"},
		{"arithmetic_offset", "MOVQ 0+(1*8)(AX),DX\nMOVQ (4+4)(SP),AX"},
		{"absolute_memory", "MOVL 8,AX\nMOVW AX,16"},
		{"stack_segments", "PUSHQ FS\nPOPQ FS\nPUSHW GS\nPOPW GS"},
		{"stack_immediate", "PUSHQ $0xffffffff\nPOPQ AX\nPUSHW $65535\nPOPW AX"},
	}
	for _, goos := range []string{"linux", "darwin"} {
		for _, row := range rows {
			t.Run(goos+"/"+row.name, func(t *testing.T) {
				source := "#include \"textflag.h\"\nTEXT physical<>(SB),NOSPLIT|NOFRAME,$0-0\n" + row.body + "\nRET\n" +
					"GLOBL ·word(SB),NOPTR,$8\nDATA ·word(SB)/8,$7\n"
				nativeAMD64OriginalObject(t, goos, source)
				nativeAMD64PhysicalObjects(t, source, NativeOptions{GOOS: goos, GOARCH: "amd64", PackagePath: "probe"})
			})
		}
	}
}

func TestNativeAMD64PhysicalMaskMoveFamilyObjects(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT physical<>(SB),516,$0-0\n")
	for _, opcode := range []string{"KMOVB", "KMOVW", "KMOVD", "KMOVQ"} {
		for _, operands := range []string{"K1,K2", "K3,8(SP)(R13*4)", "8(SP)(R13*4),K4", "BP,K5", "K5,R14"} {
			fmt.Fprintf(&source, "%s %s\n", opcode, operands)
		}
		fmt.Fprintf(&source, "MOVQ SP,R10\n%s SP,K6\n%s K7,SP\nMOVQ R10,SP\n", opcode, opcode)
	}
	source.WriteString("RET\n")
	nativeAMD64RequirePhysicalObjectBytes(t, source.String())
}

func TestNativeAMD64OfficialPhysicalVectorGPObjects(t *testing.T) {
	const stackRegisters = "(?:SP|BP)"
	formats := []string{
		`KMOV[BWDQ]\s+(?:` + stackRegisters + `,\s*K[0-7]|K[0-7],\s*` + stackRegisters + `)`,
		`VPBROADCAST[BWDQ]\s+` + stackRegisters + `,\s*K[0-7],\s*[XYZ][0-9]+`,
		`VCVTT?S[SD]2U?SI[QL]?\s+[^,]+,\s*(?:SP|BP|R14)`,
		`VCVTUSI2S[SD][QL]\s+` + stackRegisters + `,\s*X[0-9]+,\s*X[0-9]+`,
	}
	match := regexp.MustCompile("^(?:" + strings.Join(formats, "|") + ")$")
	corpus := filepath.Join(runtime.GOROOT(), "src", "cmd", "asm", "internal", "asm", "testdata", "avx512enc")
	var source strings.Builder
	source.WriteString("TEXT physical<>(SB),516,$0-0\n")
	count := 0
	for _, file := range []string{"avx512bw.s", "avx512dq.s", "avx512f.s"} {
		data, err := os.ReadFile(filepath.Join(corpus, file))
		if err != nil {
			t.Fatal(err)
		}
		// Some EVEX rows list equivalent encodings. Compare the bytes the
		// selected Go SDK actually emits for each original spelling.
		for _, line := range strings.Split(string(data), "\n") {
			code, _, _ := strings.Cut(line, "//")
			instruction := strings.TrimSpace(code)
			if !match.MatchString(instruction) {
				continue
			}
			last := instruction[strings.LastIndexByte(instruction, ',')+1:]
			destination := strings.TrimSpace(last)
			if destination == "SP" || destination == "BP" {
				fmt.Fprintf(&source, "MOVQ %s,R10\n%s\nMOVQ R10,%s\n", destination, instruction, destination)
			} else {
				fmt.Fprintln(&source, instruction)
			}
			count++
		}
	}
	if count != 40 {
		t.Fatalf("found %d original physical vector/GP rows, want 40", count)
	}
	source.WriteString("RET\n")
	nativeAMD64RequirePhysicalObjectBytes(t, source.String())
}

func nativeAMD64RequirePhysicalObjectBytes(t *testing.T, source string) {
	t.Helper()
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			listing := nativeAMD64OriginalObject(t, goos, source)
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateNativeModule(ctx, []byte(source), NativeOptions{
				GOOS: goos, GOARCH: "amd64", PackagePath: "probe",
			})
			if err != nil {
				t.Fatal(err)
			}
			defer module.Dispose()
			if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
				t.Fatal(err)
			}
			nativeAMD64CompareFrameMachineCode(t, goos, listing, module.String())
		})
	}
}

func TestNativeAMD64PhysicalGPBroadcastFamily(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT physical<>(SB),516,$0-0\n")
	for _, opcode := range []string{"VPBROADCASTB", "VPBROADCASTW", "VPBROADCASTD", "VPBROADCASTQ"} {
		for _, register := range []string{"SP", "BP", "R13"} {
			for _, dest := range []string{"X23", "Y7", "Z11"} {
				fmt.Fprintf(&source, "%s %s,%s\n", opcode, register, dest)
				fmt.Fprintf(&source, "%s %s,K4,%s\n", opcode, register, dest)
				fmt.Fprintf(&source, "%s.Z %s,K7,%s\n", opcode, register, dest)
			}
		}
	}
	source.WriteString("RET\n")
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			input := source.String()
			options := NativeOptions{GOOS: goos, GOARCH: "amd64", PackagePath: "probe"}
			listing := nativeAMD64OriginalObject(t, goos, input)
			assembly, _, err := TranslateNativeSource([]byte(input), options)
			if err != nil {
				t.Fatal(err)
			}
			nativePhysicalAssemblyObject(t, assembly, "amd64")
			ir := nativeAMD64PhysicalObjects(t, input, options)
			nativeAMD64CompareFrameMachineCode(t, goos, listing, ir)
		})
	}
}

func TestNativeAMD64PhysicalScalarConversionFamilies(t *testing.T) {
	var floatToInteger, integerToFloat strings.Builder
	const frame = "TEXT physical<>(SB),516,$0-0\n"
	floatToInteger.WriteString(frame + "MOVQ SP,R11\n")
	integerToFloat.WriteString(frame)
	rounding := []string{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}
	for _, opcode := range x86ScalarFloatIntegerOracleNames() {
		for _, source := range []string{"X2", "(SP)", "16(BP)(R13*4)", "8"} {
			fmt.Fprintf(&floatToInteger, "%s %s,BP\n", opcode, source)
		}
		if strings.HasPrefix(opcode, "V") {
			fmt.Fprintf(&floatToInteger, "%s X28,SP\nMOVQ R11,SP\n", opcode)
			suffixes := rounding
			if strings.HasPrefix(opcode, "VCVTT") {
				suffixes = []string{".SAE"}
			}
			for _, suffix := range suffixes {
				fmt.Fprintf(&floatToInteger, "%s%s X17,R15\n", opcode, suffix)
			}
		}
	}
	for _, precision := range []string{"SS", "SD"} {
		for _, width := range []string{"L", "Q"} {
			for _, source := range []string{"SP", "BP", "16(SP)(R13*4)", "8"} {
				fmt.Fprintf(&integerToFloat, "CVTS%s2%s %s,X2\n", width, precision, source)
				fmt.Fprintf(&integerToFloat, "VCVTSI2%s%s %s,X0,X1\n", precision, width, source)
				fmt.Fprintf(&integerToFloat, "VCVTUSI2%s%s %s,X9,X3\n", precision, width, source)
			}
			for _, integer := range []string{"SI", "USI"} {
				opcode := "VCVT" + integer + "2" + precision + width
				fmt.Fprintf(&integerToFloat, "%s BP,X0,X29\n%s (SP),X25,X2\n", opcode, opcode)
				if precision == "SS" || width == "Q" {
					for _, suffix := range rounding {
						fmt.Fprintf(&integerToFloat, "%s%s R13,X7,X18\n", opcode, suffix)
					}
				}
			}
		}
	}
	for _, row := range []struct{ name, body string }{
		{"float_to_integer", floatToInteger.String()},
		{"integer_to_float", integerToFloat.String()},
	} {
		for _, goos := range []string{"linux", "darwin"} {
			t.Run(row.name+"/"+goos, func(t *testing.T) {
				source := row.body + "RET\n"
				listing := nativeAMD64OriginalObject(t, goos, source)
				options := NativeOptions{GOOS: goos, GOARCH: "amd64", PackagePath: "probe"}
				ir := nativeAMD64PhysicalObjects(t, source, options)
				nativeAMD64CompareFrameMachineCode(t, goos, listing, ir)
			})
		}
	}
}

func TestNativeAMD64PhysicalPackedMoveFamilies(t *testing.T) {
	const frame = "TEXT physical<>(SB),516,$0-0\n"
	var packed, streaming strings.Builder
	packed.WriteString(frame)
	streaming.WriteString(frame)
	for _, opcode := range []string{"MOVOU", "MOVOA", "MOVO", "MOVUPS", "MOVAPS", "MOVUPD", "MOVAPD"} {
		fmt.Fprintf(&packed, "%s X3,X4\n%s 16(SP)(BP*4),X8\n%s X8,(BP)\n", opcode, opcode, opcode)
	}
	for _, row := range []struct {
		opcode  string
		vexOnly bool
	}{
		{"VMOVDQA", true}, {"VMOVDQU", true},
		{"VMOVAPD", false}, {"VMOVAPS", false}, {"VMOVUPD", false}, {"VMOVUPS", false},
		{"VMOVDQA32", false}, {"VMOVDQA64", false},
		{"VMOVDQU8", false}, {"VMOVDQU16", false}, {"VMOVDQU32", false}, {"VMOVDQU64", false},
	} {
		for _, bank := range []string{"X", "Y", "Z"} {
			if row.vexOnly && bank == "Z" {
				continue
			}
			src, dst := bank+"3", bank+"9"
			fmt.Fprintf(&packed, "%s %s,%s\n", row.opcode, src, dst)
			fmt.Fprintf(&packed, "%s (SP),%s\n%s %s,17(SP)(BP*4)\n", row.opcode, dst, row.opcode, src)
			if row.vexOnly {
				continue
			}
			high := bank + "28"
			fmt.Fprintf(&packed, "%s %s,%s\n%s %s,K2,%s\n", row.opcode, src, high, row.opcode, high, dst)
			fmt.Fprintf(&packed, "%s.Z %s,K7,%s\n", row.opcode, src, dst)
			fmt.Fprintf(&packed, "%s 17(SP)(BP*1),K1,%s\n%s.Z 17(SP)(BP*8),K4,%s\n", row.opcode, high, row.opcode, high)
			fmt.Fprintf(&packed, "%s %s,K3,17(SP)(BP*2)\n", row.opcode, high)
		}
	}
	for _, row := range x86NonTemporalNativeOracle {
		registers := []string{"X3", "X9"}
		if row.vector {
			registers = append(registers, "X28", "Y4", "Y30", "Z6", "Z16")
		}
		for _, reg := range registers {
			if row.load {
				fmt.Fprintf(&streaming, "%s 17(SP)(BP*8),%s\n", row.name, reg)
			} else {
				fmt.Fprintf(&streaming, "%s %s,17(SP)(BP*4)\n", row.name, reg)
			}
		}
	}
	for _, row := range []struct{ name, source string }{
		{"packed", packed.String()}, {"streaming", streaming.String()},
	} {
		for _, goos := range []string{"linux", "darwin"} {
			t.Run(row.name+"/"+goos, func(t *testing.T) {
				source := row.source + "RET\n"
				listing := nativeAMD64OriginalObject(t, goos, source)
				options := NativeOptions{GOOS: goos, GOARCH: "amd64", PackagePath: "probe"}
				ir := nativeAMD64PhysicalObjects(t, source, options)
				nativeAMD64CompareFrameMachineCode(t, goos, listing, ir)
			})
		}
	}
}

func TestNativeAMD64ManagedFrameMatchesGoAssembler(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, row := range []struct {
			name, flags string
			frame       int
			call        bool
			entry, exit string
		}{
			{"leaf0", "NOSPLIT", 0, false, "", "c3"},
			{"noframe0", "NOSPLIT|NOFRAME", 0, false, "", "c3"},
			{"call0", "NOSPLIT", 0, true, "554889e5", "5dc3"},
			{"frame8", "NOSPLIT", 8, false, "554889e54883ec08", "4883c4085dc3"},
			{"frame16", "NOSPLIT", 16, true, "554889e54883ec10", "4883c4105dc3"},
			{"frame224", "NOSPLIT", 224, true, "554889e54881ece0000000", "4881c4e00000005dc3"},
			{"noframe224", "NOSPLIT|NOFRAME", 224, true, "4881ece0000000", "4881c4e0000000c3"},
		} {
			t.Run(goos+"/"+row.name, func(t *testing.T) {
				body := "MOVQ AX,DX\n"
				if row.call {
					body += "CALL imported(SB)\n"
				}
				source := fmt.Sprintf("#include \"textflag.h\"\nTEXT physical<>(SB),%s,$%d-0\n%sRET\n", row.flags, row.frame, body)
				listing := nativeAMD64OriginalObject(t, goos, source)
				wantBP := !strings.Contains(row.flags, "NOFRAME") && (row.frame != 0 || row.call)
				modernGo := strings.Contains(listing, "PUSHQ\tBP") == wantBP
				if !modernGo {
					if row.frame != 0 {
						// The older producer reserves locals+BP together. Its
						// saved slot and final SP/BP match, but not entry FLAGS.
						for _, part := range []string{fmt.Sprintf("SUBQ\t$%d, SP", row.frame+8),
							fmt.Sprintf("MOVQ\tBP, %d(SP)", row.frame), fmt.Sprintf("LEAQ\t%d(SP), BP", row.frame),
							fmt.Sprintf("MOVQ\t%d(SP), BP", row.frame), fmt.Sprintf("ADDQ\t$%d, SP", row.frame+8)} {
							if !strings.Contains(listing, part) {
								t.Fatal("unknown historical Go frame shape", part, listing)
							}
						}
					} else if !row.call || strings.Contains(listing, "\tSUBQ\t") || strings.Contains(listing, "\tMOVQ\tBP,") {
						t.Fatal("unknown historical zero-local nonleaf frame", listing)
					}
					t.Log("historical Go object retained; current frame contract is independently checked, not byte/FLAGS equivalence", listing)
				}
				opts := NativeOptions{GOOS: goos, GOARCH: "amd64", PackagePath: "probe", Imports: map[string]string{"imported": "callee"}}
				assembly, _, err := TranslateNativeSource([]byte(source), opts)
				if err != nil {
					t.Fatal("actual Go managed frame rejected", err)
				}
				if strings.Contains(assembly, "pushq %rbp") != wantBP || strings.Contains(assembly, "popq %rbp") != wantBP {
					t.Fatal("native frame differs from original Go", assembly, listing)
				}
				if row.frame > 0 {
					for _, part := range []string{fmt.Sprintf("subq $%d, %%rsp", row.frame), fmt.Sprintf("addq $%d, %%rsp", row.frame)} {
						if !strings.Contains(assembly, part) {
							t.Fatal("native frame lost its exact Go local extent", part, assembly)
						}
					}
				}
				ir := nativeAMD64PhysicalObjects(t, source, opts)
				if modernGo {
					nativeAMD64CompareFrameMachineCode(t, goos, listing, ir)
				}
				// Literal machine-byte oracles preserve the selected current
				// frame contract even when the host Go uses an older epoch.
				machine := row.entry + "4889c2"
				if row.call {
					machine += "e800000000"
				}
				want, err := hex.DecodeString(machine + row.exit)
				if err != nil {
					t.Fatal(err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					code := nativeAMD64ObjectCode(t, goos, ir, level)
					if len(code) < len(want) {
						t.Fatalf("short current frame: %x", code)
					}
					code = append([]byte(nil), code[:len(want)]...)
					if row.call {
						pc := len(row.entry)/2 + 3
						for i := pc + 1; i < pc+5; i++ {
							code[i] = 0
						}
					}
					if !bytes.Equal(code, want) {
						t.Fatalf("%s current frame contract differs: got %x want %x", level, code, want)
					}
				}
			})
		}
	}
}

// The original assembler's instruction bytes are an independent oracle for
// every SP/BP change, including the extra saved BP for a zero-local nonleaf.
// Only the external CALL displacement is relocation-owned and normalized.
func nativeAMD64CompareFrameMachineCode(t *testing.T, goos, listing, ir string) {
	t.Helper()
	var want []byte
	for _, row := range regexp.MustCompile(`(?m)^\s*0x[[:xdigit:]]+\s+((?:[[:xdigit:]]{2} )+)`).FindAllStringSubmatch(listing, -1) {
		part, err := hex.DecodeString(strings.ReplaceAll(row[1], " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, part...)
	}
	lastRET := bytes.LastIndexByte(want, 0xc3)
	if lastRET < 0 {
		t.Fatal("original Go frame has no RET", listing)
	}
	want = want[:lastRET+1]
	for _, level := range []string{"-O0", "-O2"} {
		got := nativeAMD64ObjectCode(t, goos, ir, level)
		if len(got) < len(want) {
			t.Fatalf("short native frame: got %x original %x", got, want)
		}
		got = append([]byte(nil), got[:len(want)]...)
		expected := append([]byte(nil), want...)
		for _, row := range regexp.MustCompile(`(?m)^\s*0x([[:xdigit:]]+)\s+[0-9]+[^\n]*\tCALL\t`).FindAllStringSubmatch(listing, -1) {
			position, err := strconv.ParseUint(row[1], 16, 32)
			if err != nil {
				t.Fatal(err)
			}
			pc := int(position)
			if pc+5 > len(expected) || expected[pc] != 0xe8 || got[pc] != 0xe8 {
				t.Fatal("original/native CALL boundary differs", listing)
			}
			for i := pc + 1; i < pc+5; i++ {
				got[i], expected[i] = 0, 0
			}
		}
		if !bytes.Equal(got, expected) {
			t.Fatalf("%s physical frame differs: native %x original Go %x\n%s", level, got, expected, listing)
		}
	}
}

func TestNativeAMD64TypedPhysicalRejectsUnprovedForms(t *testing.T) {
	for _, body := range []string{
		"CALL $1", "CALL unknown(SB)", "CALL X0", "MOVQ X16,X0", "MOVSD AX,X0", "MOVQ (AX),(BX)",
		"MOVQ $1,X0", "DIVL $1", "PUSHQ X0", "POPQ $1", "ADJSP AX", "ADJSP $8,AX",
		"MOVQ value+0(FP),AX", "MOVQ unknown(SB),AX", "MOVQ $unknown(SB),AX", "MOVQ AX,8(FS)",
		"MOVQ 1(R8)(SP*2),AX", "ADDQ.Z AX,BX",
		"VPBROADCASTD.Z SP,Y2", "VPBROADCASTW SP,K0,X0", "VPBROADCASTQ AH,Z0",
		"VPBROADCASTB SP,K8,X23", "VPBROADCASTD SP,16(BP)",
		"CVTSS2SL X16,SP", "VCVTTSS2SI.RN_SAE X2,SP", "VCVTSS2SI.SAE X2,BP",
		"VCVTSS2USIL.RZ_SAE (SP),BP", "VCVTSI2SDL.RD_SAE SP,X2,X3",
		"VCVTUSI2SSQ $1,X2,X3", "VCVTUSI2SSL value+0(FP),X2,X3",
		"MOVAPS X16,X3", "MOVOU (BP),(SP)", "VMOVDQA Z0,Z1",
		"VMOVUPS X0,K0,X1", "VMOVAPD.Z X4,X6", "VMOVDQU32 X0,Y1",
		"VMOVNTDQ X0,K1,(SP)", "VMOVNTDQA X0,(SP)", "VMOVNTPS (SP),X2",
	} {
		t.Run(body, func(t *testing.T) {
			source := "#include \"textflag.h\"\nTEXT physical<>(SB),NOSPLIT|NOFRAME,$0-0\n" + body + "\nRET\n"
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			mod, err := TranslateNativeModule(ctx, []byte(source), NativeOptions{GOOS: "linux", GOARCH: "amd64", PackagePath: "probe"})
			if err == nil {
				mod.Dispose()
				t.Fatal("unproved physical form acquired a native carrier")
			}
			if !mod.IsNil() {
				t.Fatal("rejected source returned an owned partial module")
			}
		})
	}
}

func nativeAMD64ObjectCode(t *testing.T, goos, ir, level string) []byte {
	t.Helper()
	dir := t.TempDir()
	input, output := filepath.Join(dir, "frame.ll"), filepath.Join(dir, "frame.o")
	if err := os.WriteFile(input, []byte(ir), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	_, err := goasmcmd.Run(ctx, dir, os.Environ(), findLLVM22Tool("llc"), level, "-filetype=obj", input, "-o", output)
	cancel()
	if err != nil {
		t.Fatal("LLVM frame object", err)
	}
	var got []byte
	if goos == "linux" {
		object, err := elf.Open(output)
		if err != nil {
			t.Fatal(err)
		}
		got, err = object.Section(".text").Data()
		object.Close()
		if err != nil {
			t.Fatal(err)
		}
	} else {
		object, err := macho.Open(output)
		if err != nil {
			t.Fatal(err)
		}
		got, err = object.Section("__text").Data()
		object.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	return got
}
