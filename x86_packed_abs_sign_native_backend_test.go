package plan9asm

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// This bounded contract observes the original runtime's actual LLVM object,
// not the stock-Go KMOVQ spelling. The Intel SDM PABS/PSIGN tables distinguish
// SSSE3, VEX AVX/AVX2, and EVEX F/VL from the independent BW/DQ families.
func x86PackedAbsSignRuntimeOpcodeWithinProfile(op string, code []byte) bool {
	if len(code) == 0 {
		return false
	}
	if code[0] == 0x62 {
		if strings.HasPrefix(op, "vfm") || strings.HasPrefix(op, "vfnm") {
			return false
		}
		if x86OriginalFloatingEVEXWithinProfile("fma-caller", op, code) {
			return true
		}
		if len(code) < 6 || code[3]>>5&3 == 3 {
			return false
		}
		// SDM Table 5-19 names all eight VPCMP predicates. Objdump may
		// print the pseudo-op instead of the identical D/Q instruction plus
		// its immediate. Byte/word aliases still require independent BW.
		for _, suffix := range []string{"d", "q", "ud", "uq"} {
			for _, predicate := range []string{"eq", "lt", "le", "false", "neq", "nlt", "nle", "true"} {
				if op == "vpcmp"+predicate+suffix {
					op = "vpcmp" + suffix
				}
			}
		}
		for _, member := range strings.Fields(`
vpabsd vpabsq vpaddd vpaddq vpsubd vpsubq
vpmovsxbd vpmovsxbq vpmovsxwd vpmovsxwq vpmovsxdq
vpmovzxbd vpmovzxbq vpmovzxwd vpmovzxwq vpmovzxdq
vpcmpd vpcmpq vpcmpud vpcmpuq vpcmpeqd vpcmpeqq vpcmpgtd vpcmpgtq
vpblendmd vpblendmq vpbroadcastd vpbroadcastq vptestmd vptestmq vptestnmd vptestnmq`) {
			if op == member {
				return true
			}
		}
		return false
	}
	if strings.HasPrefix(op, "k") {
		return x86OriginalFloatingFMaskOpcode(op)
	}
	if code[0] == 0xc4 || code[0] == 0xc5 {
		for _, member := range strings.Fields(`
vzeroupper vmovaps vmovapd vmovups vmovupd vmovdqa vmovdqu vmovd vmovq vmovss vmovsd
vpxor vpand vpandn vpor vxorps vxorpd vandps vandpd vandnps vandnpd vorps vorpd
vpabsb vpabsw vpabsd vpsignb vpsignw vpsignd
vpaddb vpaddw vpaddd vpaddq vpsubb vpsubw vpsubd vpsubq
vpcmpeqb vpcmpeqw vpcmpeqd vpcmpeqq vpcmpgtb vpcmpgtw vpcmpgtd vpcmpgtq
vpblendvb vpblendw vpblendd vblendps vblendpd vblendvps vblendvpd
vpshufb vpshufd vpshufhw vpshuflw vshufps vshufpd vpermq vpermd vperm2i128 vperm2f128
vpsllw vpslld vpsllq vpsrlw vpsrld vpsrlq vpsraw vpsrad vpslldq vpsrldq
vpsllvd vpsllvq vpsrlvd vpsrlvq vpsravd
vpbroadcastb vpbroadcastw vpbroadcastd vpbroadcastq vbroadcastss vbroadcastsd
vextracti128 vextractf128 vinserti128 vinsertf128
vpextrb vpextrw vpextrd vpextrq vpinsrb vpinsrw vpinsrd vpinsrq
vpunpcklbw vpunpcklwd vpunpckldq vpunpcklqdq vpunpckhbw vpunpckhwd vpunpckhdq vpunpckhqdq
vpmovmskb vpmovzxbw vpmovzxbd vpmovzxbq vpmovzxwd vpmovzxwq vpmovzxdq
vpmovsxbw vpmovsxbd vpmovsxbq vpmovsxwd vpmovsxwq vpmovsxdq
vpacksswb vpackssdw vpackuswb vpackusdw vptest`) {
			if op == member {
				return true
			}
		}
		return false
	}
	return !strings.HasPrefix(op, "v")
}

func TestX86PackedAbsSignRuntimeISAProfileAliases(t *testing.T) {
	// These are profile field projections, not valid-encoding certificates.
	// The complete actual three-target object matrix below independently
	// observes both full bytes and each mnemonic through LLVM22 objdump.
	evex := []byte{0x62, 0xf3, 0x75, 0x28, 0x1f, 0xc2, 1}
	for _, suffix := range []string{"d", "q", "ud", "uq", "b", "w", "ub", "uw"} {
		for _, predicate := range []string{"eq", "lt", "le", "false", "neq", "nlt", "nle", "true"} {
			op := "vpcmp" + predicate + suffix
			t.Run(op, func(t *testing.T) {
				want := suffix == "d" || suffix == "q" || suffix == "ud" || suffix == "uq"
				if x86PackedAbsSignRuntimeOpcodeWithinProfile(op, evex) != want {
					t.Fatal("VPCMP predicate alias changed its D/Q F/VL versus byte/word BW requirement", op)
				}
			})
		}
	}
	for _, op := range []string{"vpextrb", "vpextrw", "vpextrd", "vpextrq", "vpinsrb", "vpinsrw", "vpinsrd", "vpinsrq"} {
		t.Run(op, func(t *testing.T) {
			if !x86PackedAbsSignRuntimeOpcodeWithinProfile(op, []byte{0xc4, 0xe3, 0x79, 0x16, 0xc8, 1}) ||
				x86PackedAbsSignRuntimeOpcodeWithinProfile(op, evex) {
				t.Fatal("VEX GP lane transport borrowed its separate EVEX BW/DQ encoding", op)
			}
		})
	}
}

func TestX86PackedAbsSignRuntimeISAExtensionFamily(t *testing.T) {
	// LLVM 22's avx512_pmovx_{bd,bq,wd,wq,dq} use F, plus VL for
	// X/Y destinations. Only bw needs BW; the input element width alone
	// does not imply that feature. Keep signed and unsigned extensions.
	// https://github.com/llvm/llvm-project/blob/llvmorg-22.1.8/llvm/lib/Target/X86/X86InstrAVX512.td
	type witness struct {
		source, opcode string
		withinProfile  bool
	}
	var cases []witness
	var source strings.Builder
	for _, sign := range []string{"S", "Z"} {
		for _, ratio := range []string{"BW", "BD", "BQ", "WD", "WQ", "DQ"} {
			op := "VPMOV" + sign + "X" + ratio
			for _, bank := range []string{"X", "Y", "Z"} {
				input := "X0"
				if bank == "Z" && (ratio == "BW" || ratio == "WD" || ratio == "DQ") {
					input = "Y0"
				}
				for _, operand := range []string{input, "8(AX)"} {
					for _, mask := range []string{"", "merge", "zero"} {
						name, args := op, operand
						if mask != "" {
							args += ",K3"
						}
						if mask == "zero" {
							name += ".Z"
						}
						// High destinations select actual EVEX even without a mask.
						row := name + " " + args + "," + bank + "16"
						cases = append(cases, witness{row, strings.ToLower(op), ratio != "BW"})
						fmt.Fprintln(&source, row)
					}
				}
			}
		}
	}
	if len(cases) != 216 {
		t.Fatal("extension family inventory changed", len(cases))
	}
	source.WriteString("RET\n")
	code, pcs := x86NumericalBoundaryGoBytes(t, "amd64", source.String())
	if len(pcs) != len(cases)+1 || code[pcs[len(cases)]] != 0xc3 {
		t.Fatal("original Go object lost its complete extension inventory")
	}
	x86NumericalNativeRequireMC(t, code, 64, len(pcs), "+avx512f,+avx512vl,+avx512bw")
	for index, row := range cases {
		t.Run(row.source, func(t *testing.T) {
			encoded := code[pcs[index]:pcs[index+1]]
			if len(encoded) < 6 || encoded[0] != 0x62 {
				t.Fatal("original source did not select complete EVEX", encoded)
			}
			if got := x86PackedAbsSignRuntimeOpcodeWithinProfile(row.opcode, encoded); got != row.withinProfile {
				t.Fatalf("actual extension changed its F/VL versus BW requirement: %x: got %t", encoded, got)
			}
		})
	}
}

func TestX86PackedAbsSignOriginalRuntimeActualBackendISA(t *testing.T) {
	source := x86PackedAbsSignOriginalRuntimeSource(t)
	llc, objdump := findLLVM22Tool("llc"), findLLVM22Tool("llvm-objdump")
	if llc == "" || objdump == "" {
		t.Fatal("actual original ABS/sign ISA requires LLVM22 llc and llvm-objdump")
	}
	for _, op := range []string{"kmovb", "kmovq", "vpmovm2q", "vpmullq", "vpabsb", "vpabsw", "vmovdqu8", "vmovdqu16", "vpsllw", "vfmadd132ps", "vfmadd132ph"} {
		if x86PackedAbsSignRuntimeOpcodeWithinProfile(op, []byte{0x62, 0xf1, 0x7c, 0x48, 0x10, 0xc0}) {
			t.Fatal("original ABS/sign borrowed an independent BW, DQ, FMA or FP16 opcode", op)
		}
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, "#include \"textflag.h\"\n"+source)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			frame := FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: Ptr, Index: 3, Field: -1},
				{Offset: 32, Type: I64, Index: 4, Field: -1},
			}}
			ir, err := Translate(file, Options{TargetTriple: triple, Goarch: "amd64", Sigs: map[string]FuncSig{
				"packedabssign": {Name: "packedabssign", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void, Frame: frame},
			}})
			if err != nil || ir == "" {
				t.Fatal("complete original initialized ABS/sign source rejected before ISA observation", err)
			}
			for _, pipeline := range []struct{ name, level, ir string }{
				{"O0", "-O0", ir}, {"O2", "-O2", ir}, {"IR_O2_backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					listing := x86FourSourceNativeObjectListing(t, llc, objdump, triple, pipeline.level, pipeline.ir)
					rows := regexp.MustCompile(`(?m)^\s*[0-9a-f]+:\s+((?:[0-9a-f]{2}\s+)+)([a-z][a-z0-9.]*)`).FindAllStringSubmatch(listing, -1)
					if len(rows) == 0 || strings.Contains(listing, "<unknown>") || strings.Contains(listing, "invalid") ||
						len(regexp.MustCompile(`(?m)^[0-9a-f]+ <_?packedabssign>:`).FindAllString(listing, -1)) != 1 ||
						len(regexp.MustCompile(`\bpsignw\s+[^\n,]*\(`).FindAllString(listing, -1)) != 1 {
						t.Fatal("original object lost its owned complete function or native Type4 PSIGNW memory operation", listing)
					}
					seen, violations := make(map[string]bool), []string{}
					for _, row := range rows {
						seen[row[2]] = true
						code, err := hex.DecodeString(strings.Join(strings.Fields(row[1]), ""))
						if err != nil || !x86PackedAbsSignRuntimeOpcodeWithinProfile(row[2], code) {
							violations = append(violations, row[0])
						}
					}
					var inventory []string
					for op := range seen {
						inventory = append(inventory, op)
					}
					sort.Strings(inventory)
					t.Logf("actual %s %s original ABS/sign opcodes: %s; objects are not CPU execution", triple, pipeline.name, strings.Join(inventory, ","))
					if len(violations) != 0 {
						t.Fatalf("actual ABS/sign object exceeds SSSE3/AVX2/F/VL (no BW/DQ/FMA):\n%s", strings.Join(violations, "\n"))
					}
				})
			}
		})
	}
}
