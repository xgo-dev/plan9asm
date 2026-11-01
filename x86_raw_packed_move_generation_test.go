package plan9asm

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

type x86PackedMovePhysicalCase struct {
	name, bank, role string
	evex, aligned    bool
	code             []byte
}

// Independent literal bytes from Go 1.27's complete _yvmovapd rows and
// AVMOVAPS/APD/UPS/UPD opcode entries. Named low-bank unmasked X/Y sources
// select VEX, so they alone cannot witness the equally valid EVEX encodings.
func x86PackedMovePhysicalCases() []x86PackedMovePhysicalCase {
	var rows []x86PackedMovePhysicalCase
	for _, name := range []string{"VMOVAPS", "VMOVAPD", "VMOVUPS", "VMOVUPD"} {
		aligned, pp, opcode := strings.HasPrefix(name, "VMOVA"), byte(0), byte(0x10)
		if aligned {
			opcode = 0x28
		}
		if strings.HasSuffix(name, "PD") {
			pp = 1
		}
		for _, evex := range []bool{false, true} {
			for length, bank := range []string{"X", "Y", "Z"} {
				if !evex && length == 2 {
					continue
				}
				for _, role := range []string{"load", "store", "register-load", "register-store"} {
					operation, modrm := opcode, byte(0x16) // (SI) and vector2.
					if strings.HasSuffix(role, "store") {
						operation++
					}
					if strings.HasPrefix(role, "register") {
						modrm = 0xd1 // vector1 and vector2; retain both opcode directions.
					}
					code := []byte{0xc4, 0xe1, 0x78 | pp | byte(length)<<2, operation, modrm}
					if evex {
						p1 := byte(0x7c) | pp
						if pp == 1 {
							p1 |= 0x80
						}
						code = []byte{0x62, 0xf1, p1, 0x08 | byte(length)<<5, operation, modrm}
					}
					rows = append(rows, x86PackedMovePhysicalCase{name, bank, role, evex, aligned, code})
				}
			}
		}
	}
	return rows
}

func TestX86RawPackedMovePhysicalGenerationAndRequiredFeatures(t *testing.T) {
	rows := x86PackedMovePhysicalCases()
	if len(rows) != 80 {
		t.Fatal("complete low-bank VEX/EVEX physical directory changed", len(rows))
	}
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range rows {
			t.Run(fmt.Sprintf("%s/%s/%s/%s/EVEX%t", arch, row.name, row.bank, row.role, row.evex), func(t *testing.T) {
				ins := x86RawMoveObservedInstruction(t, arch, row.code)
				form, known, err := amd64PackedVectorMoveProperties(ins, arch)
				if !known || err != nil || ins.Op != Op(row.name) || !x86RawVectorMoveSource(ins, arch) {
					t.Fatal("valid original physical move lost its exact existing typed family", ins.Raw, err)
				}
				if form.nativeEVEX(ins) != row.evex {
					t.Error("original low-bank physical generation was inferred from operands instead of retained from bytes")
				}
				if !row.aligned || strings.HasPrefix(row.role, "register") {
					return // Only the existing aligned native-memory bridge needs these carriers.
				}
				features := "," + inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, Func{Instrs: []Instr{ins}}) + ","
				if got := strings.Contains(features, ",+avx512f,"); got != row.evex {
					t.Error("isolated native memory has the wrong AVX512F requirement", features)
				}
				if got := strings.Contains(features, ",+avx512vl,"); got != (row.evex && row.bank != "Z") {
					t.Error("isolated native memory has the wrong AVX512VL requirement", features)
				}
				if !row.evex && !strings.Contains(features, ",+avx,") {
					t.Error("the original VEX control lost its AVX requirement", features)
				}
			})
		}
	}
}

func TestX86RawPackedMovePhysicalBytesIndependentLLVM22(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM22 llvm-mc required")
	}
	var input strings.Builder
	for _, row := range x86PackedMovePhysicalCases() {
		for _, value := range row.code {
			fmt.Fprintf(&input, "0x%02x ", value)
		}
		input.WriteByte('\n')
	}
	for _, triple := range []string{"i386-unknown-linux-gnu", "x86_64-unknown-linux-gnu"} {
		t.Run(triple, func(t *testing.T) {
			stage, cancel := runtimeOracleStageContext(t)
			defer cancel()
			command := exec.CommandContext(stage, mc, "--disassemble", "--triple="+triple,
				"--mattr=+avx,+avx512f,+avx512vl")
			command.Stdin = strings.NewReader(input.String())
			output, err := runtimeOracleCombinedOutput(stage, command)
			if err != nil || strings.Contains(string(output), "warning") || strings.Contains(string(output), "invalid") {
				t.Fatalf("independent complete physical-byte decoding failed: %v\n%s", err, output)
			}
			for _, name := range []string{"vmovaps", "vmovapd", "vmovups", "vmovupd"} {
				if count := len(regexp.MustCompile(`\b`+name+`[ \t]+`).FindAll(output, -1)); count != 20 {
					t.Fatalf("independent LLVM22 decoding lost %s physical forms: %d\n%s", name, count, output)
				}
			}
		})
	}
}

func x86RawPackedMoveAlignedPhysicalSource(arch string, initialized bool) (string, string) {
	word, pointerMove := goWordSize(arch), "MOVQ"
	if arch == "386" {
		pointerMove = "MOVL"
	}
	var source, declarations strings.Builder
	index := 0
	for _, row := range x86PackedMovePhysicalCases() {
		if !row.aligned || row.bank == "Z" || strings.HasPrefix(row.role, "register") {
			continue
		}
		fmt.Fprintf(&declarations, "func Physical%d(p *[128]byte)\n", index)
		fmt.Fprintf(&source, "TEXT ·Physical%d(SB),4,$0-%d\n", index, word)
		if initialized {
			fmt.Fprintf(&source, "%s p+0(FP),SI\nVPXOR X2,X2,X2\n", pointerMove)
		}
		for _, value := range row.code {
			fmt.Fprintf(&source, "BYTE $%d\n", value)
		}
		source.WriteString("RET\n")
		index++
	}
	return source.String(), declarations.String()
}

func TestX86RawPackedMoveLowBankEVEXAlignedFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86RawPackedMoveAlignedPhysicalSource(target.arch, true)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("valid initialized original physical move was not translated", err)
					}
					for _, name := range []string{"vmovaps", "vmovapd"} {
						if strings.Count(ir, "{evex} "+name+" ") != 4 || strings.Count(ir, `asm sideeffect "`+name+` `) != 4 {
							t.Fatal("original low-bank native EVEX/VEX opcode generation changed", name)
						}
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						compileLLVMToObject(t, llc, target.triple, "physical-move.ll", "physical-move.o", body)
					}
					x86PackedStringCompileObject(t, llc, target.triple, ir, "-O2")
				})
			}
		})
	}
}

func TestX86RawPackedMovePhysicalGenerationDoesNotGrantEntryInputs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86RawPackedMoveAlignedPhysicalSource(target.arch, false)
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("physical encoding or CPU features invented native entry inputs", api, err)
				}
			}
		})
	}
}
