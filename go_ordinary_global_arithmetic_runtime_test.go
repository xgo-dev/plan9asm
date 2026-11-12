package plan9asm

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"math/bits"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Numerical oracle independent of the opcode/effect directories and emitted
// LLVM. A big signed product supplies overflow without host-width truncation.
func ordinaryGlobalArithmeticExpected(row ordinaryGlobalArithmeticCase, arch string, seed uint64) [16]byte {
	var storage [40]byte
	for index := 0; index < 5; index++ {
		binary.LittleEndian.PutUint64(storage[8*index:], seed^(uint64(index)*0x9e3779b97f4a7c15))
	}
	var source uint64
	for index := 0; index < row.bits/8; index++ {
		source |= uint64(storage[1+index]) << uint(8*index)
	}
	prior := uint64(0x1234567889abcdef)
	if arch == "386" {
		prior = uint64(0x89abcdef)
	}
	shift := 0
	if row.highByte {
		shift = 8
	}
	mask := ^uint64(0) >> uint(64-row.bits)
	sign := uint64(1) << uint(row.bits-1)
	left := prior >> uint(shift) & mask
	carry := uint64(0)
	if row.carry {
		carry = 1
	}
	var value uint64
	cf, of := false, false
	switch row.stem {
	case "ADD", "ADC":
		var high uint64
		value, high = bits.Add64(left, source, carry)
		cf = high != 0 || value > mask
		value &= mask
		of = ^(left^source)&(left^value)&sign != 0
	case "SUB", "SBB":
		var borrow uint64
		value, borrow = bits.Sub64(left, source, carry)
		cf = borrow != 0
		value &= mask
		of = (left^source)&(left^value)&sign != 0
	case "AND":
		value = left & source
	case "OR":
		value = left | source
	case "XOR":
		value = left ^ source
	case "IMUL":
		if row.three {
			// The encoder uses an imm32, sign-extended to Q, and truncated
			// to W/L; this is not the unbounded source integer spelling.
			left = uint64(int64(int32(row.immediate))) & mask
		}
		signed := func(value uint64) *big.Int {
			result := new(big.Int).SetUint64(value)
			if value&sign != 0 {
				result.Sub(result, new(big.Int).Lsh(big.NewInt(1), uint(row.bits)))
			}
			return result
		}
		product := new(big.Int).Mul(signed(left), signed(source))
		value = new(big.Int).Mod(product, new(big.Int).Lsh(big.NewInt(1), uint(row.bits))).Uint64()
		cf = product.Cmp(signed(value)) != 0
		of = cf
	default:
		panic("unknown independent arithmetic oracle member")
	}
	register := prior&^(mask<<uint(shift)) | value<<uint(shift)
	if row.bits == 32 {
		register = value // A dword destination zeroes the upper half.
	}
	var output [16]byte
	for index := range output {
		output[index] = 0xa5
	}
	binary.LittleEndian.PutUint64(output[:8], register)
	boolean := func(value bool) byte {
		if value {
			return 1
		}
		return 0
	}
	output[8], output[9] = boolean(cf), boolean(of)
	if row.stem != "IMUL" {
		zf, sf, pf := value == 0, value&sign != 0, bits.OnesCount8(uint8(value))%2 == 0
		output[10], output[11], output[12] = boolean(zf), boolean(sf), boolean(pf)
		if row.stem != "AND" && row.stem != "OR" && row.stem != "XOR" {
			af := (left^source^value)&0x10 != 0
			output[13] = 2 | boolean(cf) | boolean(pf)<<2 | boolean(af)<<4 | boolean(zf)<<6 | boolean(sf)<<7
		}
	}
	return output
}

func TestCrossLinuxRuntimeMatrixGoModuleOrdinaryGlobalArithmeticAMD64(t *testing.T) {
	ordinaryGlobalArithmeticRuntime(t, "amd64", x86FloatCompareExecutionTools(t), true)
}

func TestGoModuleOrdinaryGlobalArithmeticPortableExecution(t *testing.T) {
	arch := "amd64"
	if strconv.IntSize == 32 {
		arch = "386"
	}
	ordinaryGlobalArithmeticRuntime(t, arch, x86ScalarCountHostExecution(t), false)
	t.Log("actual-host portable numerical/FLAGS/canary execution; not native original x86 execution")
}

func ordinaryGlobalArithmeticRuntime(t *testing.T, arch string, execution x86FloatCompareExecution, originalGo bool) {
	t.Helper()
	assembly, declarations := ordinaryGlobalArithmeticSource(arch)
	rows := ordinaryGlobalArithmeticCases(arch)
	patterns := []uint64{0, 0x7f00, 0x8000, 0xff00, 0x7fff00, 0x800000,
		0x7fffffff00, 0x8000000000, 0x95, 0xffffffffffffff6a, 0xffffffffffffffea, ^uint64(0)}
	var goChecks, cChecks, cDeclarations strings.Builder
	prefix := ""
	if runtime.GOOS == "darwin" {
		prefix = "_"
	}
	const linkedPackage = "ordinaryglobals"
	for index := range rows {
		fmt.Fprintf(&cDeclarations, "extern void arithmetic%d(uint8_t*) __asm__(\"%s%s.arithmetic%d\");\n",
			index, prefix, linkedPackage, index)
	}
	for pattern, seed := range patterns {
		fmt.Fprintf(&goChecks, "for i:=range words { words[i]=uint64(%d)^(uint64(i)*0x9e3779b97f4a7c15) }\n", seed)
		fmt.Fprintf(&cChecks, "for(unsigned i=0;i<5;++i) storage[i]=UINT64_C(%d)^((uint64_t)i*UINT64_C(0x9e3779b97f4a7c15));\n", seed)
		for index, row := range rows {
			want := ordinaryGlobalArithmeticExpected(row, arch, seed)
			var values []string
			for _, value := range want {
				values = append(values, fmt.Sprint(value))
			}
			bytes := strings.Join(values, ",")
			fmt.Fprintf(&goChecks, "{ var box struct{ before byte; data [16]byte; after byte }; box.before=55;box.after=146;for i:=range box.data { box.data[i]=165 }; arithmetic%d(&box.data); if box.before!=55||box.after!=146||box.data!=([16]byte{%s}) { panic(fmt.Sprintf(\"pattern=%d row=%d got=%%x\",box.data)) } }\n",
				index, bytes, pattern, index)
			fmt.Fprintf(&cChecks, "{ struct { uint8_t before,data[16],after; } box; box.before=55;box.after=146;memset(box.data,165,16); arithmetic%d(box.data); const uint8_t want[16]={%s}; if(box.before!=55||box.after!=146||memcmp(box.data,want,16)) {fprintf(stderr,\"pattern=%d row=%d mismatch\\n\");return 1;} }\n",
				index, bytes, pattern, index)
		}
	}
	want := fmt.Sprintf("%d readonly arithmetic programs x %d data/FLAGS/canary patterns\n", len(rows), len(patterns))
	driver := "package main\nimport \"fmt\"\nfunc main(){\n" + goChecks.String() + fmt.Sprintf("fmt.Print(%q)\n}\n", want)
	if originalGo {
		original := x86OrderingHintBuildOriginal(t, t.TempDir(), runtime.GOOS, arch,
			"package main\n"+declarations, assembly, driver)
		if output := execution.run(t, original); string(output) != want {
			t.Fatalf("original complete Go source disagrees with independent arithmetic: %q", output)
		}
	} else {
		goAssemblerOracleOutput(t, arch, assembly, "", true)
	}
	cSource := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + cDeclarations.String() +
		fmt.Sprintf("uint64_t storage[5] __asm__(\"%s%s.words\");\n", prefix, linkedPackage) +
		"int main(void){\n" + cChecks.String() + fmt.Sprintf("printf(%q);return 0;\n}\n", want)
	for _, api := range []string{"public", "owned-context"} {
		t.Run(api, func(t *testing.T) {
			pkg := mustGoPackage(t, ordinaryGlobalReadPackage, "package ordinaryglobals\n"+declarations)
			pkg.Path = linkedPackage
			ir, err := ordinaryGlobalReadRequest(t, pkg, []byte(assembly), arch, execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, pipeline := range []struct{ name, ir, level string }{
				{"backend_O0", ir, "-O0"},
				{"IR_O2/backend_O2", x86MulDivRoundOptimize(t, ir), "-O2"},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					if output := execution.compileAndRunLLVM(t, "ordinary-global-arithmetic", pipeline.ir, cSource, pipeline.level); string(output) != want {
						t.Fatalf("arithmetic numerical/FLAGS/canary receipt: %q", output)
					}
					t.Log(strings.TrimSpace(want))
				})
			}
		})
	}
}
