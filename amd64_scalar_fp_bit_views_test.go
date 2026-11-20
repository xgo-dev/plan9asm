package plan9asm

import (
	"fmt"
	"go/types"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86ScalarFPBitViewAPI(t *testing.T, source, declaration, arch, triple, api string) (string, error) {
	t.Helper()
	pkg := mustGoPackage(t, "bitview", "package bitview\n"+declaration)
	return x86ScalarFPBitViewPackageAPI(t, source, pkg, arch, triple, api)
}

func x86ScalarFPBitViewPackageAPI(t *testing.T, source string, pkg GoPackage, arch, triple, api string) (string, error) {
	return x86ScalarFPBitViewPackageAPIWithManual(t, source, pkg, arch, triple, api, nil)
}

func x86ScalarFPBitViewPackageAPIWithManual(t *testing.T, source string, pkg GoPackage, arch, triple, api string,
	manual func(string) (FuncSig, bool)) (string, error) {
	t.Helper()
	resolve := func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") }
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if api == "Go" {
		module, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: arch, TargetTriple: triple, ResolveSym: resolve, ManualSig: manual,
		})
		if module != nil && !module.Module.IsNil() {
			defer module.Module.Dispose()
			return module.Module.String(), err
		}
		return "", err
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		return "", err
	}
	signatures, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, manual)
	if err != nil {
		return "", err
	}
	options := Options{Goarch: arch, TargetTriple: triple, ResolveSym: resolve, Sigs: signatures}
	if api == "text" {
		return Translate(file, options)
	}
	if api != "module" {
		t.Fatal("unknown scalar FP bit-view API", api)
	}
	module, err := TranslateModuleInContext(ctx, file, options)
	if !module.IsNil() {
		defer module.Dispose()
		return module.String(), err
	}
	return "", err
}

type x86ScalarFPBitFixture struct {
	name, declaration, body string
	args                    int
}

func x86ScalarFPBitFixtures() []x86ScalarFPBitFixture {
	fixtures := []x86ScalarFPBitFixture{
		{"low-int64", "func view(x uint64) uint32\n", "MOVSS x+0(FP),X7\nMOVSS X7,ret+8(FP)", 12},
		{"high-int64", "func view(x int64) uint32\n", "MOVSS x+4(FP),X7\nMOVSS X7,ret+8(FP)", 12},
		{"cross-uint32", "func view(a,b uint32) uint64\n", "MOVSD a+0(FP),X7\nMOVSD X7,ret+8(FP)", 16},
		{"store-subword", "func view(x,y uint64) uint64\n", "MOVSD x+0(FP),X1\nMOVSD X1,ret+16(FP)\nMOVSS y+8(FP),X7\nMOVSS X7,ret+18(FP)", 24},
		{"read-written-result", "func view(x uint64) uint32\n", "MOVL $-1,AX\nMOVL AX,ret+8(FP)\nMOVSS ret+8(FP),X7\nMOVSS X7,ret+8(FP)", 12},
		{"cross-result-fields", "func view(x uint64) (a,b uint32)\n", "MOVSD x+0(FP),X7\nMOVSD X7,a+8(FP)\nMOVSS b+12(FP),X7\nMOVSS X7,b+12(FP)", 16},
	}
	for _, fixture := range append([]x86ScalarFPBitFixture(nil), fixtures...) {
		fixture.name = "vex-" + fixture.name
		fixture.body = strings.ReplaceAll(strings.ReplaceAll(fixture.body, "MOVSS ", "VMOVSS "), "MOVSD ", "VMOVSD ")
		fixtures = append(fixtures, fixture)
	}
	fixtures = append(fixtures,
		x86ScalarFPBitFixture{"inverse32", "func view(x float32) uint32\n", "MOVL x+0(FP),AX\nMOVL AX,ret+8(FP)", 12},
		x86ScalarFPBitFixture{"inverse64", "func view(x float64) uint64\n", "MOVQ x+0(FP),X7\nMOVQ X7,ret+8(FP)", 16},
	)
	for offset := 1; offset < 4; offset++ {
		for _, prefix := range []string{"", "V"} {
			fixtures = append(fixtures, x86ScalarFPBitFixture{
				fmt.Sprintf("%ssubbyte%d", prefix, offset), "func view(x uint64) uint32\n",
				fmt.Sprintf("%sMOVSS x+%d(FP),X7\n%sMOVSS X7,ret+8(FP)", prefix, offset, prefix), 12,
			})
		}
	}
	for _, bits := range []int{32, 64} {
		op, typ, width := "MOVSS", "uint32", bits/8
		if bits == 64 {
			op, typ = "MOVSD", "uint64"
		}
		for _, prefix := range []string{"", "V"} {
			fixtures = append(fixtures, x86ScalarFPBitFixture{
				fmt.Sprintf("%s%d-byte-fields", prefix, bits),
				fmt.Sprintf("func view(x [%d]byte) %s\n", width, typ),
				fmt.Sprintf("%s%s x+0(FP),X7\n%s%s X7,ret+%d(FP)", prefix, op, prefix, op, width), 2 * width,
			})
			for _, goType := range []string{"uint", "int", "float"} {
				fixtures = append(fixtures, x86ScalarFPBitFixture{
					fmt.Sprintf("%s%d-%s-natural", prefix, bits, goType),
					fmt.Sprintf("func view(x %s%d) uint%d\n", goType, bits, bits),
					fmt.Sprintf("%s%s x+0(FP),X7\n%s%s X7,ret+8(FP)", prefix, op, prefix, op), 8 + width,
				})
			}
			for _, fieldType := range []string{"int8", "int16", "uint16"} {
				fieldWidth := 2
				if fieldType == "int8" {
					fieldWidth = 1
				}
				fixtures = append(fixtures, x86ScalarFPBitFixture{
					fmt.Sprintf("%s%d-fields-%s", prefix, bits, fieldType),
					fmt.Sprintf("func view(x [%d]%s) %s\n", width/fieldWidth, fieldType, typ),
					fmt.Sprintf("%s%s x+0(FP),X7\n%s%s X7,ret+%d(FP)", prefix, op, prefix, op, width), 2 * width,
				})
			}
		}
	}
	for _, prefix := range []string{"", "V"} {
		fixtures = append(fixtures, x86ScalarFPBitFixture{
			prefix + "mixed-float-integer", "func view(a float32,b int32) uint64\n",
			fmt.Sprintf("%sMOVSD a+0(FP),X7\n%sMOVSD X7,ret+8(FP)", prefix, prefix), 16,
		})
	}
	for _, active := range []int{0, 1} {
		for _, zero := range []bool{false, true} {
			suffix := ""
			if zero {
				suffix = ".Z"
			}
			fixtures = append(fixtures, x86ScalarFPBitFixture{
				fmt.Sprintf("masked-load-%d-zero%t", active, zero), "func view(x,y uint64) uint32\n",
				fmt.Sprintf("MOVSS y+8(FP),X7\nMOVL $%d,AX\nKMOVD AX,K1\nVMOVSS%s x+4(FP),K1,X7\nMOVSS X7,ret+16(FP)", active, suffix), 20,
			})
		}
		fixtures = append(fixtures, x86ScalarFPBitFixture{
			fmt.Sprintf("masked-store-%d", active), "func view(x,y uint64) uint64\n",
			fmt.Sprintf("MOVSD x+0(FP),X1\nMOVSD X1,ret+16(FP)\nMOVSS y+8(FP),X7\nMOVL $%d,AX\nKMOVD AX,K1\nVMOVSS X7,K1,ret+18(FP)", active), 24,
		})
	}
	for _, active := range []int{0, 1} {
		for _, zero := range []bool{false, true} {
			suffix := ""
			if zero {
				suffix = ".Z"
			}
			fixtures = append(fixtures, x86ScalarFPBitFixture{
				fmt.Sprintf("masked-double-load-%d-zero%t", active, zero), "func view(x,y uint64) uint64\n",
				fmt.Sprintf("MOVSD y+8(FP),X7\nMOVL $%d,AX\nKMOVD AX,K1\nVMOVSD%s x+0(FP),K1,X7\nMOVSD X7,ret+16(FP)", active, suffix), 24,
			})
		}
		fixtures = append(fixtures, x86ScalarFPBitFixture{
			fmt.Sprintf("masked-double-store-%d", active), "func view(x,y uint64) uint64\n",
			fmt.Sprintf("MOVSD x+0(FP),X1\nMOVSD X1,ret+16(FP)\nMOVSD y+8(FP),X7\nMOVL $%d,AX\nKMOVD AX,K1\nVMOVSD X7,K1,ret+16(FP)", active), 24,
		})
	}
	return fixtures
}

func x86ScalarFPBitAssembly(t *testing.T, fixture x86ScalarFPBitFixture, arch string) string {
	t.Helper()
	pkg := mustGoPackage(t, "bitview", "package bitview\n"+fixture.declaration)
	sig, err := DeriveGoFuncABI0Signature("view", pkg.Types.Scope().Lookup("view").(*types.Func), arch, types.SizesFor("gc", arch))
	if err != nil {
		t.Fatal(err)
	}
	body := fixture.body
	pattern := regexp.MustCompile(`ret\+(\d+)\(FP\)`)
	matches := pattern.FindAllStringSubmatch(body, -1)
	if len(matches) != 0 {
		base, _ := strconv.Atoi(matches[0][1])
		for _, match := range matches[1:] {
			if offset, _ := strconv.Atoi(match[1]); offset < base {
				base = offset
			}
		}
		delta := sig.Frame.Results[0].Offset - int64(base)
		body = pattern.ReplaceAllStringFunc(body, func(operand string) string {
			offset, _ := strconv.Atoi(pattern.FindStringSubmatch(operand)[1])
			return fmt.Sprintf("ret+%d(FP)", int64(offset)+delta)
		})
	}
	end := int64(0)
	for _, slot := range sig.Frame.Results {
		if current := slot.Offset + x86FrameTypeSize(slot.Type); current > end {
			end = current
		}
	}
	return fmt.Sprintf("TEXT ·view(SB),4,$0-%d\n%s\nRET\n", end, body)
}

func TestX86ScalarFPBitViewsOriginalAcceptedThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, fixture := range x86ScalarFPBitFixtures() {
		for _, target := range x86RawReturnTargets {
			t.Run(fixture.name+"/"+target.triple, func(t *testing.T) {
				source := x86ScalarFPBitAssembly(t, fixture, target.arch)
				receipt := x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				t.Logf("original Go scalar bit-view object receipt: %+v", receipt)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, fixture.declaration, target.arch, target.triple, api)
						if err != nil {
							t.Fatal(err)
						}
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, ir, level)
						}
					})
				}
			})
		}
	}
}
