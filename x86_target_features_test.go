package plan9asm

import (
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// Feature inference is independent of private SDK CPU layouts and is checked
// on every supported Go version and host. The complete current SDK CRC32
// source has its own actual-source/header/storage three-API object oracle.
func TestX86CRC32AndCLMULTargetFeatures(t *testing.T) {
	llc, _, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT ·CRC(SB),4,$0-24
MOVQ a+0(FP),AX
MOVQ b+8(FP),CX
CRC32Q AX,CX
MOVQ CX,ret+16(FP)
RET

TEXT ·CLMUL(SB),4,$0-24
MOVQ a+0(FP),AX
MOVQ b+8(FP),CX
MOVQ AX,X0
MOVQ CX,X1
PCLMULQDQ $0,X1,X0
PEXTRQ $0,X0,AX
MOVQ AX,ret+16(FP)
RET
`
	if _, err := x86ScalarLiteralGoListing(t, "amd64", source); err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "literal", `package literal
func CRC(a, b uint64) uint64
func CLMUL(a, b uint64) uint64
`)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	translated, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
		FileName: "features_amd64.s", GOARCH: "amd64", GOOS: "linux",
		TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: testResolveSym(pkg.Path),
	})
	if err != nil {
		t.Fatal(err)
	}
	ir := translated.Module.String()
	translated.Module.Dispose()
	requireCRC32TargetFeatures(t, ir)
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "features.ll", "features.o", ir)
}

func requireCRC32TargetFeatures(t *testing.T, ir string) {
	t.Helper()
	if !hasTargetFeatures(ir, "+crc32", "+sse4.2") {
		t.Fatal("missing crc32 target-features attribute")
	}
	if !hasTargetFeatures(ir, "+pclmul", "+sse4.1") {
		t.Fatal("missing pclmul target-features attribute")
	}
}

func hasTargetFeatures(ir string, features ...string) bool {
	const marker = `"target-features"="`
	for _, line := range strings.Split(ir, "\n") {
		start := strings.Index(line, marker)
		if start < 0 {
			continue
		}
		value := line[start+len(marker):]
		if end := strings.IndexByte(value, '"'); end >= 0 {
			value = value[:end]
		}
		available := map[string]bool{}
		for _, feature := range strings.Split(value, ",") {
			available[feature] = true
		}
		for _, feature := range features {
			if !available[feature] {
				goto nextLine
			}
		}
		return true
	nextLine:
	}
	return false
}

func TestHasTargetFeaturesAllowsExtrasButRequiresOneExactSet(t *testing.T) {
	ir := `attributes #7 = { "target-features"="+crc32,+sse4.2" }
attributes #8 = { "target-features"="+bmi2,+pclmul,+sse4.1" }`
	if !hasTargetFeatures(ir, "+pclmul", "+sse4.1") {
		t.Fatal("extra target feature prevented matching the required set")
	}
	if hasTargetFeatures(ir, "+crc32", "+pclmul") {
		t.Fatal("features from separate attributes were combined")
	}
	if hasTargetFeatures(ir, "+sse4") {
		t.Fatal("partial feature name matched")
	}
}
