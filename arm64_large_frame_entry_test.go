package plan9asm

import (
	"context"
	"fmt"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
)

func arm64LargeFrameScalarSource(frame int) string {
	return fmt.Sprintf(`TEXT ·LargeR20(SB),4,$%d-8
MOVD $0x123456789abcdef,R8
MOVD R8,32(RSP)
WORD $0xf9401280
MOVD R0,ret+0(FP)
RET
`, frame) // Original LDR X0,[X20,#32], not a decoded fixture spelling.
}

func arm64LargeFrameScalarIRs(t *testing.T, source, triple string) []string {
	t.Helper()
	pkg := mustGoPackage(t, "largeframe", "package largeframe\nfunc LargeR20() uint64\n")
	resolve := testResolveSym("largeframe")
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", "arm64")
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
	ir, err := Translate(file, options)
	if err != nil {
		t.Fatal(err)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, options)
	if err != nil {
		t.Fatal(err)
	}
	moduleIR := module.String()
	module.Dispose()
	bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: triple, ResolveSym: resolve,
	})
	if err != nil {
		t.Fatal(err)
	}
	boundIR := bound.Module.String()
	bound.Module.Dispose()
	return []string{ir, moduleIR, boundIR}
}

func TestARM64LargeFrameR20EntryProducer(t *testing.T) {
	source := arm64LargeFrameScalarSource(496)
	requireARM64GoAssemblerResult(t, source, true)
	// Static RED witness only: the old LLVM implementation reads R20=0.
	// Never execute that old LLVM object to demonstrate its null dereference.
	for api, ir := range arm64LargeFrameScalarIRs(t, source, arm64LinuxGNUTriple) {
		sp := regexp.MustCompile(`store i64 (%t[0-9]+), ptr %reg_SP`).FindStringSubmatch(ir)
		if len(sp) != 2 || !strings.Contains(ir, "store i64 "+sp[1]+", ptr %reg_R20") {
			t.Errorf("API %d accepted the original scalar R20 load without transporting Go's new private SP to R20", api)
		}
	}
}

func TestARM64LargeFrameActualGoPrologue(t *testing.T) {
	// These are Go source frame sizes, not LLVM allocation sizes. Both Go 1.20
	// and Go 1.27 must supply the same implicit producer at the exact boundary.
	type prologueCase struct {
		name, text, body string
		frame            int64
		producer, valid  bool
	}
	var cases []prologueCase
	for _, frame := range []int64{0, 8, 16, 216, 224, 232, 240, 248, 496, 4080, 4088, 4096, 65528} {
		cases = append(cases, prologueCase{
			name: fmt.Sprint(frame), text: fmt.Sprintf("TEXT prologue(SB),4,$%d-0", frame),
			frame: frame, valid: true,
			producer: frame != 0 && arm64SourceFrameAutosize(frame) > 0xf0,
		})
	}
	cases = append(cases,
		prologueCase{name: "noframe", text: "TEXT prologue(SB),516,$0-0", valid: true},
		prologueCase{name: "negative_noframe", text: "TEXT prologue(SB),4,$-8-0", frame: -8, valid: true},
		prologueCase{name: "source_call_zero", text: "TEXT prologue(SB),4,$0-0", body: "CALL target(SB)", valid: true},
		prologueCase{name: "source_call_large", text: "TEXT prologue(SB),4,$496-0", body: "CALL target(SB)", frame: 496, producer: true, valid: true},
		prologueCase{name: "source_blr_large", text: "TEXT prologue(SB),4,$496-0", body: "BL (R9)", frame: 496, producer: true, valid: true},
		prologueCase{name: "raw_bl_zero", text: "TEXT prologue(SB),4,$0-0", body: "WORD $0x94000000", valid: true},
		prologueCase{name: "raw_bl_large", text: "TEXT prologue(SB),4,$496-0", body: "WORD $0x94000000", frame: 496, producer: true, valid: true},
		prologueCase{name: "raw_blr_large", text: "TEXT prologue(SB),4,$496-0", body: "WORD $0xd63f0120", frame: 496, producer: true, valid: true},
		prologueCase{name: "unaligned_1", text: "TEXT prologue(SB),4,$1-0", frame: 1},
		prologueCase{name: "unaligned_4", text: "TEXT prologue(SB),4,$4-0", frame: 4},
		prologueCase{name: "unaligned_230", text: "TEXT prologue(SB),4,$230-0", frame: 230},
		prologueCase{name: "noframe_nonzero", text: "TEXT prologue(SB),516,$496-0", frame: 496},
	)
	for _, target := range []string{"linux", "darwin", "windows"} {
		for _, tc := range cases {
			t.Run(target+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "prologue.s")
				source := tc.text + "\n" + tc.body + "\nRET\n"
				if err := os.WriteFile(path, []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "go", "tool", "asm", "-S", "-o", filepath.Join(dir, "prologue.o"), path)
				cmd.Env = append(os.Environ(), "GOOS="+target, "GOARCH=arm64")
				listing, err := cmd.CombinedOutput()
				if !tc.valid {
					if err == nil {
						t.Fatalf("actual Go accepted invalid source frame\n%s", listing)
					}
					t.Logf("actual Go rejected invalid frame: %s", listing)
					return
				}
				if err != nil {
					t.Fatalf("actual Go prologue: %v\n%s", err, listing)
				}
				producer := regexp.MustCompile(`SUB\s+\$[0-9]+, RSP, R20`).Match(listing)
				if producer != tc.producer || tc.producer && !strings.Contains(string(listing), "MOVD\tR20, RSP") {
					t.Fatalf("frame=%d autosize=%d producer=%v want=%v\n%s", tc.frame, arm64SourceFrameAutosize(tc.frame), producer, tc.producer, listing)
				}
				t.Logf("source frame %d: actual large-frame R20 producer=%v", tc.frame, producer)
			})
		}
	}
}

func TestARM64LargeFrameTEXTContractIsNotInferred(t *testing.T) {
	pkg := mustGoPackage(t, "largeframe", "package largeframe\nfunc LargeR20() uint64\n")
	for _, replacement := range []string{
		"TEXT ·LargeR20(SB),4,$496",
		"TEXT ·LargeR20(SB),68,$496-8", // NEEDCTXT is an unproved hidden entry.
	} {
		source := strings.Replace(arm64LargeFrameScalarSource(496), "TEXT ·LargeR20(SB),4,$496-8", replacement, 1)
		requireARM64GoAssemblerResult(t, source, true)
		arm64LargeFrameCheckAPIs(t, source, pkg, nil, true, false)
	}
	file, err := Parse(ArchARM64, arm64LargeFrameScalarSource(496))
	if err != nil {
		t.Fatal(err)
	}
	fn := file.Funcs[0]
	fn.FrameSize = 504
	if arm64SourceFrameR20(fn) {
		t.Fatal("changed parsed frame borrowed the original TEXT producer")
	}
	fn = file.Funcs[0]
	fn.ArgSize = 16
	if arm64SourceFrameR20(fn) {
		t.Fatal("changed parsed argument size borrowed the original TEXT producer")
	}
}

func TestARM64LargeFrameProducerDoesNotBorrowABIInternal(t *testing.T) {
	// Bind the same explicit runtime identity in all three translation APIs.
	// The shared selector oracle queries the actual assembler flags: Go 1.20
	// also requires the stock driver's -compiling-runtime, unlike current Go.
	pkg := mustGoPackage(t, "runtime", "package runtime\nfunc Value() uint64\n")
	const source = `TEXT runtime·Value<ABIInternal>(SB),4,$496-8
MOVD $7,R20
MOVD R20,R0
RET
`
	requireARM64TypedCallGoSelectorObject(t, source)
	for _, ir := range arm64LargeFrameCheckAPIs(t, source, pkg, nil, false, true) {
		sp := regexp.MustCompile(`store i64 (%t[0-9]+), ptr %reg_SP`).FindStringSubmatch(ir)
		if len(sp) == 2 && strings.Contains(ir, "store i64 "+sp[1]+", ptr %reg_R20") {
			t.Fatal("software-defined ABIInternal R20 borrowed the separate ABI0 implicit producer")
		}
	}
	// A complete ABIInternal signature defines its actual parameter/result
	// leaves, not an unmodelled prologue scratch value.
	read := strings.Replace(source, "MOVD $7,R20\nMOVD R20,R0", "MOVD 32(R20),R0", 1)
	requireARM64TypedCallGoSelectorObject(t, read)
	arm64LargeFrameCheckAPIs(t, read, pkg, nil, true, false)
}
