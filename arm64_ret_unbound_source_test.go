package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64UnboundRETWidthRejectsSDKDependentRawBranches(t *testing.T) {
	// The two SDKs encode these source epilogues differently. Neither actual
	// object observation identifies the encoder of an arbitrary parsed Func.
	for _, test := range []struct {
		frame int
		call  string
		span  int
	}{
		{4080, "CALL anchor(SB)\n", 12},
		{4080, "CALL anchor(SB)\n", 16},
		{4096, "", 16},
		{4096, "", 20},
	} {
		t.Run(fmt.Sprintf("frame%d-call%t-span%d", test.frame, test.call != "", test.span), func(t *testing.T) {
			word := uint32(0x14000000 | ((test.span + 4) / 4))
			source := fmt.Sprintf("TEXT rawUnboundRET(SB),4,$%d-0\n%sWORD $0x%08x\nRET\nWORD $0xd503201f\nTEXT anchor(SB),4,$0-0\nRET\n", test.frame, test.call, word)
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := normalizeARM64RawPCRelative(file.Funcs[0]); err == nil || !strings.Contains(err.Error(), "proven instruction boundary") {
				t.Fatalf("unbound original RET encoder admitted a cross-RET raw branch: %v\n%s", err, source)
			}
		})
	}
}

func TestARM64LiteralReturnWordKeepsFourByteSourceWidth(t *testing.T) {
	const source = `TEXT rawLiteralRET(SB),4,$4096-0
	WORD $0x14000002
	WORD $0xd65f03c0
target:
	WORD $0xd503201f
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	fn := file.Funcs[0]
	if width, known := arm64RawKnownSourceWidth(fn, fn.Instrs[2]); !known || width != 4 {
		t.Fatalf("literal WORD RET lost its exact source width: (%d,%v)", width, known)
	}
	if _, err := normalizeARM64RawPCRelative(fn); err != nil {
		t.Fatalf("literal four-byte return disrupted its raw branch: %v", err)
	}
}

func TestARM64UnboundRETWidthDoesNotRejectOrdinaryReturn(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, frame := range []int{4080, 4096, 65536, 1 << 20, 1 << 30} {
		source := fmt.Sprintf("TEXT ordinaryRET(SB),4,$%d-0\nRET\n", frame)
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		fn := file.Funcs[0]
		if width, known := arm64RawKnownSourceWidth(fn, fn.Instrs[1]); known {
			t.Fatalf("unbound frame established a guessed RET width: %d", width)
		}
		for _, target := range []string{
			"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
			"aarch64-apple-darwin", "aarch64-pc-windows-msvc", "aarch64-unknown-freebsd",
		} {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: target,
				Sigs: map[string]FuncSig{"ordinaryRET": {Name: "ordinaryRET", Ret: Void}},
			})
			if err != nil {
				t.Fatalf("unbound source width must not ban ordinary RET: frame=%d target=%s: %v", frame, target, err)
			}
			compileLLVMToObject(t, llc, target, "ordinary-ret.ll", "ordinary-ret.o", ir)
		}
	}
}

func TestARM64UnboundRETWidthCommonDomainEdges(t *testing.T) {
	for _, frame := range []int{4064, 4072} {
		for _, call := range []string{"", "CALL anchor(SB)\n"} {
			source := fmt.Sprintf("TEXT domainEdge(SB),4,$%d-0\n%sRET\nWORD $0xd503201f\nTEXT anchor(SB),4,$0-0\nRET\n", frame, call)
			retLine := 2 + strings.Count(call, "\n")
			positions := arm64RETObjectPositions(t, "domain-edge", source)
			start, startOK := positions[retLine]
			end, endOK := positions[retLine+1]
			if !startOK || !endOK || end <= start {
				t.Fatal("actual Go object lost the domain-edge RET span")
			}
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			fn := file.Funcs[0]
			width, known := arm64RawKnownSourceWidth(fn, fn.Instrs[len(fn.Instrs)-2])
			if known != (frame == 4064) || known && (width != 12 || width != end-start) {
				t.Fatalf("domain edge frame=%d call=%t width=(%d,%v), actual=%d", frame, call != "", width, known, end-start)
			}
			word := uint32(0x14000000) | uint32((end-start+4)/4)
			crossSource := strings.Replace(source, "\nRET\nWORD", fmt.Sprintf("\nWORD $0x%08x\nRET\nWORD", word), 1)
			crossPositions := arm64RETObjectPositions(t, "domain-crossing", crossSource)
			if branch, ok := crossPositions[retLine]; !ok || crossPositions[retLine+2]-branch != end-start+4 {
				t.Fatal("domain-edge raw branch is not bound to its actual marker")
			}
			crossFile, err := Parse(ArchARM64, crossSource)
			if err != nil {
				t.Fatal(err)
			}
			_, err = normalizeARM64RawPCRelative(crossFile.Funcs[0])
			if known && err != nil || !known && (err == nil || !strings.Contains(err.Error(), "proven instruction boundary")) {
				t.Fatalf("domain-edge source crossing frame=%d call=%t: %v", frame, call != "", err)
			}
		}
	}
}
