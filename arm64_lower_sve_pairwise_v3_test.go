package plan9asm

import (
	"debug/elf"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEPairwiseSVE2P3(t *testing.T) {
	const header = "TEXT pairwise(SB),$0-0\n"
	var source, native []string
	for _, size := range []string{"B", "H", "S", "D"} {
		suffix := strings.ToLower(size)
		source = append(source,
			fmt.Sprintf("ZADDQP Z29.%[1]s, Z30.%[1]s, Z31.%[1]s", size),
			fmt.Sprintf("ZADDSUBP Z29.%[1]s, Z30.%[1]s, Z31.%[1]s", size),
			fmt.Sprintf("ZSUBP Z29.%[1]s, Z31.%[1]s, P7.M, Z31.%[1]s", size),
			fmt.Sprintf("ZADDP Z29.%[1]s, Z31.%[1]s, P7.M, Z31.%[1]s", size),
		)
		native = append(native,
			fmt.Sprintf("addqp z31.%[1]s, z30.%[1]s, z29.%[1]s", suffix),
			fmt.Sprintf("addsubp z31.%[1]s, z30.%[1]s, z29.%[1]s", suffix),
			fmt.Sprintf("subp z31.%[1]s, p7/m, z31.%[1]s, z29.%[1]s", suffix),
			fmt.Sprintf("addp z31.%[1]s, p7/m, z31.%[1]s, z29.%[1]s", suffix),
		)
	}
	source = append(source,
		"ZADDPT Z29.D, Z30.D, Z31.D",
		"ZADDPT Z29.D, Z31.D, P7.M, Z31.D",
		"ZSUBPT Z29.D, Z30.D, Z31.D",
		"ZSUBPT Z29.D, Z31.D, P7.M, Z31.D",
	)
	native = append(native,
		"addpt z31.d, z30.d, z29.d",
		"addpt z31.d, p7/m, z31.d, z29.d",
		"subpt z31.d, z30.d, z29.d",
		"subpt z31.d, p7/m, z31.d, z29.d",
	)
	namedSource := header + strings.Join(source, "\n") + "\nRET\n"
	requireARM64SVEGoAssemblerResult(t, namedSource, true)
	words := assembleARM64LLVMWords(t, native, "+sve2p3,+cpa")
	var rawSource strings.Builder
	rawSource.WriteString(header)
	for _, word := range words {
		fmt.Fprintf(&rawSource, "WORD $%#08x\n", word)
	}
	rawSource.WriteString("RET\n")

	named, err := Parse(ArchARM64, namedSource)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Parse(ArchARM64, rawSource.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	sigs := map[string]FuncSig{"pairwise": {Name: "pairwise", Ret: Void}}
	for _, triple := range []string{arm64LinuxGNUTriple, "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			options := Options{TargetTriple: triple, Goarch: "arm64", Sigs: sigs}
			namedIR, err := Translate(named, options)
			if err != nil {
				t.Fatalf("translate named forms: %v", err)
			}
			rawIR, err := Translate(raw, options)
			if err != nil {
				t.Fatalf("translate raw forms: %v", err)
			}
			// Every call has a fresh LLVM buffer name in its module header.
			_, namedBody, namedOK := strings.Cut(namedIR, "\ntarget triple")
			_, rawBody, rawOK := strings.Cut(rawIR, "\ntarget triple")
			if !namedOK || !rawOK || namedBody != rawBody {
				t.Fatal("named and raw encodings did not lower identically")
			}
			object := compileLLVMToObject(t, llc, triple, "pairwise.ll", "pairwise.o", namedIR)
			if triple == arm64LinuxGNUTriple {
				masks := make([]uint32, len(native))
				for i, instruction := range native {
					masks[i] = 0xffe0fc00
					if strings.Contains(instruction, "/m,") {
						masks[i] = 0xffffe000
					}
				}
				requireARM64ObjectWordSequence(t, object, words, masks, native)
			}
		})
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
		t.Run(triple, func(t *testing.T) {
			for _, file := range []*File{named, raw} {
				ir, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: sigs})
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("incompatible backend returned IR=%t, error=%v", ir != "", err)
				}
			}
		})
	}
}

// A mask retains opcode and element width while excluding register fields
// chosen by the backend allocator.
func requireARM64ObjectWordSequence(t *testing.T, object string, expected, masks []uint32, assembly []string) {
	t.Helper()
	f, err := elf.Open(object)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	section := f.Section(".text")
	if section == nil {
		t.Fatal("missing AArch64 code section")
	}
	code, err := section.Data()
	if err != nil {
		t.Fatal(err)
	}
	next := 0
	for offset := 0; offset+4 <= len(code) && next < len(expected); offset += 4 {
		actual := f.ByteOrder.Uint32(code[offset : offset+4])
		mask := masks[next]
		if actual&mask == expected[next]&mask {
			next++
		}
	}
	if next != len(expected) {
		t.Fatalf("after %d of %d expected operations, object lacks %q", next, len(expected), assembly[next])
	}
}
