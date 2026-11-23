package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64SVEWidthChangeCompleteGo127Forms(t *testing.T) {
	const header = "TEXT svewidth(SB),$0-0\n"
	var source, rawSource strings.Builder
	source.WriteString(header)
	rawSource.WriteString(header)
	var assembly []string
	var masks []uint32
	widths := [...]string{"b", "h", "s", "d"}
	for _, op := range []string{"scvtflt", "ucvtflt"} {
		for i, narrow := range widths[:3] {
			wide := widths[i+1]
			fmt.Fprintf(&source, "\tZ%s Z29.%s, Z31.%s\n", strings.ToUpper(op), strings.ToUpper(narrow), strings.ToUpper(wide))
			assembly = append(assembly, fmt.Sprintf("%s z31.%s, z29.%s", op, wide, narrow))
			masks = append(masks, 0xfffffc00)
		}
	}
	for _, op := range []string{"fcvtzsn", "fcvtzun", "sqshrn", "sqshrun", "uqshrn"} {
		shifted := !strings.HasPrefix(op, "fcvt")
		for i, narrow := range widths[:3] {
			wide := widths[i+1]
			if shifted && narrow == "s" {
				continue
			}
			count := 1
			if shifted {
				count = 8 << i
			}
			for n := 1; n <= count; n++ {
				prefix, suffix := "", ""
				if shifted {
					prefix, suffix = fmt.Sprintf("$%d, ", n), fmt.Sprintf(", #%d", n)
				}
				fmt.Fprintf(&source, "\tZ%s %s[Z28.%[3]s-Z29.%[3]s], Z31.%[4]s\n",
					strings.ToUpper(op), prefix, strings.ToUpper(wide), strings.ToUpper(narrow))
				assembly = append(assembly, fmt.Sprintf("%s z31.%s, {z28.%[3]s-z29.%[3]s}%[4]s", op, narrow, wide, suffix))
				masks = append(masks, 0xfffffc20)
			}
		}
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	named, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	words := assembleARM64LLVMWords(t, assembly, "+sve2p3")
	for _, word := range words {
		fmt.Fprintf(&rawSource, "\tWORD $%#08x\n", word)
	}
	rawSource.WriteString("\tRET\n")
	raw, err := Parse(ArchARM64, rawSource.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{arm64LinuxGNUTriple, "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			options := Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"svewidth": {Name: "svewidth", Ret: Void}},
			}
			namedIR, err := Translate(named, options)
			if err != nil {
				t.Fatalf("translate named width changes: %v", err)
			}
			rawIR, err := Translate(raw, options)
			if err != nil {
				t.Fatalf("translate width-change WORDs: %v", err)
			}
			_, namedBody, namedOK := strings.Cut(namedIR, "\ntarget triple")
			_, rawBody, rawOK := strings.Cut(rawIR, "\ntarget triple")
			if !namedOK || !rawOK || namedBody != rawBody {
				t.Fatal("named and raw width changes did not lower identically")
			}
			object := compileLLVMToObject(t, llc, triple, "sve-width-change.ll", "sve-width-change.o", namedIR)
			if triple == arm64LinuxGNUTriple {
				requireARM64ObjectWordSequence(t, object, words, masks, assembly)
			}
		})
	}
}

func TestTranslateARM64SVEWidthChangeRejectsIllegalGo127Forms(t *testing.T) {
	for _, instruction := range []string{
		"ZSCVTFLT Z1.H, Z2.H",
		"ZUCVTFLT Z1.D, Z2.D",
		"ZFCVTZSN [Z1.H-Z2.H], Z4.B",
		"ZFCVTZUN [Z0.H, Z1.H], Z4.B",
		"ZFCVTZUN [Z0.S-Z1.S], Z4.B",
		"ZSQSHRN $0, [Z0.H-Z1.H], Z4.B",
		"ZSQSHRUN $9, [Z0.H-Z1.H], Z4.B",
		"ZUQSHRN $17, [Z0.S-Z1.S], Z4.H",
		"ZSQSHRN $1, [Z0.D-Z1.D], Z4.S",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT svewidth(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			ir, err := Translate(file, Options{
				TargetTriple: arm64LinuxGNUTriple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"svewidth": {Name: "svewidth", Ret: Void}},
			})
			if err == nil || ir != "" {
				t.Fatalf("illegal form returned IR=%t, error=%v", ir != "", err)
			}
		})
	}
}
