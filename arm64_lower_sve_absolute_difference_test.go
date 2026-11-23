package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64SVEAbsoluteDifferenceCompleteForms() (string, []string, []uint32) {
	var source strings.Builder
	var assembly []string
	var masks []uint32
	source.WriteString("TEXT sveabsdiffforms(SB),$0-0\n")
	widths := [...]string{"b", "h", "s", "d"}
	const vectors = 0xffe0fc00
	const merging = 0xffffe000
	for _, op := range []string{"saba", "uaba"} {
		for _, width := range widths {
			fmt.Fprintf(&source, "\tZ%s Z29.%[2]s, Z30.%[2]s, Z31.%[2]s\n", strings.ToUpper(op), strings.ToUpper(width))
			assembly = append(assembly, fmt.Sprintf("%s z31.%[2]s, z30.%[2]s, z29.%[2]s", op, width))
			masks = append(masks, vectors)
		}
	}
	for _, op := range []string{"sabd", "uabd"} {
		for _, width := range widths {
			fmt.Fprintf(&source, "\tZ%s Z29.%[2]s, Z31.%[2]s, P7.M, Z31.%[2]s\n", strings.ToUpper(op), strings.ToUpper(width))
			assembly = append(assembly, fmt.Sprintf("%s z31.%[2]s, p7/m, z31.%[2]s, z29.%[2]s", op, width))
			masks = append(masks, merging)
		}
	}
	for _, op := range []string{"sabalb", "sabalt", "uabalb", "uabalt", "sabdlb", "sabdlt", "uabdlb", "uabdlt", "sabal", "uabal"} {
		for index, narrow := range widths[:3] {
			wide := widths[index+1]
			fmt.Fprintf(&source, "\tZ%s Z29.%[2]s, Z30.%[2]s, Z31.%[3]s\n",
				strings.ToUpper(op), strings.ToUpper(narrow), strings.ToUpper(wide))
			assembly = append(assembly, fmt.Sprintf("%s z31.%s, z30.%[3]s, z29.%[3]s", op, wide, narrow))
			masks = append(masks, vectors)
		}
	}
	for _, op := range []string{"sadalp", "uadalp"} {
		for index, narrow := range widths[:3] {
			wide := widths[index+1]
			fmt.Fprintf(&source, "\tZ%s Z29.%s, P7.M, Z31.%s\n",
				strings.ToUpper(op), strings.ToUpper(narrow), strings.ToUpper(wide))
			assembly = append(assembly, fmt.Sprintf("%s z31.%s, p7/m, z29.%s", op, wide, narrow))
			masks = append(masks, merging)
		}
	}
	source.WriteString("\tRET\n")
	return source.String(), assembly, masks
}

func TestTranslateARM64SVEAbsoluteDifferenceCompleteGo127Family(t *testing.T) {
	source, assembly, masks := arm64SVEAbsoluteDifferenceCompleteForms()
	requireARM64SVEGoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	words := assembleARM64LLVMWords(t, assembly, "+sve2p3")
	var rawSource strings.Builder
	rawSource.WriteString("TEXT sveabsdiffforms(SB),$0-0\n")
	for _, word := range words {
		fmt.Fprintf(&rawSource, "\tWORD $%#08x\n", word)
	}
	rawSource.WriteString("\tRET\n")
	rawFile, err := Parse(ArchARM64, rawSource.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			options := Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"sveabsdiffforms": {Name: "sveabsdiffforms", Ret: Void}},
			}
			ll, err := Translate(file, options)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := Translate(rawFile, options)
			if err != nil {
				t.Fatalf("translate raw absolute-difference forms: %v", err)
			}
			// Translation gives each module a unique buffer name.
			_, namedBody, namedOK := strings.Cut(ll, "\ntarget triple")
			_, rawBody, rawOK := strings.Cut(raw, "\ntarget triple")
			if !namedOK || !rawOK || namedBody != rawBody {
				t.Fatal("named and raw encodings did not lower identically")
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2,+sve2p3"`,
				"@llvm.aarch64.sve.saba.nxv16i8",
				"@llvm.aarch64.sve.uaba.nxv2i64",
				"@llvm.aarch64.sve.sabd.nxv8i16",
				"@llvm.aarch64.sve.uabd.nxv4i32",
				"@llvm.aarch64.sve.sabalb.nxv8i16",
				"@llvm.aarch64.sve.uabalt.nxv2i64",
				"@llvm.aarch64.sve.sabdlt.nxv4i32",
				"@llvm.aarch64.sve.uabdlb.nxv8i16",
				"@llvm.aarch64.sve.sadalp.nxv8i16",
				"@llvm.aarch64.sve.uadalp.nxv2i64",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE absolute-difference lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			object := compileLLVMToObject(t, llc, triple, "arm64-sve-absolute-difference.ll", "arm64-sve-absolute-difference.o", ll)
			if triple == arm64LinuxGNUTriple {
				requireARM64ObjectWordSequence(t, object, words, masks, assembly)
			}
		})
	}
}

func TestTranslateARM64SVEAbsoluteDifferenceRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSABA Z1.B, Z2.H, Z3.B",
		"ZUABA Z1.S, Z2.S, Z3.D",
		"ZSABD Z1.B, Z2.B, P0, Z2.B",
		"ZUABD Z1.H, Z2.H, P8.M, Z2.H",
		"ZSABD Z1.S, Z2.S, P0.M, Z3.S",
		"ZSABALB Z1.B, Z2.H, Z3.H",
		"ZUABALT Z1.S, Z2.S, Z3.S",
		"ZSABAL Z1.B, Z2.H, Z3.H",
		"ZUABAL Z1.S, Z2.S, Z3.S",
		"ZSABAL Z1.D, Z2.D, Z3.D",
		"ZSABDLB Z1.D, Z2.D, Z3.D",
		"ZUABDLT Z1.H, Z2.H, Z3.H",
		"ZSADALP Z1.B, P0, Z2.H",
		"ZUADALP Z1.H, P0.M, Z2.H",
		"ZSABA.Z Z1.B, Z2.B, Z3.B",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsveabsdiff(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveabsdiff": {Name: "badsveabsdiff", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE absolute-difference forms", instruction)
			}
		})
	}
}
