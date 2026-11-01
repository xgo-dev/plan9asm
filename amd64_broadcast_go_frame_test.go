package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86PackedBroadcastGoFrameScalarWidths(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, arch := range []string{"386", "amd64"} {
		pointerBytes, movePointer := 8, "MOVQ"
		triples := []string{"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"}
		if arch == "386" {
			pointerBytes, movePointer = 4, "MOVL"
			triples = []string{"i386-unknown-linux-gnu", "i686-pc-windows-msvc"}
		}
		for _, form := range []struct {
			op    string
			bytes int
		}{
			{"VPBROADCASTB", 1}, {"VPBROADCASTW", 2},
			{"VPBROADCASTD", 4}, {"VPBROADCASTQ", 8},
		} {
			t.Run(arch+"/"+form.op, func(t *testing.T) {
				outOffset := (form.bytes + pointerBytes - 1) &^ (pointerBytes - 1)
				var source, declarations strings.Builder
				declarations.WriteString("package broadcast\n")
				for _, width := range []string{"X", "Y", "Z"} {
					for index, masking := range []struct{ suffix, mask string }{
						{}, {mask: "K1,"}, {suffix: ".Z", mask: "K7,"},
					} {
						name := fmt.Sprintf("Broadcast%s%d", width, index)
						fmt.Fprintf(&declarations, "func %s(x uint%d, out *[64]byte)\n", name, form.bytes*8)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n", name, outOffset+pointerBytes)
						if masking.mask != "" {
							fmt.Fprintf(&source, "%s $1,AX\nKMOVQ AX,%s\n", movePointer, strings.TrimSuffix(masking.mask, ","))
							if masking.suffix == "" {
								clear := map[string]string{"X": "PXOR X0,X0", "Y": "VPXOR Y0,Y0,Y0", "Z": "VPXORD Z0,Z0,Z0"}[width]
								fmt.Fprintln(&source, clear)
							}
						}
						fmt.Fprintf(&source, "%s%s x+0(FP),%s%s0\n", form.op, masking.suffix, masking.mask, width)
						fmt.Fprintf(&source, "%s out+%d(FP),AX\n", movePointer, outOffset)
						store := map[string]string{"X": "MOVOU", "Y": "VMOVDQU", "Z": "VMOVDQU64"}[width]
						fmt.Fprintf(&source, "%s %s0,(AX)\nRET\n", store, width)
					}
				}
				requireX86GoAssemblerResult(t, arch, source.String(), true)
				sourceText := source.String()
				if arch == "386" {
					// KMOVQ's W bit is ignored for a GP transfer in mode32.
					// Keep KMOVD as a reference and compile the original below.
					sourceText = strings.ReplaceAll(sourceText, "KMOVQ AX,", "KMOVD AX,")
					requireX86GoAssemblerResult(t, arch, sourceText, true)
				}
				file, err := Parse(ArchAMD64, sourceText)
				if err != nil {
					t.Fatal(err)
				}
				pkg := mustGoPackage(t, "example.com/broadcast", declarations.String())
				resolve := testResolveSym(pkg.Path)
				sigs, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				for _, triple := range triples {
					t.Run(triple, func(t *testing.T) {
						if arch == "386" {
							original, err := Parse(ArchAMD64, source.String())
							if err != nil {
								t.Fatal(err)
							}
							originalSigs, err := goSigsForAsmFile(pkg, original, resolve, arch, nil, nil, nil)
							if err != nil {
								t.Fatal(err)
							}
							ir, err := Translate(original, Options{
								Goarch: arch, TargetTriple: triple, Sigs: originalSigs, ResolveSym: resolve,
							})
							if err != nil || ir == "" {
								t.Fatal("original mode32 KMOVQ must consume GP32 and zero-extend the mask", err)
							}
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, triple, ir, level)
							}
						}
						ctx := llvm.NewContext()
						defer ctx.Dispose()
						module, err := TranslateModuleInContext(ctx, file, Options{
							Goarch: arch, TargetTriple: triple, Sigs: sigs, ResolveSym: resolve,
						})
						if err != nil {
							t.Fatal(err)
						}
						defer module.Dispose()
						if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
							t.Fatal(err)
						}
						compileLLVMToObject(t, llc, triple, "broadcast-frame.ll", "broadcast-frame.o", module.String())
					})
				}
			})
		}
	}
}
