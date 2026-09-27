package plan9asm

import "testing"

func TestTranslateX86RawVEXVNNIAndVariableDwordPermuteAllTargets(t *testing.T) {
	const source = `TEXT rawvexfamilies(SB),$0-0
	// {vex} VPDPBUSD X2, X1, X0.
	BYTE $0xc4; BYTE $0xe2; BYTE $0x71; BYTE $0x50; BYTE $0xc2
	// {vex} VPERMD Y5, Y3, Y4.
	BYTE $0xc4; BYTE $0xe2; BYTE $0x65; BYTE $0x36; BYTE $0xe5
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			ll, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"rawvexfamilies": {Name: "rawvexfamilies", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-vex-families-"+target.name+".ll", "raw-vex-families-"+target.name+".o", ll)
		})
	}
}
