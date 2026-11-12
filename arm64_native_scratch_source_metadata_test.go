package plan9asm

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestARM64NativeScratchObjectSourceMetadataRequiresCapturedPhysicalInput(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "src")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(directory, "input.s")
	data := []byte("TEXT ·Value(SB),516,$0-8\nRET\n")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	// Explicit metadata unit input, not a live factory or source permission.
	source := &GoARM64ScratchSource{filePrefix: "gofile..", settings: map[string]string{"GOROOT": root},
		inputs: map[string][32]byte{input: sha256.Sum256(data)}}
	for _, name := range []string{
		input, "gofile.." + input, filepath.ToSlash(input), "gofile.." + filepath.ToSlash(input),
		"$GOROOT/src/input.s", "gofile..$GOROOT/src/input.s",
	} {
		if physical, valid := source.originalObjectSource(name); !valid || physical != input {
			t.Fatalf("exact captured physical source metadata %q rejected: %q", name, physical)
		}
	}
	foreign := filepath.Join(directory, "foreign.s")
	if err := os.WriteFile(foreign, data, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "alias.s")
	if err := os.Symlink(input, alias); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		foreign, alias, "input.s", "gofile..input.s", "gofile..gofile.." + input,
		filepath.Join(directory, "missing.s"), directory, "$GOROOT/../outside.s",
		directory + "/../src/input.s", "unknown-prefix" + input,
		"$GOROOT/src/../src/input.s", "$GOROOT/src/./input.s",
		"$GOROOT//src/input.s", "gofile..$GOROOT/src/../src/input.s",
	} {
		t.Run(name, func(t *testing.T) {
			if _, valid := source.originalObjectSource(name); valid {
				t.Fatal("uncaptured/relative/alias/escaping/nonregular metadata acquired a physical source identity")
			}
		})
	}
	if err := os.WriteFile(input, []byte("changed original bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, valid := source.originalObjectSource("gofile.." + input); valid {
		t.Fatal("metadata source bytes changed after capture")
	}
}

func TestARM64NativeScratchBuiltinObjectVersionMetadataIsNotABIAdmission(t *testing.T) {
	// This unit reads the actual selected SDK table. It deliberately has no
	// live capture, source selection, native body or declaration permission.
	source := &GoARM64ScratchSource{inputs: make(map[string][32]byte)}
	root, err := sourcepath.Resolve(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	if err := source.captureBuiltinObjectVersions(root); err != nil {
		t.Fatal(err)
	}
	if actual := source.originalObjectCallTarget("runtime.memmove<1>"); actual != "runtime.memmove" {
		t.Fatalf("actual builtin ABI metadata was not preserved: %q", actual)
	}
	for _, symbol := range []string{
		"runtime.memmove", "runtime.memmove<0>", "runtime.memmove<2>",
		"runtime.memmove<ABIInternal>", "runtime.memmove<1>suffix", "runtime.memmove<01>",
		"example.invalid/user.Value<1>", "runtime.unknown<1>",
	} {
		if actual := source.originalObjectCallTarget(symbol); actual != symbol {
			t.Fatalf("uncaptured object version spelling %q acquired a canonical target %q", symbol, actual)
		}
	}
	if source.ready || len(source.closed) != 0 || len(source.abis) != 0 {
		t.Fatal("object metadata created an ABI/body admission")
	}
	source.builtinVersions = nil
	if actual := source.originalObjectCallTarget("runtime.memmove<1>"); actual != "runtime.memmove<1>" {
		t.Fatal("missing actual metadata was guessed")
	}
}

func TestARM64NativeScratchGeneratedLeafFrameRestoreIsExact(t *testing.T) {
	for _, autosize := range []int64{16, 32, 48, 240} {
		for _, words := range [][]uint32{
			{0x910003fd | uint32(autosize-8)<<10, 0x910003ff | uint32(autosize)<<10},
			{0x910003ff | uint32(autosize)<<10, 0xd10023fd},
		} {
			if !arm64ScratchGeneratedLeafRestore(words, autosize) {
				t.Fatalf("exact registered leaf restore %x frame=%d rejected", words, autosize)
			}
			for index := range words {
				mutation := append([]uint32(nil), words...)
				mutation[index] ^= 1
				if arm64ScratchGeneratedLeafRestore(mutation, autosize) {
					t.Fatalf("changed physical frame restore %x accepted", mutation)
				}
			}
		}
	}
	for _, autosize := range []int64{-16, 0, 8, 24, 256} {
		if arm64ScratchGeneratedLeafRestore([]uint32{0x910043ff, 0xd10023fd}, autosize) {
			t.Fatalf("unbound physical frame %d accepted", autosize)
		}
	}
}
