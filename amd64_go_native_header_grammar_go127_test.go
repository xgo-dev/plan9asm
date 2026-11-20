//go:build go1.27

package plan9asm

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func TestSDKAMD64NativeHeaderActualGoAttributes(t *testing.T) {
	_, profile, _, _ := numericalSBFixture(t, "amd64")
	ctx, cancel := runtimeOracleProofContext(t)
	defer cancel()
	sdk := filepath.Dir(filepath.Dir(profile.GoBinary))
	builtin, err := os.ReadFile(filepath.Join(sdk, "src/cmd/internal/goobj/builtinlist.go"))
	if err != nil {
		t.Fatal(err)
	}
	// Decimal flags are independent official TEXT values: DUPOK=2,
	// NOSPLIT=4, TOPFRAME=2048. These are metadata objects, not entries.
	const source = `TEXT ·Ordinary(SB),4,$16-0
	RET
TEXT ·Duplicate(SB),6,$16-0
	RET
TEXT ·Top(SB),2052,$16-0
	RET
TEXT private<>(SB),4,$0-0
	RET
TEXT ·Combined(SB),2054,$16-0
	RET
TEXT crypto∕internal∕fips140∕headerfixture·FIPS(SB),2054,$16-0
	RET
TEXT runtime·goexit(SB),2052,$0-0
	RET
`
	input := filepath.Join(profile.Directory, "header-attributes.s")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			env := append([]string(nil), profile.Environment...)
			for index, pair := range env {
				if strings.HasPrefix(pair, "GOOS=") {
					env[index] = "GOOS=" + goos
				}
			}
			objectPath := filepath.Join(t.TempDir(), "header-attributes.o")
			listing, err := goasmcmd.Run(ctx, profile.Directory, env, profile.GoBinary,
				"tool", "asm", "-p", "headerfixture", "-S", "-o", objectPath, input)
			if err != nil {
				t.Fatal("actual Go assembler precondition", err)
			}
			object, err := os.ReadFile(objectPath)
			if err != nil || len(object) == 0 {
				t.Fatal("actual complete Go object precondition", err)
			}
			observed, err := gostaticstorage.ObserveAMD64AssemblyData([]byte(source), object, builtin, "headerfixture", goos+"/amd64")
			if err != nil || len(observed.Member.Texts) != 7 || len(observed.TextOrder) != 7 {
				t.Fatal("complete original source/object association precondition", err)
			}
			if !bytes.Contains(listing, []byte(" dupok ")) || !bytes.Contains(listing, []byte(" topframe ")) ||
				bytes.Count(listing, []byte(" STEXTFIPS ")) != 1 {
				t.Fatalf("actual Go did not emit the independent attribute/kind priors:\n%s", listing)
			}
			records, err := sdkAMD64FrameNativeRecordsForSource(listing, observed.Member.Texts, observed.TextOrder)
			if err != nil || len(records) != 7 {
				t.Fatal("complete actual native headers lost their object associations", err)
			}
			for index, record := range records {
				locals := uint64(24)
				if index == 3 || index == 6 {
					locals = 0
				}
				if record.Symbol != observed.TextOrder[index].Name || record.Static != (index == 3) ||
					!record.NoSplit || !record.ASM || !record.ArgsKnown || record.Args != 0 || record.Locals != locals {
					t.Fatal("actual header changed independent symbol/frame/argument metadata", index, record)
				}
			}
		})
	}
}
