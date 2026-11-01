package plan9asm

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func arm64PCAlignTestForms() []string {
	var forms []string
	for alignment := 8; alignment <= 2048; alignment *= 2 {
		forms = append(forms, fmt.Sprintf("PCALIGN $%d", alignment))
		for _, limit := range []int{0, alignment - 1} {
			forms = append(forms, fmt.Sprintf("PCALIGNMAX $%d,$%d", alignment, limit))
		}
	}
	return forms
}

func arm64PCAlignTailSource(row string) string {
	source := arm64ClosedTailPointerSource("B")
	source = strings.Replace(source, "B readbody", row+"\nB readbody", 1)
	return strings.Replace(source, "MOVD (R0),R0", row+"\nMOVD (R0),R0", 1)
}

func TestARM64PCAlignClosedTailObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, row := range arm64PCAlignTestForms() {
		for _, target := range []string{
			"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-unknown-freebsd",
			"aarch64-apple-darwin", "aarch64-pc-windows-msvc",
		} {
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(row+"/"+target+"/"+api, func(t *testing.T) {
					ir, err := arm64ClosedTailTranslate(t, arm64PCAlignTailSource(row), "func Read(*uint64) uint64", target, api)
					if err != nil {
						t.Fatal(err)
					}
					value := strings.Split(strings.Split(row, "$")[1], ",")[0]
					alignment, err := strconv.Atoi(value)
					if err != nil {
						t.Fatal(err)
					}
					aligned := false
					for _, line := range strings.Split(ir, "\n") {
						if strings.HasPrefix(line, "define ") && strings.Contains(line, fmt.Sprintf(" align %d ", alignment)) {
							aligned = true
						}
					}
					if !aligned {
						t.Fatal("source-required function alignment was lost")
					}
					compileLLVMToObject(t, llc, target, "aligned-tail.ll", "aligned-tail.o", ir)
				})
			}
		}
	}
}

func TestARM64PCAlignMalformedCompleteSource(t *testing.T) {
	for _, row := range []string{
		"PCALIGN", "PCALIGN $16,$1", "PCALIGN $0", "PCALIGN $4", "PCALIGN $24",
		"PCALIGN $4096", "PCALIGN $-16", "PCALIGN $16.0", "PCALIGN $missing",
		"PCALIGN R0", "PCALIGN 16(R0)", "PCALIGN.P $16",
		"PCALIGNMAX", "PCALIGNMAX $16", "PCALIGNMAX $16,$1,$2",
		"PCALIGNMAX $16,$16", "PCALIGNMAX $16,$-1", "PCALIGNMAX $24,$1",
		"PCALIGNMAX $16,$1.0", "PCALIGNMAX $16,R0", "PCALIGNMAX R0,$1",
		"PCALIGNMAX $16,$missing", "PCALIGNMAX.P $16,$7",
	} {
		for _, placement := range []string{"root", "helper", "dead"} {
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(row+"/"+placement+"/"+api, func(t *testing.T) {
					source := arm64ClosedTailPointerSource("B")
					switch placement {
					case "root":
						source = strings.Replace(source, "B readbody", row+"\nB readbody", 1)
					case "helper":
						source = strings.Replace(source, "MOVD (R0),R0", row+"\nMOVD (R0),R0", 1)
					case "dead":
						source += "dead:\n" + row + "\nRET\n"
					}
					if ir, err := arm64ClosedTailTranslate(t, source, "func Read(*uint64) uint64", arm64LinuxGNUTriple, api); err == nil || ir != "" {
						t.Fatalf("malformed alignment acquired a source contract: %v", err)
					}
				})
			}
		}
	}
}

func TestARM64PCAlignDoesNotAuthorizeNativeLayout(t *testing.T) {
	for _, row := range []string{"PCALIGN $16", "PCALIGNMAX $16,$0", "PCALIGNMAX $16,$15"} {
		for _, observer := range []string{
			"TEXT ·Excluded(SB),516,$0-8\nWORD $0xd503201f\nRET\n",
			"TEXT ·Excluded(SB),516,$0-8\nADR label,R0\nlabel:\nRET\n",
			"TEXT ·Excluded(SB),516,$0-8\nB 1(PC)\nRET\n",
			"TEXT ·Excluded(SB),516,$0-8\nMOVD $readbody<>(SB),R0\nRET\n",
			"DATA saved<>+0(SB)/8,$readbody<>(SB)\nGLOBL saved<>(SB),8,$8\n",
		} {
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(row+"/"+strings.Split(observer, "\n")[0]+"/"+api, func(t *testing.T) {
					_, err := arm64ClosedTailTranslate(t, arm64PCAlignTailSource(row)+observer,
						"func Read(*uint64) uint64\nfunc Excluded() uint64", arm64LinuxGNUTriple, api)
					if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("alignment authorized an observable native layout: %v", err)
					}
				})
			}
		}
	}
}

func TestARM64PCAlignRetainsContinuationGuards(t *testing.T) {
	for _, row := range []string{"PCALIGN $16", "PCALIGNMAX $32,$0", "PCALIGNMAX $32,$31"} {
		t.Run(row, func(t *testing.T) {
			// A data-only directive cannot initialize an otherwise unknown R9.
			source := strings.Replace(arm64PCAlignTailSource(row), "MOVD (R0),R0", "MOVD R9,R0", 1)
			for _, api := range []string{"text", "module", "GoModule"} {
				if _, err := arm64ClosedTailTranslate(t, source, "func Read(*uint64) uint64", arm64LinuxGNUTriple, api); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("alignment initialized a missing register: %v", err)
				}
			}

			// CALL helpers deliberately retain their separate layout contract.
			file, err := Parse(ArchARM64, arm64PrivateCallCFGCopySource+
				"TEXT observer<>(SB),516,$0-0\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := CoalesceARM64PrivateRegisterHelpers(file); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("tail alignment permission leaked into a CALL continuation: %v", err)
			}

			file, err = Parse(ArchARM64, arm64PCAlignTailSource(row))
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := CoalesceARM64PrivateRegisterHelpers(file)
			if err != nil {
				t.Fatal(err)
			}
			observer, err := Parse(ArchARM64, "TEXT observer<>(SB),516,$0-0\nWORD $0xd503201f\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			prepared.Funcs = append(prepared.Funcs, observer.Funcs...)
			if _, err := CoalesceARM64PrivateRegisterHelpers(prepared); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("prepared aligned source bypassed its final whole-file audit: %v", err)
			}
		})
	}
}
