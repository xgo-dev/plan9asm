package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

const (
	x86PackedConversionObjectBatchSize = 48
	x86PackedConversionObjectOwners    = 4
)

// Scheduling alone is partitioned. Every original row retains initialized
// named/raw functions, all public APIs and three real LLVM22 object paths.
// Each synchronous capture owns at most48 functions and releases its objects.
func x86PackedConversionPublicObjectOwner(t *testing.T, arch, triple string, owner int) {
	t.Helper()
	if owner < 0 || owner >= x86PackedConversionObjectOwners {
		t.Fatal("invalid complete conversion object owner", owner)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	rows := x86PackedConversionContinuationRows(arch)
	rawRows := x86PackedConversionContinuationRawRows(t, arch, rows)
	consumed := 0
	for batch, start := 0, 0; start < len(rows); batch, start = batch+1, start+x86PackedConversionObjectBatchSize {
		if batch%x86PackedConversionObjectOwners != owner {
			continue
		}
		end := start + x86PackedConversionObjectBatchSize
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("batch-%04d", start), func(t *testing.T) {
			var named, raw, declarations strings.Builder
			for index := start; index < end; index++ {
				name := fmt.Sprintf("Conversion%d", index)
				body, declaration := x86PackedConversionContinuationFixture(t, name, arch, rows[index])
				named.WriteString(body)
				raw.WriteString(strings.Replace(body, rows[index]+"\n", rawRows[index]+"\n", 1))
				declarations.WriteString(declaration)
			}
			for _, spelling := range []struct{ name, source string }{{"named", named.String()}, {"raw", raw.String()}} {
				t.Run(spelling.name, func(t *testing.T) {
					x86LEAActualTargetGoObject(t, arch, triple, spelling.source)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, spelling.source, declarations.String(), arch, triple, api)
							if err != nil || ir == "" {
								t.Fatal("initialized complete conversion lost its original public path", err)
							}
							optimized := x86DwordProductIROptimize(t, ir)
							for _, pipeline := range []struct{ name, ir, backend string }{
								{"backend_O0", ir, "-O0"}, {"backend_O2", ir, "-O2"}, {"IR_O2_backend_O2", optimized, "-O2"},
							} {
								t.Run(pipeline.name, func(t *testing.T) {
									if strings.Count(pipeline.ir, "asm sideeffect") != end-start ||
										strings.Contains(pipeline.ir, " fptosi ") || strings.Contains(pipeline.ir, " fptoui ") {
										t.Fatal("complete conversion lost native MXCSR/exception or dead effects")
									}
									x86PackedStringCompileObject(t, llc, triple, pipeline.ir, pipeline.backend)
								})
							}
						})
					}
				})
			}
			consumed += end - start
		})
	}
	if consumed == 0 {
		t.Fatal("empty initialized conversion object owner", owner)
	}
	t.Logf("%d/%d original rows owned here; named+raw,3 APIs,3 actual LLVM22 object paths, no runtime claim", consumed, len(rows))
}

func TestX86PackedConversionPublicObjectsLinux386Part0(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "386", "i386-unknown-linux-gnu", 0)
}

func TestX86PackedConversionPublicObjectsLinux386Part1(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "386", "i386-unknown-linux-gnu", 1)
}

func TestX86PackedConversionPublicObjectsLinux386Part2(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "386", "i386-unknown-linux-gnu", 2)
}

func TestX86PackedConversionPublicObjectsLinux386Part3(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "386", "i386-unknown-linux-gnu", 3)
}

func TestX86PackedConversionPublicObjectsWindows386Part0(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "386", "i686-pc-windows-msvc", 0)
}

func TestX86PackedConversionPublicObjectsWindows386Part1(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "386", "i686-pc-windows-msvc", 1)
}

func TestX86PackedConversionPublicObjectsWindows386Part2(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "386", "i686-pc-windows-msvc", 2)
}

func TestX86PackedConversionPublicObjectsWindows386Part3(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "386", "i686-pc-windows-msvc", 3)
}

func TestX86PackedConversionPublicObjectsLinuxAMD64Part0(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "amd64", "x86_64-unknown-linux-gnu", 0)
}

func TestX86PackedConversionPublicObjectsLinuxAMD64Part1(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "amd64", "x86_64-unknown-linux-gnu", 1)
}

func TestX86PackedConversionPublicObjectsLinuxAMD64Part2(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "amd64", "x86_64-unknown-linux-gnu", 2)
}

func TestX86PackedConversionPublicObjectsLinuxAMD64Part3(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "amd64", "x86_64-unknown-linux-gnu", 3)
}

func TestX86PackedConversionPublicObjectsDarwinAMD64Part0(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "amd64", "x86_64-apple-darwin", 0)
}

func TestX86PackedConversionPublicObjectsDarwinAMD64Part1(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "amd64", "x86_64-apple-darwin", 1)
}

func TestX86PackedConversionPublicObjectsDarwinAMD64Part2(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "amd64", "x86_64-apple-darwin", 2)
}

func TestX86PackedConversionPublicObjectsDarwinAMD64Part3(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "amd64", "x86_64-apple-darwin", 3)
}

func TestX86PackedConversionPublicObjectsWindowsAMD64Part0(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "amd64", "x86_64-pc-windows-msvc", 0)
}

func TestX86PackedConversionPublicObjectsWindowsAMD64Part1(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "amd64", "x86_64-pc-windows-msvc", 1)
}

func TestX86PackedConversionPublicObjectsWindowsAMD64Part2(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "amd64", "x86_64-pc-windows-msvc", 2)
}

func TestX86PackedConversionPublicObjectsWindowsAMD64Part3(t *testing.T) {
	x86PackedConversionPublicObjectOwner(t, "amd64", "x86_64-pc-windows-msvc", 3)
}

func TestX86PackedConversionOriginalLowBankEVEXObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			for index, member := range []struct {
				row  string
				code []byte
			}{
				{"VCVTDQ2PS X0,X1", []byte{0x62, 0xf1, 0x7c, 0x08, 0x5b, 0xc8}},
				{"VCVTDQ2PD X0,X1", []byte{0x62, 0xf1, 0x7e, 0x08, 0xe6, 0xc8}},
			} {
				body, declaration := x86PackedConversionContinuationFixture(t, fmt.Sprintf("OriginalEVEX%d", index), target.arch, member.row)
				source.WriteString(strings.Replace(body, member.row+"\n", x86RawDisplacementDirectives(member.code), 1))
				declarations.WriteString(declaration)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil || strings.Count(ir, "{evex} vcvtdq2p") != 2 || !strings.Contains(ir, "+avx512vl") {
					t.Fatal("low-bank original EVEX became VEX or borrowed sibling features", api, err)
				}
				for _, pipeline := range []struct{ ir, backend string }{
					{ir, "-O0"}, {ir, "-O2"}, {x86DwordProductIROptimize(t, ir), "-O2"},
				} {
					if strings.Count(pipeline.ir, "{evex} vcvtdq2p") != 2 {
						t.Fatal("IR optimization erased physical EVEX opcode identity", api)
					}
					x86PackedStringCompileObject(t, llc, target.triple, pipeline.ir, pipeline.backend)
				}
			}
		})
	}
}
