package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86CallerAddressBroadcastCompleteGPUnwrittenAndResultAnchors(t *testing.T) {
	rows := x86BroadcastMemoryRows()
	for _, spec := range x86BroadcastTestDirectory {
		for _, bank := range spec.destinations {
			if spec.source == "K" {
				rows = append(rows, fmt.Sprintf("%s K1,%c2", spec.name, bank))
			}
			for _, source := range spec.source {
				if source == 'X' {
					rows = append(rows, fmt.Sprintf("%s X1,%c2", spec.name, bank))
				} else if source == 'G' {
					rows = append(rows, fmt.Sprintf("%s AX,%c2", spec.name, bank))
				}
			}
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range rows {
			ins := x86YMMReadSource(t, row)
			before := [16]bool{true, true, true, true, false, false, true, true}
			if after := x86ResultCallerAddressesAfter(ins, before, nil, arch); after != before {
				t.Errorf("%s %s: a vector-only output erased caller GP identities", arch, row)
			}
			anchor := x86ResultSlotAddress{start: 8, end: 16, offset: 8, valid: true}
			state := x86ResultState{}
			state.resultAddressGP[6] = anchor
			x86ResultSlotRevokeOverwrites(ins, &state, state.resultAddressGP, arch)
			if state.resultAddressGP[6] != anchor {
				t.Errorf("%s %s: an unwritten logical result anchor was revoked", arch, row)
			}
		}
	}
}

func TestX86CallerAddressBitScanRevokesOnlyActualDestination(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, direction := range []string{"F", "R"} {
			widths := []string{"W", "L"}
			if arch == "amd64" {
				widths = append(widths, "Q")
			}
			for _, width := range widths {
				ins := x86YMMReadSource(t, "BS"+direction+width+" DX,CX")
				before := [16]bool{true, true, true, true, false, false, true, true}
				want := before
				want[1] = false
				if after := x86ResultCallerAddressesAfter(ins, before, nil, arch); after != want {
					t.Errorf("%s %s: conditional numerical result widened its GP-write footprint", arch, ins.Raw)
				}
			}
		}
	}
}

func TestX86CallerAddressVectorTestsHaveNoGPWrites(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"PTEST", "VPTEST", "VTESTPS", "VTESTPD"} {
			banks := []string{"X"}
			if op != "PTEST" {
				banks = append(banks, "Y")
			}
			for _, bank := range banks {
				for _, source := range []string{bank + "1", "(AX)", "feature+7(SB)"} {
					ins := x86YMMReadSource(t, fmt.Sprintf("%s %s,%s2", op, source, bank))
					before := [16]bool{true, true, true, true, false, false, true, true}
					if after := x86ResultCallerAddressesAfter(ins, before, nil, arch); after != before {
						t.Errorf("%s %s: read-only vector test erased unrelated GP addresses", arch, ins.Raw)
					}
				}
			}
		}
	}
}

func TestX86CallerAddressRegisteredFootprintsCannotWashUnknownRoles(t *testing.T) {
	before := [16]bool{true, true, true, true, false, false, true, true}
	for _, arch := range []string{"386", "amd64"} {
		for _, row := range []string{
			"VPBROADCASTB X1,X2", "VPMOVMSKB X1,DX", "VPTEST X1,X2", "BSFL DX,CX",
		} {
			for _, role := range []string{"raw", "decoded", "address override", "unbound address", "segment"} {
				t.Run(arch+"/"+row+"/"+role, func(t *testing.T) {
					ins := x86YMMReadSource(t, row)
					switch role {
					case "raw":
						ins.x86SourceRaw = &x86SourceRawInstruction{}
					case "decoded":
						ins.x86Encoded = true
					case "address override":
						ins.x86AddressBits = 32
					case "unbound address":
						ins.x86UnboundAddressOverride = true
					case "segment":
						ins.x86SegmentPrefix = 0x64
					}
					if after := x86ResultCallerAddressesAfter(ins, before, nil, arch); after != [16]bool{} {
						t.Fatal("registered source spelling washed an unbound physical role", after)
					}
				})
			}
		}
		for _, row := range []string{"VPBROADCASTB.Z X1,X2", "VPBROADCASTB X1,K0,X2", "BSFL X1,CX", "PTEST X1,Y2", "VPMOVMSKB M1,DX", "UNKNOWN X1,X2"} {
			if after := x86ResultCallerAddressesAfter(x86YMMReadSource(t, row), before, nil, arch); after != [16]bool{} {
				t.Fatal("unknown/malformed instruction preserved caller provenance", arch, row, after)
			}
		}
	}
}
