package gotoolprofile

import (
	"context"

	"github.com/xgo-dev/plan9asm/internal/golegacymod"
	"golang.org/x/mod/sumdb/tlog"
)

// Keep the existing report schema and API while sharing the independent
// authentication layer with original-source observers, without a root cycle.
const ProxyGoModProtocol = golegacymod.ProxyGoModProtocol

type ProxyGoModProof = golegacymod.ProxyGoModProof
type SumDBReader = golegacymod.SumDBReader

func CaptureProxyGoMod(path, version, zipSum, modSum string, contents, lookup []byte, tiles tlog.TileReader) (*ProxyGoModProof, error) {
	return golegacymod.CaptureProxyGoMod(path, version, zipSum, modSum, contents, lookup, tiles)
}

func ValidateProxyGoMod(proof *ProxyGoModProof) error {
	return golegacymod.ValidateProxyGoMod(proof)
}

func validProxyGoModH1(value string) bool {
	return golegacymod.ValidH1(value)
}

func NewSumDBReader(ctx context.Context, moduleCache, proxy string) (*SumDBReader, error) {
	return golegacymod.NewSumDBReader(ctx, moduleCache, proxy)
}

func ReadChecksumFile(name string, limit int) ([]byte, error) {
	return golegacymod.ReadChecksumFile(name, limit)
}
