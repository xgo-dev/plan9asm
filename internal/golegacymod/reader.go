package golegacymod

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

// Sumdb responses are public source metadata, never executable dependencies.
// Cache reads are read-only; fetched bytes stay in memory and are authenticated
// before being recorded. No user/global cache is written or cleaned.
type SumDBReader struct {
	Context        context.Context
	Cache          string
	Client         *http.Client
	ReadonlyCaches []string
}

func NewSumDBReader(ctx context.Context, moduleCache, proxy string) (*SumDBReader, error) {
	if !filepath.IsAbs(moduleCache) || len(proxy) > 64<<10 {
		return nil, fmt.Errorf("invalid actual checksum cache configuration")
	}
	reader := &SumDBReader{
		Context: ctx,
		Cache:   filepath.Join(moduleCache, "cache", "download", "sumdb", "sum.golang.org"),
	}
	seen := map[string]bool{reader.Cache: true}
	for _, item := range strings.FieldsFunc(proxy, func(char rune) bool { return char == ',' || char == '|' }) {
		location, err := url.Parse(item)
		if err != nil {
			return nil, fmt.Errorf("invalid actual module proxy: %w", err)
		}
		if location.Scheme != "file" {
			continue
		}
		if location.Host != "" || location.User != nil || location.RawQuery != "" || location.Fragment != "" || location.Opaque != "" {
			return nil, fmt.Errorf("checksum reuse requires an absolute local file proxy")
		}
		cachePath := filepath.FromSlash(location.Path)
		// file:///C:/... is Go's local Windows file-proxy spelling. Keep
		// native drive/UNC handling in filepath rather than accepting hosts.
		if filepath.Separator == '\\' && len(cachePath) >= 3 && cachePath[0] == '\\' && cachePath[2] == ':' {
			cachePath = cachePath[1:]
		}
		if !filepath.IsAbs(cachePath) {
			return nil, fmt.Errorf("checksum reuse requires an absolute local file proxy")
		}
		cache := filepath.Join(cachePath, "sumdb", "sum.golang.org")
		if seen[cache] {
			continue
		}
		seen[cache] = true
		reader.ReadonlyCaches = append(reader.ReadonlyCaches, cache)
		if len(reader.ReadonlyCaches) > 8 {
			return nil, fmt.Errorf("checksum cache roots exceed their explicit bound")
		}
	}
	return reader, nil
}

func (reader *SumDBReader) Height() int                     { return 8 }
func (reader *SumDBReader) SaveTiles([]tlog.Tile, [][]byte) {}

func (reader *SumDBReader) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	if len(tiles) > 64 {
		return nil, fmt.Errorf("checksum tile request exceeds its explicit bound")
	}
	var result [][]byte
	for _, tile := range tiles {
		if tile.H != 8 || tile.W < 1 || tile.W > 256 {
			return nil, fmt.Errorf("invalid checksum tile extent")
		}
		if reader.Context == nil || reader.Context.Err() != nil {
			return nil, fmt.Errorf("checksum tile request has no live context")
		}
		data, err := reader.readCache(tile.Path(), tile.W*tlog.HashSize)
		if os.IsNotExist(err) && tile.W < 256 {
			full := tile
			full.W = 256
			data, err = reader.readCache(full.Path(), 256*tlog.HashSize)
			if err == nil && len(data) == 256*tlog.HashSize {
				data = data[:tile.W*tlog.HashSize]
			}
		}
		if os.IsNotExist(err) {
			data, err = reader.Read(tile.Path(), tile.W*tlog.HashSize)
		}
		if err != nil {
			return nil, fmt.Errorf("read exact checksum tile %s: %w", tile.Path(), err)
		}
		if len(data) != tile.W*tlog.HashSize {
			return nil, fmt.Errorf("checksum tile %s has an incorrect byte extent", tile.Path())
		}
		result = append(result, data)
	}
	return result, nil
}

func (reader *SumDBReader) Read(name string, limit int) ([]byte, error) {
	if reader.Context == nil || reader.Context.Err() != nil || strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
		return nil, fmt.Errorf("invalid bounded checksum source read")
	}
	data, err := reader.readCache(name, limit)
	if err == nil {
		return data, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	request, err := http.NewRequestWithContext(reader.Context, http.MethodGet, "https://sum.golang.org/"+name, nil)
	if err != nil {
		return nil, err
	}
	client := reader.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("read signed checksum source: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checksum source returned HTTP %d", response.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, int64(limit+1)))
	if err != nil {
		return nil, fmt.Errorf("read checksum source: %w", err)
	}
	if len(data) > limit {
		return nil, fmt.Errorf("checksum source exceeds its explicit bound")
	}
	return data, nil
}

func (reader *SumDBReader) readCache(name string, limit int) ([]byte, error) {
	var missing error
	for _, cache := range append([]string{reader.Cache}, reader.ReadonlyCaches...) {
		data, err := ReadChecksumFile(filepath.Join(cache, filepath.FromSlash(name)), limit)
		if !os.IsNotExist(err) {
			return data, err // Bad cache bytes or access errors must not be hidden.
		}
		missing = err
	}
	return nil, missing
}

func ReadChecksumFile(name string, limit int) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return nil, fmt.Errorf("checksum cache source is not a bounded regular file")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit+1)))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("checksum cache source exceeds its explicit bound")
	}
	return data, nil
}
