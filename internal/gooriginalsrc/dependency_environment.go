package gooriginalsrc

import (
	"fmt"
	"path/filepath"
	"strings"
)

// DependencyQueryEnvironment allows module lookup only in the already observed
// download cache's file-proxy index. GOPROXY=off cannot resolve legacy imports
// even when their exact ZIPs are present. There is no network/direct fallback,
// source rewrite, compiler-version change or checksum-verification exemption.
func DependencyQueryEnvironment(environment []string) ([]string, error) {
	cache := ""
	var result []string
	for _, item := range environment {
		key, value, ok := strings.Cut(item, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("malformed dependency query environment")
		}
		if key == "GOMODCACHE" {
			cache = value
		}
		if key != "GOPROXY" && key != "GONOPROXY" {
			result = append(result, item)
		}
	}
	if !filepath.IsAbs(cache) {
		return nil, fmt.Errorf("dependency query requires an absolute observed module cache")
	}
	proxy, err := FileProxyURL(filepath.Join(cache, "cache", "download"))
	if err != nil {
		return nil, err
	}
	return append(result, "GOPROXY="+proxy, "GONOPROXY=none"), nil
}
