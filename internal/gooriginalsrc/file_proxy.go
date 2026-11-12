package gooriginalsrc

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// FileProxyURL names one absolute local proxy, without allowing punctuation in
// its directory name to introduce another GOPROXY entry or network fallback.
func FileProxyURL(directory string) (string, error) {
	if !filepath.IsAbs(directory) {
		return "", fmt.Errorf("file proxy requires an absolute directory")
	}
	return fileProxyURL(filepath.ToSlash(directory)), nil
}

func fileProxyURL(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path // Windows drive paths use file:///C:/..., not a host.
	}
	proxy := (&url.URL{Scheme: "file", Path: path}).String()
	return strings.NewReplacer(",", "%2C", "|", "%7C").Replace(proxy)
}
