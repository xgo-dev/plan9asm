package gotoolprofile

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sync"
)

const discoveryFeatureHashBufferSize = 256 << 10

type discoveryFeatureHashBuffer = [discoveryFeatureHashBufferSize]byte

type discoveryFeatureHashBuffers interface {
	Get() any
	Put(any)
}

var discoveryFeatureFileHashBuffers = sync.Pool{
	New: func() any { return new(discoveryFeatureHashBuffer) },
}

func discoveryFeatureFileSHA256(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	return discoveryFeatureReadCloserSHA256(f, &discoveryFeatureFileHashBuffers)
}

func discoveryFeatureReadCloserSHA256(input io.ReadCloser, buffers discoveryFeatureHashBuffers) (string, error) {
	buffer := buffers.Get().(*discoveryFeatureHashBuffer)
	defer buffers.Put(buffer)
	h := sha256.New()
	// Hide WriterTo: os.File's fallback otherwise bypasses CopyBuffer and
	// allocates its own small buffer. Every call still reads the complete file.
	_, readErr := io.CopyBuffer(h, struct{ io.Reader }{input}, buffer[:])
	closeErr := input.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
