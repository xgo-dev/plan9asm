package gotoolprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

type fileSHAReader struct {
	data                    []byte
	position, calls, widest int
	step                    int
	failAfter               int
	dataError, finalEOF     bool
	readError, closeError   error
	closed                  int
}

func (reader *fileSHAReader) Read(output []byte) (int, error) {
	reader.calls++
	if len(output) > reader.widest {
		reader.widest = len(output)
	}
	if reader.failAfter > 0 && reader.position == reader.failAfter {
		return 0, reader.readError
	}
	if reader.position == len(reader.data) {
		if reader.readError != nil {
			return 0, reader.readError
		}
		return 0, io.EOF
	}
	if reader.step > 0 && len(output) > reader.step {
		output = output[:reader.step]
	}
	if reader.failAfter > 0 && len(output) > reader.failAfter-reader.position {
		output = output[:reader.failAfter-reader.position]
	}
	n := copy(output, reader.data[reader.position:])
	reader.position += n
	if reader.dataError && reader.position == reader.failAfter {
		return n, reader.readError
	}
	if reader.finalEOF && reader.position == len(reader.data) {
		return n, io.EOF
	}
	return n, nil
}

func (reader *fileSHAReader) Close() error {
	reader.closed++
	return reader.closeError
}

type fileSHASpyBuffers struct {
	mu         sync.Mutex
	gets, puts int
	active     map[*discoveryFeatureHashBuffer]bool
	onPut      func()
}

func (buffers *fileSHASpyBuffers) Get() any {
	buffer := new(discoveryFeatureHashBuffer)
	buffers.mu.Lock()
	defer buffers.mu.Unlock()
	if buffers.active == nil {
		buffers.active = make(map[*discoveryFeatureHashBuffer]bool)
	}
	buffers.gets++
	buffers.active[buffer] = true
	return buffer
}

func (buffers *fileSHASpyBuffers) Put(value any) {
	buffer, valid := value.(*discoveryFeatureHashBuffer)
	if !valid {
		panic("unexpected hash buffer type")
	}
	buffers.mu.Lock()
	defer buffers.mu.Unlock()
	if !buffers.active[buffer] {
		panic("unborrowed or double-returned hash buffer")
	}
	delete(buffers.active, buffer)
	buffers.puts++
	if buffers.onPut != nil {
		buffers.onPut()
	}
}

func fileSHAExpected(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func fileSHAData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*71 + i/251)
	}
	return data
}

// A counting wrapper around a real regular file measures each actual Read
// request. Its WriterTo reproduces the stock Go genericWriteTo fallback, so
// the baseline also exercises the path used by io.Copy on an *os.File.
type fileSHACountingFile struct {
	*os.File
	calls, widest int
}

func (file *fileSHACountingFile) Read(output []byte) (int, error) {
	file.calls++
	if len(output) > file.widest {
		file.widest = len(output)
	}
	return file.File.Read(output)
}

func (file *fileSHACountingFile) WriteTo(output io.Writer) (int64, error) {
	return io.Copy(output, struct{ io.Reader }{file})
}

func TestFileSHA256BoundedReadRequestsOnActualFile(t *testing.T) {
	data := fileSHAData(8 << 20)
	name := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	opened, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	file := &fileSHACountingFile{File: opened}
	digest, err := discoveryFeatureReadCloserSHA256(file, &fileSHASpyBuffers{})
	if err != nil || digest != fileSHAExpected(data) {
		t.Fatalf("complete actual file digest: %s/%v", digest, err)
	}
	maximumReads := (len(data)+discoveryFeatureHashBufferSize-1)/discoveryFeatureHashBufferSize + 1
	t.Logf("actual regular file bytes=%d Read calls=%d widest request=%d maximum calls=%d", len(data), file.calls, file.widest, maximumReads)
	if file.calls > maximumReads || file.widest != discoveryFeatureHashBufferSize {
		t.Fatalf("full regular file used small or unbounded read requests: calls=%d widest=%d", file.calls, file.widest)
	}
}

func TestFileSHA256ShortReadsAndErrorsReturnBuffer(t *testing.T) {
	readError := errors.New("original read failure")
	closeError := errors.New("original close failure")
	for _, row := range []struct {
		name                  string
		size, step            int
		failAfter             int
		dataError, finalEOF   bool
		readError, closeError error
		wantError             error
	}{
		{name: "empty"},
		{name: "partial final block", size: 263},
		{name: "data with EOF", size: 263, finalEOF: true},
		{name: "short reads", size: 1027, step: 7},
		{name: "empty read error", readError: readError, wantError: readError},
		{name: "read error", size: 263, step: 7, readError: readError, wantError: readError},
		{name: "early read error", size: 263, failAfter: 7, readError: readError, wantError: readError},
		{name: "partial data with read error", size: 263, failAfter: 7, dataError: true, readError: readError, wantError: readError},
		{name: "close error", size: 263, closeError: closeError, wantError: closeError},
		{name: "read error precedes close error", size: 263, readError: readError, closeError: closeError, wantError: readError},
	} {
		t.Run(row.name, func(t *testing.T) {
			reader := &fileSHAReader{
				data: fileSHAData(row.size), step: row.step, failAfter: row.failAfter,
				dataError: row.dataError, finalEOF: row.finalEOF,
				readError: row.readError, closeError: row.closeError,
			}
			buffers := &fileSHASpyBuffers{onPut: func() {
				if reader.closed != 1 {
					t.Error("buffer returned before the owned reader closed")
				}
			}}
			digest, err := discoveryFeatureReadCloserSHA256(reader, buffers)
			wantConsumed := row.size
			if row.failAfter > 0 {
				wantConsumed = row.failAfter
			}
			if !errors.Is(err, row.wantError) || reader.closed != 1 || reader.position != wantConsumed {
				t.Fatalf("full read/close/error precedence changed: position=%d closes=%d digest=%s err=%v", reader.position, reader.closed, digest, err)
			}
			if row.wantError != nil && digest != "" || row.wantError == nil && digest != fileSHAExpected(reader.data) {
				t.Fatalf("success/failure digest changed: %s/%v", digest, err)
			}
			if buffers.gets != 1 || buffers.puts != 1 || len(buffers.active) != 0 {
				t.Fatalf("bounded buffer not returned exactly once: gets=%d puts=%d active=%d", buffers.gets, buffers.puts, len(buffers.active))
			}
		})
	}
}

func TestFileSHA256ActualFilesAlwaysRecaptureBytes(t *testing.T) {
	for _, size := range []int{0, 1, 32767, 32768, 32769, discoveryFeatureHashBufferSize - 1, discoveryFeatureHashBufferSize, discoveryFeatureHashBufferSize + 1, 3*discoveryFeatureHashBufferSize + 17} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			name := filepath.Join(t.TempDir(), "original")
			data := fileSHAData(size)
			if err := os.WriteFile(name, data, 0600); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(name)
			if err != nil {
				t.Fatal(err)
			}
			before, err := FileSHA256(name)
			if err != nil || before != fileSHAExpected(data) {
				t.Fatalf("reference digest differs: %s/%v", before, err)
			}
			if size != 0 {
				data[size-1] ^= 0x5a
			}
			if err := os.WriteFile(name, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(name, info.ModTime(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
			after, err := FileSHA256(name)
			if err != nil || after != fileSHAExpected(data) || size != 0 && after == before {
				t.Fatalf("same-path/size/mtime changed bytes were not read: %s/%v", after, err)
			}
		})
	}
	if digest, err := FileSHA256(filepath.Join(t.TempDir(), "missing")); err == nil || digest != "" {
		t.Fatalf("missing file supplied a digest: %s/%v", digest, err)
	}
	if digest, err := FileSHA256(t.TempDir()); err == nil || digest != "" {
		t.Fatalf("directory supplied a digest: %s/%v", digest, err)
	}
}

func TestFileSHA256ConcurrentBufferReturn(t *testing.T) {
	const count = 32
	var workers sync.WaitGroup
	buffers := new(fileSHASpyBuffers)
	failures := make(chan error, 3*count)
	for index := 0; index < count; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			data := fileSHAData(discoveryFeatureHashBufferSize + index)
			reader := &fileSHAReader{data: data, step: 1009}
			digest, err := discoveryFeatureReadCloserSHA256(reader, buffers)
			if err != nil || digest != fileSHAExpected(data) || reader.closed != 1 {
				failures <- fmt.Errorf("worker %d: digest=%s closes=%d error=%v", index, digest, reader.closed, err)
			}
			// Also exercise the production sync.Pool concurrently, including
			// immediate reuse after successful and error returns.
			for _, readError := range []error{errors.New("read failure"), nil} {
				reader := &fileSHAReader{data: data, readError: readError}
				digest, err := discoveryFeatureReadCloserSHA256(reader, &discoveryFeatureFileHashBuffers)
				if !errors.Is(err, readError) || reader.closed != 1 || readError == nil && digest != fileSHAExpected(data) {
					failures <- fmt.Errorf("production pool worker %d: digest=%s closes=%d error=%v", index, digest, reader.closed, err)
					return
				}
			}
		}(index)
	}
	workers.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
	if buffers.gets != count || buffers.puts != count || len(buffers.active) != 0 {
		t.Fatalf("concurrent buffer ownership leaked: gets=%d puts=%d active=%d", buffers.gets, buffers.puts, len(buffers.active))
	}
}

func fileSHABaseline(name string) (string, error) {
	file, err := os.Open(name)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, readError := io.Copy(hash, file)
	closeError := file.Close()
	if readError != nil {
		return "", readError
	}
	if closeError != nil {
		return "", closeError
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func BenchmarkFileSHA256CompletePhysicalRead(b *testing.B) {
	fixture := filepath.Join(b.TempDir(), "fixture")
	if err := os.WriteFile(fixture, fileSHAData(8<<20), 0600); err != nil {
		b.Fatal(err)
	}
	for _, row := range []struct{ name, file string }{
		{"fixture_8MiB", fixture},
		{"selected_SDK_driver", filepath.Join(runtime.GOROOT(), "bin", "go")},
	} {
		info, err := os.Stat(row.file)
		if err != nil {
			b.Fatal(err)
		}
		reference, err := fileSHABaseline(row.file)
		if err != nil {
			b.Fatal(err)
		}
		for _, implementation := range []struct {
			name string
			hash func(string) (string, error)
		}{
			{"baseline_io_Copy", fileSHABaseline},
			{"production", FileSHA256},
		} {
			b.Run(row.name+"/"+implementation.name, func(b *testing.B) {
				b.SetBytes(info.Size())
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					digest, err := implementation.hash(row.file)
					if err != nil || digest != reference {
						b.Fatalf("full reference digest changed: %s/%v", digest, err)
					}
				}
			})
		}
	}
}
